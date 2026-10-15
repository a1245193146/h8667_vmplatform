# -*- coding: utf-8 -*-
"""运维分析——服务器操作影响分析（Linux 只读采集）。

红线：全程只读，绝不执行关机/重启/停服务等任何改变系统状态的操作。
采集：基础状态 / 用户与会话 / 网络连接 / 监听端口 / 服务 / 进程 / Supervisor。
输出单行 JSON: {"ok":true,"data":{...}}，结构与 Windows 采集器
(Collect-OpsImpact.ps1) 完全一致，故上层 impact_rules.analyze_impact 无需区分 OS。

兼容 Python 2.7 / 3.x（CentOS 7 默认 python2.7，也可能只有 python3）。
仅使用标准库 + 常见系统命令（df/who/ss/netstat/systemctl/ps/supervisorctl），
每条命令都容错：命令不存在或失败都不影响其它段，绝不抛出中断整次采集。

用法:
    python collect_ops_impact.py [--max-conn 200] [--max-proc 60]
作者: AUTO-GENERATED (opsanalysis module)
"""
from __future__ import print_function

import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta

MAX_CONN = 200
MAX_PROC = 60
# 非运行状态服务的名单上限（总数照常全量回报，只是不逐条列出）
MAX_SVC_OTHER = 200
APP_LOG_PATH = ''
OS_LOG_DAYS = 1
MAX_OSLOG_PER_KIND = 60
MAX_OSLOG_TOTAL = 300

# 从任意命令行里尽力提取监听端口（runserver 0.0.0.0:80 / uwsgi --http :80 / :5858）
PORT_RE = re.compile(r'(?:--http\s*:?|0\.0\.0\.0:|127\.0\.0\.1:|:)(\d{2,5})\b')

# syslog 月份名手工映射：strftime('%b') 依赖 locale，中文 locale 的机器上会解析失败，
# 故一律自己查表，保证 CentOS/Ubuntu、C/zh_CN locale 下行为一致。
_MONTHS = {'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
           'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12}
# syslog 行首： Oct 11 20:56:58 host unit[pid]: message
SYSLOG_RE = re.compile(
    r'^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s*(.*)$')
# journalctl -o short-iso 行首： 2026-10-11T20:56:58+0800 host unit[pid]: message
JOURNAL_ISO_RE = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})\S*\s+(\S+)\s*(.*)$')
# last -x -F 的完整时间： Sat Oct 11 20:56:58 2026
LAST_LONG_RE = re.compile(
    r'\b[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\b')
# last 不带 -F 时的短时间： Sat Oct 11 20:56
LAST_SHORT_RE = re.compile(
    r'\b[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2})\b')
# dmesg -T 行首： [Sat Oct 11 20:56:58 2026] message
DMESG_RE = re.compile(
    r'^\[\s*[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s*\]\s*(.*)$')
# systemctl list-units 的"单元行"：首列必须是带单元后缀的名字。
# 用来滤掉表头(UNIT LOAD ACTIVE SUB)、图例(LOAD   = Reflects...)、页脚
# (1 loaded units listed.)——这些在部分 systemd 版本上即使加了 --no-legend
# 也会输出，若被当成"失败单元"就是凭空捏造事实。
UNIT_LINE_RE = re.compile(
    r'^(?P<unit>\S+\.(?:service|socket|timer|mount|target|path|scope|slice'
    r'|swap|device|automount))(?:\s|$)')


# ------------------------------------------------------------------ 基础工具

def _args(argv):
    """极简参数解析：--max-conn N / --max-proc N / --app-log PATH / --os-log-days N。"""
    global MAX_CONN, MAX_PROC, APP_LOG_PATH, OS_LOG_DAYS, MAX_OSLOG_TOTAL
    i = 0
    while i < len(argv):
        a = argv[i]
        try:
            if a == '--max-conn' and i + 1 < len(argv):
                MAX_CONN = int(argv[i + 1]); i += 2; continue
            if a == '--max-proc' and i + 1 < len(argv):
                MAX_PROC = int(argv[i + 1]); i += 2; continue
            if a == '--app-log' and i + 1 < len(argv):
                APP_LOG_PATH = argv[i + 1]; i += 2; continue
            if a == '--os-log-days' and i + 1 < len(argv):
                OS_LOG_DAYS = max(1, int(argv[i + 1])); i += 2; continue
            if a == '--max-oslog' and i + 1 < len(argv):
                MAX_OSLOG_TOTAL = max(1, int(argv[i + 1])); i += 2; continue
        except (ValueError, TypeError):
            pass
        i += 1


def run(cmd, timeout=30):
    """执行只读命令，返回 (returncode, stdout_text)。失败返回 (-1, '')。绝不抛出。"""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _err = p.communicate()
        if isinstance(out, bytes):
            out = out.decode('utf-8', 'replace')
        return (p.returncode if p.returncode is not None else 0), out
    except Exception:
        return (-1, '')


def to_int(v, default=None):
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


def to_float(v, default=None):
    try:
        return float(v)
    except (ValueError, TypeError):
        return default


def _dedup(seq):
    """去重保序（py2 的 dict 不保序，故用显式列表，保证 py2/py3 行为一致）。"""
    out = []
    seen = set()
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def port_from_text(text):
    if not text:
        return None
    m = PORT_RE.search(text)
    if m:
        p = to_int(m.group(1))
        if p is not None and 1 <= p <= 65535:
            return p
    return None


def now_iso():
    return datetime.now().isoformat()


# ------------------------------------------------------------------ 基础状态

def collect_basic():
    # 预置全部字段，保证 snapshot schema 稳定（某段采集失败也保留键，值为 None），
    # 与 Windows 采集器一致，便于上层 impact_rules / 模板无差别读取。
    basic = {
        'hostname': '', 'os': '', 'os_version': '', 'ip': '',
        'cpu_percent': None, 'mem_total_mb': None, 'mem_free_mb': None,
        'mem_percent': None, 'boot_time': None, 'uptime_seconds': None,
        'disks': [],
    }
    try:
        basic['hostname'] = socket.gethostname() or ''
    except Exception:
        pass

    # os / os_version：优先 /etc/os-release，退回 /etc/redhat-release
    os_name = ''; os_version = ''
    try:
        with open('/etc/os-release') as f:
            for line in f:
                line = line.strip()
                if line.startswith('PRETTY_NAME='):
                    os_name = line.split('=', 1)[1].strip().strip('"')
                elif line.startswith('VERSION='):
                    os_version = line.split('=', 1)[1].strip().strip('"')
    except Exception:
        pass
    if not os_name:
        try:
            with open('/etc/redhat-release') as f:
                os_name = f.read().strip()
        except Exception:
            rc, out = run(['uname', '-sr'])
            os_name = out.strip() if rc == 0 else ''
    basic['os'] = os_name
    basic['os_version'] = os_version

    # 本机 IPv4（排除回环）
    ips = []
    rc, out = run(['hostname', '-I'])
    if rc == 0 and out.strip():
        for tok in out.split():
            tok = tok.strip()
            if tok and not tok.startswith('127.'):
                ips.append(tok)
    if not ips:
        try:
            for info in socket.gethostbyname_ex(socket.gethostname())[2]:
                if info and not info.startswith('127.'):
                    ips.append(info)
        except Exception:
            pass
    basic['ip'] = ','.join(_dedup(ips))  # 去重保序（py2/py3 一致）

    # CPU 使用率：/proc/stat 两次采样求差
    basic['cpu_percent'] = cpu_percent()

    # 内存：/proc/meminfo
    try:
        info = {}
        with open('/proc/meminfo') as f:
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    info[parts[0].strip()] = to_float(parts[1].strip().split()[0])
        tot_kb = info.get('MemTotal')
        avail_kb = info.get('MemAvailable')
        if avail_kb is None:
            avail_kb = (info.get('MemFree', 0) + info.get('Buffers', 0)
                        + info.get('Cached', 0))
        if tot_kb:
            basic['mem_total_mb'] = round(tot_kb / 1024.0, 0)
            basic['mem_free_mb'] = round((avail_kb or 0) / 1024.0, 0)
            basic['mem_percent'] = round(((tot_kb - (avail_kb or 0)) / tot_kb) * 100, 1)
    except Exception:
        pass

    # 运行时长 / 开机时间：/proc/uptime
    try:
        with open('/proc/uptime') as f:
            up = to_float(f.read().split()[0])
        if up is not None:
            basic['uptime_seconds'] = round(up, 0)
            basic['boot_time'] = (datetime.now() - timedelta(seconds=up)).isoformat()
    except Exception:
        pass

    # 磁盘：df -Pl，仅保留设备名以 / 开头的真实块设备（排除 tmpfs/devtmpfs 等）
    disks = []
    rc, out = run(['df', '-Pl'])
    if rc == 0:
        for line in out.splitlines()[1:]:
            f = line.split()
            if len(f) < 6 or not f[0].startswith('/'):
                continue
            size_kb = to_float(f[1]); free_kb = to_float(f[3])
            pct = f[4].rstrip('%')
            disks.append({
                'device': f[5],
                'size_gb': round(size_kb / 1024.0 / 1024.0, 1) if size_kb else None,
                'free_gb': round(free_kb / 1024.0 / 1024.0, 1) if free_kb else None,
                'percent': to_float(pct),
            })
    basic['disks'] = disks
    return basic


def _read_stat():
    try:
        with open('/proc/stat') as f:
            line = f.readline()
        parts = [to_float(x, 0) for x in line.split()[1:]]
        idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
        total = sum(parts)
        return idle, total
    except Exception:
        return None, None


def cpu_percent():
    idle1, total1 = _read_stat()
    if idle1 is None:
        return None
    time.sleep(0.4)
    idle2, total2 = _read_stat()
    if idle2 is None:
        return None
    dt = total2 - total1
    di = idle2 - idle1
    if dt <= 0:
        return None
    return round((1.0 - di / dt) * 100, 1)


# ------------------------------------------------------------------ 用户与会话

def collect_users():
    users = {'logged_on': [], 'logged_on_count': 0, 'sessions': [],
             'session_count': 0, 'rdp_active': 0}
    rc, out = run(['who'])
    if rc != 0:
        return users
    seen_users = []
    sessions = []
    rdp = 0
    idx = 0
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        user = parts[0]
        tty = parts[1]
        rest = parts[2] if len(parts) > 2 else ''
        if not user or user in ('runlevel', 'reboot', 'LOGIN'):
            continue
        origin = ''
        m = re.search(r'\(([^)]*)\)', rest)
        if m:
            origin = m.group(1)
        idx += 1
        state = 'Active'
        sessions.append({
            'user': user, 'session': tty, 'id': idx,
            'state': state, 'raw': line, 'origin': origin,
        })
        if user not in seen_users:
            seen_users.append(user)
        blob = (tty + ' ' + origin).lower()
        if 'xrdp' in blob or ':0' in blob or 'vnc' in blob:
            rdp += 1
    users['sessions'] = sessions
    users['session_count'] = len(sessions)
    users['logged_on'] = seen_users
    users['logged_on_count'] = len(seen_users)
    users['rdp_active'] = rdp
    return users


# ------------------------------------------------------------------ 网络连接 / 监听端口

def _pid_name(process_field):
    """从 ss/netstat 的进程字段里提取 pid 与进程名。
    ss:  users:(("sshd",pid=1234,fd=3))   netstat: 1234/sshd
    """
    pid = None; name = ''
    if not process_field:
        return pid, name
    m = re.search(r'"([^"]+)",pid=(\d+)', process_field)
    if m:
        return to_int(m.group(2)), m.group(1)
    m = re.search(r'(\d+)/([\w.\-+]+)', process_field)
    if m:
        return to_int(m.group(1)), m.group(2)
    m = re.search(r'pid=(\d+)', process_field)
    if m:
        pid = to_int(m.group(1))
    return pid, name


def _split_addr(addr):
    """拆分 host:port，兼容 IPv6（[::]:22 / *:22 / 0.0.0.0:22）。"""
    if not addr:
        return '', None
    addr = addr.strip()
    if addr.rfind(':') == -1:
        return addr, None
    host, _, port = addr.rpartition(':')
    host = host.strip('[]')
    return host, to_int(port)


def _ss_lines():
    """优先 ss -tunap，退回 netstat -tunap。返回 (netid,state,local,peer,process) 元组列表。"""
    rows = []
    rc, out = run(['ss', '-tunap'])
    source = 'ss'
    if rc != 0 or not out.strip():
        rc, out = run(['netstat', '-tunap'])
        source = 'netstat'
        if rc != 0:
            return rows
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        low = s.lower()
        if low.startswith('netid') or low.startswith('proto') or low.startswith('active'):
            continue
        f = s.split()
        if source == 'ss':
            # Netid State Recv-Q Send-Q Local Peer Process...
            if len(f) < 6:
                continue
            netid = f[0].lower()
            state = f[1]
            local = f[4]
            peer = f[5]
            process = ' '.join(f[6:]) if len(f) > 6 else ''
        else:
            # Proto Recv-Q Send-Q Local Peer State Process...  (tcp)
            # Proto Recv-Q Send-Q Local Peer            Process... (udp 无 State)
            if len(f) < 5:
                continue
            proto = f[0].lower()
            local = f[3]
            peer = f[4]
            if proto.startswith('tcp'):
                state = f[5] if len(f) > 5 else ''
                process = ' '.join(f[6:]) if len(f) > 6 else ''
            else:
                state = ''
                process = ' '.join(f[5:]) if len(f) > 5 else ''
            netid = 'tcp' if proto.startswith('tcp') else 'udp'
        if netid not in ('tcp', 'udp'):
            continue
        rows.append((netid, state, local, peer, process))
    return rows


def collect_connections_and_listeners():
    conns = {'tcp_total': 0, 'by_state': {}, 'established': [],
             'established_total': 0, 'established_truncated': False,
             'remote_ip_top': [], 'udp_total': 0}
    listeners = []
    rows = _ss_lines()

    tcp_total = 0
    udp_total = 0
    by_state = {}
    established = []
    established_total = 0
    remote_agg = {}
    seen_listen = set()

    for netid, state, local, peer, process in rows:
        st = (state or '').upper()
        pid, pname = _pid_name(process)
        l_host, l_port = _split_addr(local)
        p_host, p_port = _split_addr(peer)
        if netid == 'tcp':
            tcp_total += 1
            if st:
                by_state[st] = by_state.get(st, 0) + 1
            if st == 'ESTAB':
                established_total += 1
                if p_host:
                    remote_agg[p_host] = remote_agg.get(p_host, 0) + 1
                if len(established) < MAX_CONN:
                    established.append({
                        'local_addr': l_host, 'local_port': l_port,
                        'remote_addr': p_host, 'remote_port': p_port,
                        'pid': pid, 'process': pname,
                    })
            elif st == 'LISTEN':
                key = ('TCP', l_host, l_port, pid)
                if key not in seen_listen:
                    seen_listen.add(key)
                    listeners.append({
                        'proto': 'TCP', 'local_addr': l_host, 'local_port': l_port,
                        'pid': pid, 'process': pname, 'service': '',
                    })
        else:  # udp
            udp_total += 1
            # UDP 无连接；UNCONN 且绑定了端口的视为监听
            if st in ('', 'UNCONN') and l_port is not None:
                key = ('UDP', l_host, l_port, pid)
                if key not in seen_listen:
                    seen_listen.add(key)
                    listeners.append({
                        'proto': 'UDP', 'local_addr': l_host, 'local_port': l_port,
                        'pid': pid, 'process': pname, 'service': '',
                    })

    conns['tcp_total'] = tcp_total
    conns['udp_total'] = udp_total
    conns['by_state'] = by_state
    conns['established'] = established
    # 明细样本有上限，计数必须是全量：上层若拿 len(established) 当"活动连接数"，
    # 截断后的数字就会被当成事实（Windows 侧已修同一类问题）。
    conns['established_total'] = established_total
    conns['established_truncated'] = established_total > len(established)
    top = sorted(remote_agg.items(), key=lambda kv: kv[1], reverse=True)[:30]
    conns['remote_ip_top'] = [{'ip': k, 'count': v} for k, v in top]
    return conns, listeners


# ------------------------------------------------------------------ 服务

def collect_services():
    """采全部状态的服务单元，返回 {'services', 'services_total', 'services_other', ...}。

    以前只采 --state=running：一台机上"该起却没起"的服务恰恰是故障本身，
    只报运行中的等于把最关键的线索藏起来。Windows 侧已同步改为全状态采集。
    """
    out = {'services': [], 'services_total': 0, 'services_other': [],
           'services_other_total': 0, 'services_other_dropped': 0, 'error': ''}
    rc, txt = run(['systemctl', 'list-units', '--type=service', '--all',
                   '--no-legend', '--no-pager'])
    if rc == 0 and txt.strip():
        other_total = 0
        for line in txt.splitlines():
            s = line.strip()
            if not s or s.startswith('*'):
                s = s.lstrip('*').strip()
            if not s:
                continue
            f = s.split(None, 4)
            # UNIT LOAD ACTIVE SUB DESCRIPTION
            if len(f) < 4:
                continue
            if not UNIT_LINE_RE.match(s):
                continue      # 滤掉表头/图例/页脚，避免凭空多出 UNIT、LOAD 之类"服务"
            if f[1] != 'loaded':
                continue      # not-found/masked 的残留单元不是"这台机上的服务"
            unit = f[0]
            desc = f[4] if len(f) > 4 else ''
            active, sub = f[2], f[3]
            # systemctl 的 enabled/disabled 要另查，成本高；这里给 active 态即可，
            # 上层判断"自动启动却停止"用的是 Windows 的 start_mode，Linux 留空不影响。
            item = {'name': unit.replace('.service', ''),
                    'display_name': desc or unit,
                    'status': sub or active, 'start_mode': ''}
            if active == 'active' and sub == 'running':
                out['services'].append(item)
            else:
                other_total += 1
                if len(out['services_other']) < MAX_SVC_OTHER:
                    out['services_other'].append(item)
        out['services_total'] = len(out['services'])
        out['services_other_total'] = other_total
        out['services_other_dropped'] = max(0, other_total - len(out['services_other']))
        return out
    # 退回：service --status-all。'[ + ]' 才是运行中，'[ - ]' 是停止——
    # 以前一律标 running，等于把停止的服务说成在跑。
    rc, txt = run(['service', '--status-all'])
    if rc != 0:
        out['error'] = 'systemctl 与 service 均不可用（非 systemd 或无权限）'
        return out
    other_total = 0
    for line in txt.splitlines():
        m = re.search(r'\[\s*([+-?])\s*\]\s+([\w.\-+]+)', line)
        if not m:
            continue
        # '[ ? ]' 是该 init 脚本没有 status 动作，属"不知道"，不能当成"已停止"
        st = {'+': 'running', '-': 'stopped'}.get(m.group(1), 'unknown')
        item = {'name': m.group(2), 'display_name': m.group(2),
                'status': st, 'start_mode': ''}
        if st == 'running':
            out['services'].append(item)
        else:
            other_total += 1
            if len(out['services_other']) < MAX_SVC_OTHER:
                out['services_other'].append(item)
    out['services_total'] = len(out['services'])
    out['services_other_total'] = other_total
    out['services_other_dropped'] = max(0, other_total - len(out['services_other']))
    return out


# ------------------------------------------------------------------ 进程

def collect_processes():
    """返回 (procs, total, truncated)。

    上限只截"明细条数"，总数必须继续数完：以前到 MAX_PROC 就 break，
    上层只能拿 len(procs) 当进程总数，截断值于是被当成了事实。
    """
    procs = []
    rc, out = run(['ps', '-eo', 'pid,rss,comm,args', '--sort=-rss'])
    if rc != 0:
        rc, out = run(['ps', '-eo', 'pid,rss,comm,args'])
    if rc != 0:
        return procs, 0, False
    total = 0
    lines = out.splitlines()
    for line in lines[1:]:
        s = line.strip()
        if not s:
            continue
        f = s.split(None, 3)
        if len(f) < 3:
            continue
        total += 1
        if len(procs) >= MAX_PROC:
            continue
        pid = to_int(f[0])
        rss_kb = to_float(f[1])
        comm = f[2]
        args = f[3] if len(f) > 3 else ''
        procs.append({
            'name': comm, 'pid': pid,
            'mem_mb': round(rss_kb / 1024.0, 1) if rss_kb else 0.0,
            'command_line': args[:300],
        })
    return procs, total, total > len(procs)


# ------------------------------------------------------------------ Supervisor

SUP_CONF_DIRS = ['/etc/supervisord.d', '/etc/supervisor/conf.d',
                 '/etc/supervisor.d', '/etc/supervisor']
SUP_MAIN_CONFS = ['/etc/supervisord.conf', '/etc/supervisor/supervisord.conf']


def _parse_programs_from_ini(path, fname):
    """从 supervisor ini/conf 里解析 [program:x] / command / stdout_logfile。"""
    progs = []
    cur = None
    try:
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith(';') or line.startswith('#'):
                    continue
                m = re.match(r'^\[program:(.+)\]$', line)
                if m:
                    if cur:
                        progs.append(cur)
                    cur = {'name': m.group(1).strip(), 'port': None,
                           'command': '', 'stdout_logfile': '', 'ini_file': fname}
                    continue
                if line.startswith('['):
                    if cur:
                        progs.append(cur); cur = None
                    continue
                if cur is None:
                    continue
                # 精确按 key 比较：startswith('stdout_logfile') 会误命中
                # stdout_logfile_maxbytes / stdout_logfile_backups，把 "10MB"/"10"
                # 当成日志路径覆盖真实值。
                key = line.split('=', 1)[0].strip() if '=' in line else ''
                val = line.split('=', 1)[1].strip() if '=' in line else ''
                if key == 'command':
                    cur['command'] = val[:300]
                    p = port_from_text(val)
                    if p:
                        cur['port'] = p
                elif key == 'stdout_logfile':
                    # 就地展开 supervisor 的 %(program_name)s，否则登记的是未替换原文，
                    # 磁盘上"文件不存在"（真实文件名由 supervisor 按程序名生成）。
                    if cur.get('name') and '%(program_name)s' in val:
                        val = val.replace('%(program_name)s', cur['name'])
                    cur['stdout_logfile'] = val
    except Exception:
        return progs
    if cur:
        progs.append(cur)
    return progs


def collect_supervisor():
    sup = {'detected': False, 'programs': [], 'ini_programs': []}

    # 1) 运行中的应用进程命令行里识别端口（runserver/uwsgi/--http）
    rc, out = run(['ps', '-eo', 'pid,args'])
    if rc == 0:
        for line in out.splitlines()[1:]:
            s = line.strip()
            if not s:
                continue
            f = s.split(None, 1)
            if len(f) < 2:
                continue
            pid = to_int(f[0]); args = f[1]
            low = args.lower()
            if 'runserver' in low or 'uwsgi' in low or '--http' in low or 'gunicorn' in low:
                sup['programs'].append({
                    'pid': pid, 'port': port_from_text(args),
                    'command': args[:300],
                })

    # 2) 解析 supervisor 配置里的 program 定义
    ini_progs = []
    etc_dir = ''
    for conf in SUP_MAIN_CONFS:
        if os.path.isfile(conf):
            sup['detected'] = True
            sup['service_exe'] = conf
            ini_progs.extend(_parse_programs_from_ini(conf, os.path.basename(conf)))
    for d in SUP_CONF_DIRS:
        if not os.path.isdir(d):
            continue
        etc_dir = etc_dir or d
        try:
            names = sorted(os.listdir(d))
        except Exception:
            continue
        for nm in names:
            if not (nm.endswith('.ini') or nm.endswith('.conf')):
                continue
            fp = os.path.join(d, nm)
            if os.path.isfile(fp):
                sup['detected'] = True
                ini_progs.extend(_parse_programs_from_ini(fp, nm))
    if etc_dir:
        sup['etc_dir'] = etc_dir

    # 3) supervisorctl 兜底探测（只读 status）
    if not sup['detected']:
        rc, out = run(['supervisorctl', 'status'])
        if rc == 0 and out.strip():
            sup['detected'] = True
    # supervisord 进程存在也算 detected
    if not sup['detected']:
        rc, out = run(['pgrep', '-f', 'supervisord'])
        if rc == 0 and out.strip():
            sup['detected'] = True

    sup['ini_programs'] = ini_progs
    return sup


# ------------------------------------------------------------------ 主流程

def collect_app_log(path):
    """只读探测应用/supervisor 日志文件的新鲜度(mtime)与尾部若干行，
    作为"应用是否仍在运行"的旁证（日志近期有写入 → 应用大概率活着）。
    红线：只读文件属性与尾部，绝不改写/删除/轮转日志。path 为空则不作探测。"""
    res = {'path': path or '', 'exists': False, 'size': None, 'mtime': '',
           'mtime_ago_sec': None, 'last_lines': [], 'error': ''}
    if not path:
        res['error'] = '未提供日志路径'
        return res
    try:
        if not os.path.isfile(path):
            res['error'] = '文件不存在'
            return res
        st = os.stat(path)
        res['exists'] = True
        res['size'] = st.st_size
        res['mtime'] = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        res['mtime_ago_sec'] = int(time.time() - st.st_mtime)
        # 只读尾部 64KB 取最后 5 行，避免加载超大日志
        try:
            with open(path, 'rb') as f:
                if st.st_size > 65536:
                    f.seek(st.st_size - 65536)
                    f.read(1024)  # 丢弃可能被截断的半行
                raw = f.read()
            lines = raw.decode('utf-8', 'replace').splitlines()
            res['last_lines'] = [ln.strip()[:300] for ln in lines[-5:] if ln.strip()]
        except Exception:
            pass
    except Exception as e:
        res['error'] = str(e)
    return res


# ------------------------------------------------------------------ 操作系统日志

def _tail_lines(path, max_lines=600, kb=256):
    """只读文件尾部若干行（避免加载超大日志）。不存在/无权限返回 []。"""
    try:
        st = os.stat(path)
    except Exception:
        return []
    try:
        with open(path, 'rb') as f:
            if st.st_size > kb * 1024:
                f.seek(st.st_size - kb * 1024)
                f.read(1024)          # 丢弃可能被截断的半行
            raw = f.read()
    except Exception:
        return []
    lines = raw.decode('utf-8', 'replace').splitlines()
    return [ln for ln in lines[-max_lines:] if ln.strip()]


def _fmt_ts(y, mo, d, h, mi, s):
    try:
        return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s)).strftime(
            '%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return ''


def _syslog_ts(mo, day, h, mi, s, year=None):
    """syslog/last/dmesg 时间戳 → '%Y-%m-%d %H:%M:%S'。
    syslog 不带年份：按当前年推断，若结果落在未来超过一天则回退到去年（跨年日志）。"""
    mon = _MONTHS.get((mo or '')[:3].lower(), 0)
    if not mon:
        return ''
    if year:
        return _fmt_ts(year, mon, day, h, mi, s)
    now = datetime.now()
    ts = _fmt_ts(now.year, mon, day, h, mi, s)
    if ts:
        try:
            if datetime.strptime(ts, '%Y-%m-%d %H:%M:%S') > now + timedelta(days=1):
                ts = _fmt_ts(now.year - 1, mon, day, h, mi, s)
        except (ValueError, TypeError):
            pass
    return ts


def collect_os_logs():
    """近 N 日操作系统日志（只读）。输出结构与 Windows 采集器 os_logs 完全一致，
    上层分析无需区分 OS：
      {os_type, days, since, total_matched, counts, truncated, events, errors}
      events: [{ts, log, id, level, source, kind, message}]

    kind 与 Windows 侧对齐，便于共用同一套分析规则：
      reboot      重启/关机（last -x；对应 Windows 1074/6008/41）
      oom         内存耗尽被杀（dmesg/journal 的 Out of memory / Killed process）
      kernel      内核错误（dmesg --level=err..emerg）
      service     服务失败/被停/被启（systemctl + journal，对应 Windows 7034/7045）
      syslog_err  err 及以上系统日志（journalctl 优先，无 systemd 时回退 /var/log）
      auth        登录与 sudo 提权（/var/log/secure 或 auth.log）
      cron        定时任务执行（/var/log/cron）
      pkg         软件包安装/升级（/var/log/yum.log）

    红线：只用只读命令（last/dmesg/journalctl/systemctl list-units/tail 文本日志），
    绝不清除日志、绝不改配置、绝不重启任何服务。无权限的日志静默跳过并记入 errors。"""
    errors = []
    evs = []
    kind_counts = {}
    kind_dropped = {}
    now = datetime.now()
    cutoff = now - timedelta(days=max(1, OS_LOG_DAYS))
    cutoff_s = cutoff.strftime('%Y-%m-%d %H:%M:%S')

    def in_window(ts):
        """ts 为空表示无法判定时间（如 dmesg 不带 -T）——保守保留，宁多勿漏。"""
        if not ts:
            return True
        try:
            return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S') >= cutoff
        except (ValueError, TypeError):
            return True

    def add(kind, ts, message, level='Information', source='', log=''):
        m = re.sub(r'\s+', ' ', str(message or '')).strip()[:300]
        if not m or not in_window(ts):
            return
        if kind_counts.get(kind, 0) >= MAX_OSLOG_PER_KIND:
            # 如实记账：以前这里直接 return，被丢的事件既不计数也不留痕，
            # 于是上层的 counts/total_matched 变成"采到的条数"而不是"发生的条数"，
            # "一天刷了 800 条同一个错误"会被显示成"60 条"，且看不出被截过。
            kind_dropped[kind] = kind_dropped.get(kind, 0) + 1
            return
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        evs.append({'ts': ts or '', 'log': log, 'id': 0, 'level': level,
                    'source': source or '', 'kind': kind, 'message': m})

    # ---- 1) 重启 / 关机 ----
    rc, out = run(['last', '-x', '-F', '-n', '40', 'reboot', 'shutdown'])
    if rc != 0 or not (out or '').strip():
        rc, out = run(['last', '-x', '-n', '40', 'reboot', 'shutdown'])
    if rc != 0:
        errors.append('last 不可用（无法获取重启/关机记录）')
    for ln in (out or '').splitlines():
        s = ln.strip()
        if not s:
            continue
        head = s.split()[0].lower()
        if head not in ('reboot', 'shutdown'):
            continue
        m = LAST_LONG_RE.search(s)
        if m:
            ts = _syslog_ts(m.group(1), m.group(2), m.group(3), m.group(4),
                            m.group(5), year=m.group(6))
        else:
            m2 = LAST_SHORT_RE.search(s)
            ts = _syslog_ts(m2.group(1), m2.group(2), m2.group(3), m2.group(4), '00') if m2 else ''
        add('reboot', ts, s, level='Warning' if head == 'shutdown' else 'Information',
            source='last', log='wtmp')

    # ---- 2) 内核错误 / OOM ----
    rc, out = run(['dmesg', '-T', '--level=emerg,alert,crit,err'])
    dlines = []
    if rc == 0 and (out or '').strip():
        dlines = out.splitlines()
    else:
        rc2, out2 = run(['dmesg', '-T'])
        if rc2 != 0:
            rc2, out2 = run(['dmesg'])
        if rc2 == 0:
            # 老 util-linux 不支持 --level：全量 dmesg 再按关键字过滤
            dlines = [l for l in (out2 or '').splitlines()
                      if re.search(r'error|fail|critical|oom|killed process|segfault'
                                   r'|i/o error|panic', l, re.I)]
        else:
            errors.append('dmesg 不可用或无权限（kernel.dmesg_restrict）')
    for ln in dlines:
        m = DMESG_RE.match(ln.strip())
        if m:
            ts = _syslog_ts(m.group(1), m.group(2), m.group(3), m.group(4),
                            m.group(5), year=m.group(6))
            msg = m.group(7)
        else:
            ts = ''
            msg = re.sub(r'^\[\s*[\d.]+\s*\]\s*', '', ln.strip())
        if not msg:
            continue
        if re.search(r'out of memory|oom-killer|killed process|oom_reaper', msg, re.I):
            add('oom', ts, msg, level='Error', source='kernel', log='dmesg')
        else:
            add('kernel', ts, msg, level='Error', source='kernel', log='dmesg')

    # ---- 3) 当前失败的 systemd 单元 ----
    rc, out = run(['systemctl', 'list-units', '--state=failed', '--no-legend',
                   '--plain', '--no-pager'])
    if rc == 0:
        for ln in (out or '').splitlines():
            s = ln.strip()
            if not s:
                continue
            if not UNIT_LINE_RE.match(s):
                continue          # 表头/图例/页脚，不是单元行
            add('service', now.strftime('%Y-%m-%d %H:%M:%S'),
                '采集时刻处于 failed 状态：%s' % s,
                level='Error', source='systemctl', log='systemd')
    else:
        errors.append('systemctl 不可用（非 systemd 或无权限）')

    # ---- 4) journal：err 及以上 + 服务启停 ----
    have_journal = run(['journalctl', '--version'])[0] == 0
    if have_journal:
        rc, out = run(['journalctl', '--since', cutoff_s, '-p', 'err..emerg',
                       '--no-pager', '-o', 'short-iso',
                       '-n', str(MAX_OSLOG_PER_KIND * 3)])
        if rc == 0:
            for ln in (out or '').splitlines():
                s = ln.strip()
                if not s or s.startswith('--'):
                    continue
                m = JOURNAL_ISO_RE.match(s)
                if m:
                    ts = _fmt_ts(m.group(1), m.group(2), m.group(3),
                                 m.group(4), m.group(5), m.group(6))
                    rest = m.group(8)
                else:
                    ts = ''
                    rest = s
                src = ''
                mm = re.match(r'(\S+?)(?:\[\d+\])?:\s*(.*)$', rest)
                if mm:
                    src = mm.group(1)
                    rest = mm.group(2)
                if re.search(r'out of memory|oom-killer|killed process', rest, re.I):
                    add('oom', ts, rest, level='Error', source=src, log='journal')
                else:
                    add('syslog_err', ts, rest, level='Error', source=src, log='journal')
        else:
            errors.append('journalctl 读取失败（需 root 或 systemd-journal/adm 组）')

        rc, out = run(['journalctl', '--since', cutoff_s, '-t', 'systemd',
                       '--no-pager', '-o', 'short-iso',
                       '-n', str(MAX_OSLOG_PER_KIND * 4)])
        if rc == 0:
            keep = re.compile(r'Failed to start|entered failed state|Failed with result'
                              r'|Deactivated unsuccessfully|Stopped |Starting |Started ',
                              re.I)
            for ln in (out or '').splitlines():
                s = ln.strip()
                if not s or s.startswith('--'):
                    continue
                m = JOURNAL_ISO_RE.match(s)
                if m:
                    ts = _fmt_ts(m.group(1), m.group(2), m.group(3),
                                 m.group(4), m.group(5), m.group(6))
                    rest = m.group(8)
                else:
                    ts = ''
                    rest = s
                mm = re.match(r'(\S+?)(?:\[\d+\])?:\s*(.*)$', rest)
                if mm:
                    rest = mm.group(2)
                if not keep.search(rest):
                    continue
                add('service', ts, rest,
                    level='Error' if re.search(r'fail', rest, re.I) else 'Information',
                    source='systemd', log='journal')
    else:
        errors.append('journalctl 不可用（非 systemd），已回退 /var/log 文本日志')
        for p in ('/var/log/messages', '/var/log/syslog'):
            if not os.path.isfile(p):
                continue
            got = False
            for ln in _tail_lines(p, max_lines=1500):
                m = SYSLOG_RE.match(ln)
                if not m:
                    continue
                ts = _syslog_ts(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5))
                if not in_window(ts):
                    continue
                msg = m.group(7)
                got = True
                if re.search(r'out of memory|oom-killer|killed process', msg, re.I):
                    add('oom', ts, msg, level='Error', source=m.group(6), log=p)
                elif re.search(r'error|fail|crit|emerg|alert|panic', msg, re.I):
                    add('syslog_err', ts, msg, level='Error', source=m.group(6), log=p)
            if got:
                break

    # ---- 5) 登录与 sudo 提权 ----
    auth_file = ''
    for p in ('/var/log/secure', '/var/log/auth.log'):
        if os.path.isfile(p):
            auth_file = p
            break
    if auth_file:
        pat = re.compile(r'sudo:|COMMAND=|Accepted password|Accepted publickey'
                         r'|Failed password|authentication failure|invalid user', re.I)
        for ln in _tail_lines(auth_file, max_lines=2000):
            m = SYSLOG_RE.match(ln)
            if not m:
                continue
            msg = m.group(7)
            if not pat.search(msg):
                continue
            ts = _syslog_ts(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5))
            add('auth', ts, msg,
                level='Warning' if re.search(r'fail|invalid', msg, re.I) else 'Information',
                source=m.group(6), log=auth_file)
    else:
        errors.append('未找到 /var/log/secure 或 /var/log/auth.log（无法采集登录/sudo）')

    # ---- 6) 定时任务 ----
    for p in ('/var/log/cron', '/var/log/syslog', '/var/log/messages'):
        if not os.path.isfile(p):
            continue
        for ln in _tail_lines(p, max_lines=1500):
            m = SYSLOG_RE.match(ln)
            if not m:
                continue
            if 'CROND' not in m.group(7) and 'cron' not in (m.group(6) or '').lower():
                continue
            ts = _syslog_ts(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5))
            add('cron', ts, m.group(7), level='Information', source=m.group(6), log=p)
        break

    # ---- 7) 软件包安装/升级 ----
    if os.path.isfile('/var/log/yum.log'):
        for ln in _tail_lines('/var/log/yum.log', max_lines=800):
            m = re.match(r'^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(.*)$',
                         ln.strip())
            if not m:
                continue
            ts = _syslog_ts(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5))
            add('pkg', ts, m.group(6), level='Information', source='yum',
                log='/var/log/yum.log')

    counts = dict(kind_counts)
    evs.sort(key=lambda e: e.get('ts') or '', reverse=True)
    # total_matched 必须是"匹配到的条数"，含被单类上限与总上限丢掉的：
    # 以前它等于 len(截断后的 evs)，于是 truncated 永远为 False，
    # 页面上看不出数据被截过——和被静默丢弃是同一个问题。
    per_kind_dropped = sum(kind_dropped.values())
    kept = min(len(evs), MAX_OSLOG_TOTAL)
    total = len(evs) + per_kind_dropped
    truncated = total > kept
    evs = evs[:MAX_OSLOG_TOTAL]
    if per_kind_dropped:
        errors.append('单类事件上限 %d 条已触顶，被丢弃 %s（这些是"发生过但没逐条送出"，'
                      '不代表无异常）' % (MAX_OSLOG_PER_KIND,
                                        '、'.join('%s=%d' % (k, v)
                                                  for k, v in sorted(kind_dropped.items()))))
    return {'os_type': 'linux', 'days': OS_LOG_DAYS, 'since': cutoff_s,
            'total_matched': total, 'counts': counts, 'truncated': truncated,
            'dropped': total - len(evs),
            'dropped_by_kind': kind_dropped,
            'logs_scanned': ['last(wtmp)', 'dmesg', 'journalctl', 'systemctl --state=failed',
                             '/var/log/secure 或 auth.log', '/var/log/cron', '/var/log/yum.log'],
            'level_filter': ('采集源：last 重启/关机、dmesg 与 journalctl 的 err 及以上、'
                             'systemctl --state=failed、/var/log/secure(auth.log) 登录与 sudo、'
                             'cron、yum.log；未覆盖的日志源及其中 info 级消息不采集'),
            'events': evs, 'errors': errors}


def main():
    _args(sys.argv[1:])
    data = {
        'collected_at': now_iso(),
        'os_type': 'linux',
    }
    try:
        data['basic'] = collect_basic()
    except Exception:
        data['basic'] = {}
    try:
        data['users'] = collect_users()
    except Exception:
        data['users'] = {'logged_on': [], 'logged_on_count': 0, 'sessions': [],
                         'session_count': 0, 'rdp_active': 0}
    try:
        conns, listeners = collect_connections_and_listeners()
    except Exception:
        conns = {'tcp_total': 0, 'by_state': {}, 'established': [],
                 'established_total': 0, 'established_truncated': False,
                 'remote_ip_top': [], 'udp_total': 0}
        listeners = []
    data['connections'] = conns
    data['listeners'] = listeners
    try:
        svc = collect_services()
    except Exception as e:
        svc = {'services': [], 'services_total': 0, 'services_other': [],
               'services_other_total': 0, 'services_other_dropped': 0,
               'error': 'collect_failed: %s' % e}
    data['services'] = svc['services']
    data['services_total'] = svc['services_total']
    data['services_other'] = svc['services_other']
    data['services_other_total'] = svc['services_other_total']
    data['services_other_dropped'] = svc['services_other_dropped']
    if svc.get('error'):
        data['services_error'] = svc['error']
    try:
        procs, proc_total, proc_trunc = collect_processes()
    except Exception:
        procs, proc_total, proc_trunc = [], 0, False
    data['processes'] = procs
    data['processes_total'] = proc_total
    data['processes_truncated'] = proc_trunc
    try:
        data['supervisor'] = collect_supervisor()
    except Exception:
        data['supervisor'] = {'detected': False, 'programs': [], 'ini_programs': []}
    try:
        data['app_log'] = collect_app_log(APP_LOG_PATH)
    except Exception:
        data['app_log'] = {'path': APP_LOG_PATH, 'exists': False, 'size': None,
                           'mtime': '', 'mtime_ago_sec': None, 'last_lines': [],
                           'error': 'probe_failed'}
    try:
        data['os_logs'] = collect_os_logs()
    except Exception as e:
        data['os_logs'] = {'os_type': 'linux', 'days': OS_LOG_DAYS, 'since': '',
                           'total_matched': 0, 'counts': {}, 'truncated': False,
                           'events': [], 'errors': ['collect_failed: %s' % e]}

    print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))


if __name__ == '__main__':
    main()
