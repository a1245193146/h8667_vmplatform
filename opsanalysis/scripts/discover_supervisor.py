# -*- coding: utf-8 -*-
"""运维分析——Supervisor 程序只读发现（服务关联发现用）。

红线：全程只读，仅 `supervisorctl status` 与读取 supervisor 配置文件，
绝不 start/stop/restart 任何 program。
输出每个 program 的：name / port(从 command 提取) / command / stdout_logfile /
ini_file / status(supervisorctl)。供 Django 侧按 ip:port 关联 nginx / jenkins。

兼容 Python 2.7 / 3.x。用法:
    python discover_supervisor.py
作者: AUTO-GENERATED (opsanalysis module)
"""
from __future__ import print_function

import glob
import json
import os
import re
import socket
import subprocess
import sys

PORT_RE = re.compile(r'(?:--http\s*:?|0\.0\.0\.0:|127\.0\.0\.1:|:)(\d{2,5})\b')
SUP_CONF_DIRS = ['/etc/supervisord.d', '/etc/supervisor/conf.d',
                 '/etc/supervisor.d', '/etc/supervisor']
# 主配置候选：supervisord.conf 常见于 /etc 或 /etc/supervisor；
# 用户环境里 supervisorctl.conf 也放在 /etc/ 下，一并作为主配置尝试解析 [include]。
SUP_MAIN_CONFS = ['/etc/supervisord.conf', '/etc/supervisor/supervisord.conf',
                  '/etc/supervisorctl.conf', '/etc/supervisor/supervisorctl.conf']
INCLUDE_FILES_RE = re.compile(r'^files\s*=\s*(.+)$')


def run(cmd):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = p.communicate()
        if isinstance(out, bytes):
            out = out.decode('utf-8', 'replace')
        return (p.returncode or 0), out
    except Exception:
        return (-1, '')


def host_ip():
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
    return ','.join(ips)


def port_from_text(text):
    if not text:
        return None
    m = PORT_RE.search(text)
    if m:
        try:
            p = int(m.group(1))
        except (ValueError, TypeError):
            return None
        if 1 <= p <= 65535:
            return p
    return None


def parse_ini(path, fname, progs):
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
                    cur = {'name': m.group(1).strip(), 'port': None, 'command': '',
                           'stdout_logfile': '', 'ini_file': fname, 'status': ''}
                    continue
                if line.startswith('['):
                    if cur:
                        progs.append(cur); cur = None
                    continue
                if cur is None:
                    continue
                # 精确按 key 比较：startswith('stdout_logfile') 会误命中
                # stdout_logfile_maxbytes / stdout_logfile_backups，导致把 "10MB"/"10"
                # 当成日志路径覆盖真实值（线上曾出现 app_log_path 被写成 "10"）。
                key = line.split('=', 1)[0].strip() if '=' in line else ''
                val = line.split('=', 1)[1].strip() if '=' in line else ''
                if key == 'command':
                    cur['command'] = val[:300]
                    p = port_from_text(val)
                    if p:
                        cur['port'] = p
                elif key == 'stdout_logfile':
                    # supervisor 启动时会用程序名展开 %(program_name)s（如
                    # /opt/logs/%(program_name)s_deubg.log → /opt/logs/h14_mes_deubg.log）。
                    # 登记前就地展开，否则存的是未替换原文，磁盘上"文件不存在"。
                    if cur.get('name') and '%(program_name)s' in val:
                        val = val.replace('%(program_name)s', cur['name'])
                    cur['stdout_logfile'] = val
    except Exception:
        return
    if cur:
        progs.append(cur)


def include_globs(path):
    """读取主配置里的 [include] files= 值，展开成实际文件路径列表。
    supervisor 的 files= 支持空格分隔的多个 glob（相对路径按主配置所在目录解析）。"""
    out = []
    in_include = False
    base = os.path.dirname(path)
    try:
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith(';') or line.startswith('#'):
                    continue
                if line.startswith('['):
                    in_include = (line.lower() == '[include]')
                    continue
                if in_include:
                    m = INCLUDE_FILES_RE.match(line)
                    if not m:
                        continue
                    for tok in m.group(1).split():
                        tok = tok.strip()
                        if not tok:
                            continue
                        if not os.path.isabs(tok):
                            tok = os.path.join(base, tok)
                        for fp in sorted(glob.glob(tok)):
                            if os.path.isfile(fp) and fp not in out:
                                out.append(fp)
    except Exception:
        return out
    return out


def ctl_status_map():
    """supervisorctl status → {program: state}，best-effort。"""
    m = {}
    rc, out = run(['supervisorctl', 'status'])
    if rc not in (0, 3, 4):  # 3/4 表示有 program 非 RUNNING，仍可读
        return m
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        parts = s.split(None, 1)
        if len(parts) >= 1:
            state = parts[1].split()[0] if len(parts) > 1 and parts[1].split() else ''
            m[parts[0]] = state
    return m


def main():
    data = {'ip': host_ip(), 'programs': [], 'etc_dir': '', 'detected': False, 'error': ''}
    try:
        progs = []
        seen = set()

        def do_parse(fp):
            fp = os.path.abspath(fp)
            if fp in seen or not os.path.isfile(fp):
                return
            seen.add(fp)
            data['detected'] = True
            parse_ini(fp, os.path.basename(fp), progs)

        # 1) 主配置 + 其 [include] files= 展开（最权威，能定位真实 program 目录）
        for conf in SUP_MAIN_CONFS:
            if os.path.isfile(conf):
                do_parse(conf)
                for inc in include_globs(conf):
                    do_parse(inc)

        # 2) 常见 program 配置目录
        etc_dir = ''
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
                do_parse(os.path.join(d, nm))

        # 3) 兜底：/etc 顶层的 *.ini（用户环境里 program 配置可能直接放 /etc/ 下）
        try:
            for nm in sorted(os.listdir('/etc')):
                if nm.endswith('.ini'):
                    do_parse(os.path.join('/etc', nm))
        except Exception:
            pass

        if etc_dir:
            data['etc_dir'] = etc_dir
        elif seen:
            data['etc_dir'] = os.path.dirname(sorted(seen)[0])
        if not data['detected']:
            rc, out = run(['pgrep', '-f', 'supervisord'])
            if rc == 0 and out.strip():
                data['detected'] = True
        # 合并 supervisorctl 运行状态
        st = ctl_status_map()
        for p in progs:
            if p['name'] in st:
                p['status'] = st[p['name']]
        # 即便没解析到 ini，也把 supervisorctl 里的 program 收进来
        known = set(p['name'] for p in progs)
        for name, state in st.items():
            if name not in known:
                progs.append({'name': name, 'port': None, 'command': '',
                              'stdout_logfile': '', 'ini_file': '', 'status': state})
                data['detected'] = True
        data['programs'] = progs
    except Exception as e:
        data['error'] = 'supervisor_error: %s' % e
    print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))


if __name__ == '__main__':
    main()
