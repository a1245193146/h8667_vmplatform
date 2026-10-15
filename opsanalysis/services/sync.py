"""运维分析——Ansible 控制机脚本自动同步（只读采集脚本 / playbook 下发）。

背景：ops 的 playbook 与目标端脚本必须存在于 Ansible 控制机(10.2.20.226)上，
ansible 的 copy/win_copy 才能把它们再推到目标机。为避免人工复制放错目录，
这里在每次运行 ops playbook 前，用 SFTP 把本仓库的三类文件自动同步到控制机
固定目录，并按"内容指纹"增量上传（未变化则整批跳过）：

    本地(应用服务器)                       远端(控制机)
    opsanalysis/ansible/*.yml      →   {REMOTE_BASE}/*.yml
    opsanalysis/scripts/*.py       →   {REMOTE_BASE}/scripts/*.py
    opsanalysis/powershell/*.ps1   →   {REMOTE_BASE}/powershell/*.ps1

REMOTE_BASE 默认 /etc/ansible/playbooks/opsanalysis（可用 settings 覆盖）。
运行时把 script_dir / ps_dir 作为 -e 显式传给 playbook，故不依赖 playbook 里
`playbook_dir ~ '/../scripts'` 的默认相对路径（那会指到 playbooks/ 父级）。

红线：只同步 ops 自己的这三类文件到约定目录，绝不触碰控制机上的 inventory、
凭据、其它模块的 playbook；SFTP 失败不抛出，只告警并让 playbook 自行报错定位。
"""
import hashlib
import logging
import os
import posixpath
import re
import time

import paramiko
from django.conf import settings

from firewall.services.ansible_executor import run_playbook

logger = logging.getLogger(__name__)

# 控制机上 ops playbook 目录（相对 WORKDIR=/etc/ansible 的子路径），供 run_playbook 用
OPS_SUBDIR = 'playbooks/opsanalysis'

DEFAULT_REMOTE_BASE = '/etc/ansible/playbooks/opsanalysis'
_MARKER = '.ops_sync_sha'

# opsanalysis 包目录（services/ 的上一级）
_PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# (本地目录, 远端子目录, 允许的扩展名)
_LOCAL_SOURCES = [
    (os.path.join(_PKG_DIR, 'ansible'), '', '.yml'),
    (os.path.join(_PKG_DIR, 'scripts'), 'scripts', '.py'),
    (os.path.join(_PKG_DIR, 'powershell'), 'powershell', '.ps1'),
]

# 进程内缓存：上次成功同步的本地指纹（celery -P solo 单进程可跨任务复用）
_SYNCED = {'fp': None}

# 进程内缓存：inventory 主机集合、TTL 探测结果（避免重复 SSH / ping）
_INV_CACHE = {}
_TTL_CACHE = {}
# 存活探测缓存：ip -> (探测时刻, 是否在线)；短 TTL，避免一次发现内对同机反复 ping
_ALIVE_CACHE = {}

_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


# ------------------------------------------------------------------ 配置/路径

def _cfg():
    return getattr(settings, 'OPS_DISCOVERY_CONFIG', {}) or {}


def _remote_base():
    return (_cfg().get('REMOTE_BASE') or DEFAULT_REMOTE_BASE).rstrip('/')


def remote_script_dir():
    """控制机上 Linux 目标端脚本目录（传给 playbook 的 -e script_dir）。"""
    return _remote_base() + '/scripts'


def remote_ps_dir():
    """控制机上 PowerShell 脚本目录（传给 playbook 的 -e ps_dir）。"""
    return _remote_base() + '/powershell'


def windows_inventory():
    """Windows 目标所用 inventory（与 Linux 分开，见 settings.OPS_DISCOVERY_CONFIG）。"""
    return _cfg().get('WINDOWS_INVENTORY') or 'inventory.d/windows_dynamic.ini'


def linux_inventory():
    """Linux 目标所用 inventory（默认 hosts）。"""
    return _cfg().get('INVENTORY') or 'hosts'


def _sh(s):
    """把字符串安全放进单引号（同 ansible_executor 的转义规则）。"""
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


# ------------------------------------------------------------------ 本地清单/指纹

def _sha_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _local_files():
    """返回 [(本地绝对路径, 远端绝对路径, 展示用相对名)]，按名字排序保证指纹稳定。"""
    out = []
    base = _remote_base()
    for localdir, sub, ext in _LOCAL_SOURCES:
        if not os.path.isdir(localdir):
            continue
        for name in sorted(os.listdir(localdir)):
            if not name.endswith(ext):
                continue
            ap = os.path.join(localdir, name)
            if not os.path.isfile(ap):
                continue
            rpath = posixpath.join(base, sub, name) if sub else posixpath.join(base, name)
            rel = (sub + '/' + name) if sub else name
            out.append((ap, rpath, rel))
    return out


def _fingerprint(files):
    h = hashlib.sha256()
    for _ap, _rpath, rel in files:
        h.update(rel.encode('utf-8'))
        h.update(_sha_file(_ap).encode('utf-8'))
    return h.hexdigest()


# ------------------------------------------------------------------ 同步

def ensure_ops_synced(force=False):
    """把本地 ops 文件同步到控制机；未变化则跳过。返回 {'ok','skipped','uploaded','error'}。

    任何异常都不抛出（只读采集不应因同步问题中断调用链），失败时 playbook 会因
    找不到脚本给出明确的 fail 提示，便于定位。"""
    try:
        files = _local_files()
    except Exception as exc:
        return {'ok': False, 'skipped': False, 'uploaded': [],
                'error': 'local_scan: %s: %s' % (type(exc).__name__, exc)}
    if not files:
        return {'ok': False, 'skipped': False, 'uploaded': [],
                'error': '本地未发现任何 ops 脚本/playbook（检查 opsanalysis/ansible|scripts|powershell）'}

    fp = _fingerprint(files)
    # 进程内缓存命中：本进程已同步过且文件未变
    if not force and _SYNCED['fp'] == fp:
        return {'ok': True, 'skipped': True, 'cached': True, 'uploaded': [], 'fingerprint': fp}

    config = settings.ANSIBLE_CONFIG
    base = _remote_base()
    marker = base + '/' + _MARKER
    ssh = None
    sync_started = time.monotonic()
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=config['HOST'],
            username=config['USERNAME'],
            password=config['PASSWORD'],
            timeout=30,
        )

        # 远端指纹一致 → 跳过上传（跨进程/重启后仍省流量）
        if not force:
            try:
                _, so, _ = ssh.exec_command('cat %s 2>/dev/null' % _sh(marker), timeout=20)
                remote_fp = so.read().decode(errors='ignore').strip()
                so.channel.recv_exit_status()
                if remote_fp == fp:
                    _SYNCED['fp'] = fp
                    return {'ok': True, 'skipped': True, 'cached': False,
                            'uploaded': [], 'fingerprint': fp}
            except Exception:
                pass  # 读不到标记就继续走上传

        # 建远端目录（一次 mkdir -p 全部）
        dirs = sorted({posixpath.dirname(r) for _a, r, _rel in files})
        if dirs:
            mkdir_cmd = ' && '.join('mkdir -p %s' % _sh(d) for d in dirs)
            _, so, se = ssh.exec_command(mkdir_cmd, timeout=30)
            rc = so.channel.recv_exit_status()
            if rc != 0:
                err = se.read().decode(errors='ignore').strip()
                _log_sync(base, error='mkdir 失败(%s): %s' % (rc, err[:300]),
                          started=sync_started)
                return {'ok': False, 'skipped': False, 'uploaded': [],
                        'error': 'mkdir 失败(%s): %s' % (rc, err[:300])}

        # SFTP 上传全部文件（小文件，全量覆盖最简单可靠）
        uploaded = []
        sftp = ssh.open_sftp()
        try:
            for ap, rpath, rel in files:
                sftp.put(ap, rpath)
                uploaded.append(rel)
        finally:
            try:
                sftp.close()
            except Exception:
                pass

        # 写指纹标记，供下次快速跳过
        try:
            _, so, _ = ssh.exec_command(
                'printf %%s %s > %s' % (_sh(fp), _sh(marker)), timeout=20)
            so.channel.recv_exit_status()
        except Exception:
            pass

        _SYNCED['fp'] = fp
        logger.info('ops 脚本已同步到控制机 %s：%d 个文件', base, len(uploaded))
        _log_sync(base, uploaded=uploaded, started=sync_started)
        return {'ok': True, 'skipped': False, 'cached': False,
                'uploaded': uploaded, 'fingerprint': fp}
    except Exception as exc:
        logger.exception('ops 同步到控制机失败')
        _log_sync(base, error='%s: %s' % (type(exc).__name__, exc),
                  started=sync_started)
        return {'ok': False, 'skipped': False, 'uploaded': [],
                'error': '%s: %s' % (type(exc).__name__, exc)}
    finally:
        if ssh is not None:
            try:
                ssh.close()
            except Exception:
                pass


# ------------------------------------------------------------------ 运行包装

def ops_run_playbook(playbook, extra_vars=None, timeout=120,
                     initiated_by='system', name='', inventory=None):
    """ops 专用 playbook 运行入口：先自动同步脚本，再显式传 script_dir/ps_dir 执行。

    inventory 为空时用 settings 的 Linux inventory（默认 hosts）；Windows 采集须显式
    传 windows_dynamic.ini（见 collectors.collect_impact_windows）。
    对上层保持与 firewall.run_playbook 相同的返回结构 {'ok','stdout','error',...}。"""
    ev = dict(extra_vars or {})

    sync = ensure_ops_synced()
    if not sync.get('ok'):
        # 不阻断：继续尝试执行，让 playbook 的"找不到脚本"fail 提示暴露真实原因
        logger.warning('ops 脚本同步失败（将继续尝试执行 %s）：%s',
                       playbook, sync.get('error'))

    # 显式指定控制机上的脚本目录，覆盖 playbook 内默认相对路径
    ev.setdefault('script_dir', remote_script_dir())
    ev.setdefault('ps_dir', remote_ps_dir())

    inv = inventory if inventory is not None else (_cfg().get('INVENTORY') or '')
    return run_playbook(
        playbook, ev, timeout=timeout, initiated_by=initiated_by,
        name=name or playbook.replace('.yml', ''),
        subdir=OPS_SUBDIR, inventory=inv,
    )


# ------------------------------------------------------------------ OS 判定辅助

def _log_exec(cmd, rc, status, stdout, stderr, started,
              module='opsanalysis', kind='', target='控制机',
              task_ref='', initiated_by='system', note=''):
    """写一条执行留痕（sysmanage.ExecLog）。

    留痕失败绝不能影响采集主流程，故整段包在 try 里；execlog.record 自身也
    不抛异常，这里是双保险（连 import 失败都要挡住）。
    """
    try:
        from sysmanage.services import execlog
        k = kind or execlog.classify(cmd)
        if k == 'probe' and rc is not None:
            # ping 收不到应答时 rc=1，那是"探测成功执行、结果是主机不可达"，
            # 不是"探测失败"。混为一谈会让日志页的失败筛选被探活噪声填满。
            status = 'success'
        execlog.record(
            command=cmd, rc=rc, status=status, stdout=stdout, stderr=stderr,
            duration_ms=int((time.monotonic() - started) * 1000),
            module=module, kind=k, target=target, initiated_by=initiated_by,
            task_ref=task_ref, note=note,
        )
    except Exception:
        logger.warning('执行留痕写入失败（忽略，不影响主流程）', exc_info=True)


def _log_sync(base, uploaded=None, error='', started=None):
    """SFTP 脚本同步的留痕（口径见 sysmanage.services.execlog.log_sync）。"""
    try:
        from sysmanage.services import execlog
        execlog.log_sync(
            target=base, uploaded=uploaded, error=error, base=base,
            module='opsanalysis',
            duration_ms=int((time.monotonic() - started) * 1000) if started else 0,
        )
    except Exception:
        logger.warning('同步留痕写入失败（忽略，不影响主流程）', exc_info=True)


def ssh_exec(cmd, timeout=30, module='', kind='', target='',
             task_ref='', initiated_by='system', note=''):
    """在控制机上执行一条命令，返回 (rc, stdout, stderr)。任何异常都不抛出。

    每次调用都写一条执行留痕。后面几个参数只影响留痕的分类与归属，留空则由
    execlog 按命令形态自动判定，既有调用点一行都不用改。

    关于"只读"红线：本函数是【传输层】，它本身不保证只读——真正保证只读的是
    opsanalysis 里所有调用它的人（只下发采集/探测命令）。serverops 模块也用它
    下发变更命令，那是另一个 app 的职责边界；两边共用这一条通道，正是为了让
    "平台往控制机发过什么"只有 ExecLog 一个答案，不会因为多了通道而出现盲区。
    """
    config = settings.ANSIBLE_CONFIG
    ssh = None
    started = time.monotonic()
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=config['HOST'], username=config['USERNAME'],
                    password=config['PASSWORD'], timeout=20)
        _, so, se = ssh.exec_command(cmd, timeout=timeout)
        out = so.read().decode(errors='ignore')
        err = se.read().decode(errors='ignore')
        rc = so.channel.recv_exit_status()
        _log_exec(cmd, rc, 'success' if rc == 0 else 'failed', out, err, started,
                  module=module or 'opsanalysis', kind=kind, target=target,
                  task_ref=task_ref, initiated_by=initiated_by, note=note)
        return rc, out, err
    except Exception as exc:
        logger.warning('控制机命令执行失败: %s (%s)', cmd[:80], exc)
        err = '%s: %s' % (type(exc).__name__, exc)
        # 归 error 而不是 failed：连不上/超时时根本没拿到退出码，
        # 报成"命令执行失败"会让人以为是命令本身写错了。
        _log_exec(cmd, None, 'error', '', err, started,
                  module=module or 'opsanalysis', kind=kind, target=target,
                  task_ref=task_ref, initiated_by=initiated_by, note=note)
        return -1, '', err
    finally:
        if ssh is not None:
            try:
                ssh.close()
            except Exception:
                pass


def _parse_inventory_hosts(stdout):
    """从 `ansible-inventory --list` 的 JSON 里收集所有主机标识（含 ansible_host 映射的 IP）。"""
    import json as _json
    hosts = set()
    try:
        doc = _json.loads(stdout)
    except (ValueError, TypeError):
        # 退化：按行抓 IP
        for m in _IP_RE.finditer(stdout or ''):
            hosts.add(m.group(0))
        return hosts
    meta = doc.get('_meta', {}).get('hostvars', {}) if isinstance(doc, dict) else {}
    for name, vars_ in meta.items():
        hosts.add(str(name))
        if isinstance(vars_, dict):
            ah = vars_.get('ansible_host')
            if ah:
                hosts.add(str(ah))
    for gname, gbody in (doc.items() if isinstance(doc, dict) else []):
        if gname == '_meta' or not isinstance(gbody, dict):
            continue
        for h in (gbody.get('hosts') or []):
            hosts.add(str(h))
    return hosts


def inventory_hosts(inventory):
    """控制机上某 inventory 文件包含的主机集合（进程内缓存）。

    两条腿走路，避免依赖单一手段：
      1) `ansible-inventory --list`（结构化，用 bash -lc 保证 PATH 里有 ansible）；
      2) 直接 `cat` inventory 原文按正则抓 IP（不依赖 ansible 是否在 PATH）。
    只要文件能被 cat 到（rc==0）就认为"读取成功"，返回集合（可能为空集）；
    两条腿都失败（文件读不到）才返回 None，表示"无法判定"。"""
    if not inventory:
        return None
    if inventory in _INV_CACHE:
        return _INV_CACHE[inventory]
    workdir = (settings.ANSIBLE_CONFIG.get('WORKDIR') or '/etc/ansible').rstrip('/')
    hosts = set()

    # 1) 结构化清单（best-effort）
    cmd = 'bash -lc %s' % _sh('cd %s && ansible-inventory -i %s --list 2>/dev/null'
                              % (_sh(workdir), _sh(inventory)))
    rc, out, _err = ssh_exec(cmd, timeout=40, kind='ansible',
                             target='inventory:%s' % inventory)
    if rc == 0 and out.strip():
        hosts |= _parse_inventory_hosts(out)

    # 2) 原文兜底：cat 出来正则抓 IP（同时用它判断文件是否可读）
    inv_path = posixpath.join(workdir, inventory)
    rc2, out2, _err2 = ssh_exec('cat %s 2>/dev/null' % _sh(inv_path), timeout=20,
                                kind='shell', target=inv_path)
    readable = (rc2 == 0)
    if readable and out2:
        for m in _IP_RE.finditer(out2):
            hosts.add(m.group(0))

    if not readable and rc != 0:
        # 文件读不到、结构化也失败 → 无法判定，不缓存（下次可重试）
        return None
    _INV_CACHE[inventory] = hosts
    return hosts


def os_type_by_inventory(ip):
    """按控制机 inventory 归属判定 OS。windows_dynamic.ini 是"哪些是 Windows"的权威清单：
      - IP 在 windows inventory 里 → windows；
      - windows inventory 能读到但该 IP 不在其中 → linux（Windows 机全部登记在此文件）；
      - windows inventory 读不到 → 退而看 linux inventory，命中则 linux，否则 None（交给 TTL/默认）。
    这是最权威的信号，因为 ansible 正是据此选择连接方式(winrm/ssh)。"""
    win = inventory_hosts(windows_inventory())
    if win is not None:
        return 'windows' if ip in win else 'linux'
    lin = inventory_hosts(linux_inventory())
    if lin is not None and ip in lin:
        return 'linux'
    return None


def ttl_os_type(ip):
    """TTL 启发式：在控制机上 ping 目标，TTL≥100 判 Windows(默认128)，0<TTL<100 判 Linux(默认64)。
    在控制机执行 ping 而非本机，因为控制机才是能直达所有 ansible 目标的网络位置。
    不可达/无 TTL 返回 None。结果按 IP 缓存。"""
    if ip in _TTL_CACHE:
        return _TTL_CACHE[ip]
    result = None
    try:
        cmd = 'ping -c 1 -W 2 %s 2>/dev/null' % _sh(ip)
        rc, out, _err = ssh_exec(cmd, timeout=15, kind='probe', target=ip)
        m = re.search(r'[Tt][Tt][Ll][=:]\s*(\d+)', out or '')
        if m:
            ttl = int(m.group(1))
            result = 'windows' if ttl >= 100 else 'linux'
    except Exception as exc:
        logger.debug('TTL 探测 %s 失败: %s', ip, exc)
        result = None
    _TTL_CACHE[ip] = result
    return result


def host_alive(ip, ttl=90, wait=2):
    """在控制机上 ping 目标，判断是否在线（用于自动发现时跳过未开机的服务器）。

    返回：True=在线；False=不在线(无 ICMP 应答，多为关机)；None=无法判定(控制机 SSH 异常)。
    无法判定时调用方应"保守执行"（照常采集），只有明确 False 才跳过，避免因 ICMP 被
    防火墙拦截而误跳过在线主机。结果按 ttl 秒缓存。"""
    now = time.time()
    hit = _ALIVE_CACHE.get(ip)
    if hit and (now - hit[0]) < ttl:
        return hit[1]
    alive = None
    try:
        # -c 1 单包，-W wait 单包超时(秒)。ping: 0=收到应答 1=无应答 2=错误
        rc, out, _err = ssh_exec(
            'ping -c 1 -W %d %s 2>/dev/null' % (int(wait), _sh(ip)),
            timeout=int(wait) + 8, kind='probe', target=ip)
        if rc == -1:
            alive = None          # ssh_exec 自身异常 → 无法判定
        elif rc == 0 and '100% packet loss' not in (out or ''):
            alive = True
        elif rc in (1, 2):
            alive = False
        else:
            alive = None
    except Exception as exc:
        logger.debug('存活探测 %s 失败: %s', ip, exc)
        alive = None
    if alive is not None:
        _ALIVE_CACHE[ip] = (now, alive)
    return alive


