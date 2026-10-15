"""firewall/antivirus 的 playbook 与 PowerShell 脚本自动同步到 Ansible 控制机。

背景：firewall/antivirus 模块的 playbook 与目标端 ps1 必须存在于控制机(10.2.20.226)上，
ansible 的 win_copy 才能把 ps1 推到目标机。历史上靠人工把 firewall/ansible、
firewall/powershell 拷到控制机，目录一放错就报
`ERROR! the playbook: ... could not be found` 或"控制器上找不到脚本"。

这里在每次执行 firewall 类 playbook 前，用 SFTP 把本地两类文件按"内容指纹"增量同步到
控制机的固定目录（相对 WORKDIR=/etc/ansible）：

    本地(应用服务器)                     远端(控制机)
    firewall/ansible/*.yml      →   {PLAYBOOK_SUBDIR}/*.yml           (playbooks/firewall/)
    firewall/powershell/*.ps1   →   {POWERSHELL_SUBDIR}/*.ps1         (playbooks/powershell/)

POWERSHELL_SUBDIR 默认取 PLAYBOOK_SUBDIR 的上一级 + /powershell，因为所有 firewall
playbook 用 `playbook_dir ~ '/../powershell'` 定位 ps1（playbooks/firewall/../powershell
= playbooks/powershell）。

红线：只同步 firewall 自己的这两类文件到约定目录，绝不触碰控制机上的 inventory、凭据、
opsanalysis 或其它模块的 playbook；SFTP 失败不抛出，只告警并让 playbook 自行报错定位。
本模块自成一体（只用 paramiko + settings），不 import ansible_executor，避免循环依赖；
执行留痕走 sysmanage.services.execlog（懒加载 import，与本模块无依赖关系）。
"""
import hashlib
import logging
import os
import posixpath
import time

import paramiko
from django.conf import settings

logger = logging.getLogger(__name__)


def _log_sync(base, uploaded=None, error='', started=None):
    """SFTP 同步留痕。懒加载 import：本模块要保持"只用 paramiko + settings"，
    不引入 ansible_executor（会循环依赖）；execlog 与 firewall 无依赖关系，安全。
    留痕失败只 warning，绝不影响同步结果与调用链。"""
    try:
        from sysmanage.services import execlog
        execlog.log_sync(
            target=base, uploaded=uploaded, error=error, base=base,
            module='firewall',
            duration_ms=int((time.monotonic() - started) * 1000) if started else 0,
        )
    except Exception:
        logger.warning('同步留痕写入失败（忽略，不影响主流程）', exc_info=True)

# firewall 包目录（services/ 的上一级）
_PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_MARKER = '.fw_sync_sha'

# 进程内缓存：上次成功同步的本地指纹（celery -P solo 单进程可跨任务复用）
_SYNCED = {'fp': None}


def _ansible_cfg():
    return getattr(settings, 'ANSIBLE_CONFIG', {}) or {}


def playbook_subdir():
    """firewall playbook 在控制机上的子目录（相对 WORKDIR），供 run_playbook 拼路径。"""
    return (_ansible_cfg().get('PLAYBOOK_SUBDIR') or 'playbooks/firewall').strip('/')


def powershell_subdir():
    """firewall ps1 在控制机上的子目录（相对 WORKDIR）。

    默认 = playbook_subdir 的上一级 + /powershell，匹配 playbook 内
    `playbook_dir ~ '/../powershell'` 的默认相对定位。"""
    env = os.environ.get('VMP_ANSIBLE_POWERSHELL_SUBDIR', '')
    if env:
        return env.strip('/')
    pb = playbook_subdir()
    parent = posixpath.dirname(pb)          # playbooks/firewall → playbooks
    return posixpath.join(parent, 'powershell') if parent else 'powershell'


def _sh(s):
    """把字符串安全放进单引号（同 ansible_executor 的转义规则）。"""
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


def _sha_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _sources():
    """[(本地目录, 远端子目录(相对WORKDIR), 扩展名)]。"""
    return [
        (os.path.join(_PKG_DIR, 'ansible'), playbook_subdir(), '.yml'),
        (os.path.join(_PKG_DIR, 'powershell'), powershell_subdir(), '.ps1'),
    ]


def _local_files():
    """返回 [(本地绝对路径, 远端绝对路径, 展示用相对名)]，按名字排序保证指纹稳定。"""
    workdir = (_ansible_cfg().get('WORKDIR') or '/etc/ansible').rstrip('/')
    out = []
    for localdir, sub, ext in _sources():
        if not os.path.isdir(localdir):
            continue
        for name in sorted(os.listdir(localdir)):
            if not name.endswith(ext):
                continue
            ap = os.path.join(localdir, name)
            if not os.path.isfile(ap):
                continue
            rpath = posixpath.join(workdir, sub, name)
            rel = sub + '/' + name
            out.append((ap, rpath, rel))
    return out


def _fingerprint(files):
    h = hashlib.sha256()
    for _ap, _rpath, rel in files:
        h.update(rel.encode('utf-8'))
        h.update(_sha_file(_ap).encode('utf-8'))
    return h.hexdigest()


def ensure_firewall_synced(force=False):
    """把本地 firewall/ansible、firewall/powershell 同步到控制机；未变化则跳过。

    返回 {'ok','skipped','uploaded','error'}。任何异常都不抛出（只读采集/处置不应因
    同步问题中断调用链），失败时 playbook 会因找不到文件给出明确 fail 提示便于定位。"""
    try:
        files = _local_files()
    except Exception as exc:
        return {'ok': False, 'skipped': False, 'uploaded': [],
                'error': 'local_scan: %s: %s' % (type(exc).__name__, exc)}
    if not files:
        return {'ok': False, 'skipped': False, 'uploaded': [],
                'error': '本地未发现 firewall/ansible|powershell 文件，跳过同步'}

    fp = _fingerprint(files)
    if not force and _SYNCED['fp'] == fp:
        return {'ok': True, 'skipped': True, 'cached': True, 'uploaded': [], 'fingerprint': fp}

    config = _ansible_cfg()
    workdir = (config.get('WORKDIR') or '/etc/ansible').rstrip('/')
    marker = posixpath.join(workdir, playbook_subdir(), _MARKER)
    base = posixpath.join(workdir, playbook_subdir())
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

        # 写指纹标记，供下次快速跳过（写不进也不影响本次结果）
        try:
            _, so, _ = ssh.exec_command(
                'printf %%s %s > %s' % (_sh(fp), _sh(marker)), timeout=20)
            so.channel.recv_exit_status()
        except Exception:
            pass

        _SYNCED['fp'] = fp
        logger.info('firewall 脚本已同步到控制机 %s：%d 个文件', workdir, len(uploaded))
        _log_sync(base, uploaded=uploaded, started=sync_started)
        return {'ok': True, 'skipped': False, 'cached': False,
                'uploaded': uploaded, 'fingerprint': fp}
    except Exception as exc:
        logger.exception('firewall 同步到控制机失败')
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
