"""运维分析——采集编排（只读）。

统一经 firewall.services.ansible_executor.run_playbook 下发到 Ansible 控制机执行，
按目标操作系统路由到 Windows / Linux 采集 playbook；回传单行 JSON 用 parse_host_json 解析。

红线：本模块一切采集均为只读，绝不触发关机/重启/停服务等改变系统状态的操作。
"""
import logging
import re

from django.conf import settings
from django.utils import timezone

from firewall.models import FirewallHost
from firewall.services.ansible_executor import parse_host_json

from opsanalysis.services.sync import (
    OPS_SUBDIR, ops_run_playbook, os_type_by_inventory, ttl_os_type,
    windows_inventory,
)

logger = logging.getLogger(__name__)

# ops playbook 位于控制机 /etc/ansible/playbooks/opsanalysis/（OPS_SUBDIR 由 sync 统一定义）；
# 脚本在运行前由 sync.ensure_ops_synced 自动 SFTP 同步，无需人工复制。
__all__ = ['OPS_SUBDIR', 'detect_os_type', 'collect_impact_windows',
           'collect_impact_linux', 'collect_impact_snapshot', 'now_iso',
           'failure_reason', 'os_log_days']

# OS 判定结果缓存（进程内），避免对同一 IP 反复查库/SSH/ping
_OS_CACHE = {}


def os_log_days() -> int:
    """采集"近 N 日操作系统日志"的天数（settings 可调，最小 1，异常回退 1）。"""
    cfg = getattr(settings, 'OPS_DISCOVERY_CONFIG', {}) or {}
    try:
        return max(1, int(cfg.get('OS_LOG_DAYS', 1)))
    except (TypeError, ValueError):
        return 1


def failure_reason(res: dict) -> str:
    """从 run_playbook 的失败结果里给出**准确**的失败原因。

    注意：ansible 的 PLAY RECAP 行永远包含 `unreachable=0`，所以绝不能用
    `'unreachable' in blob` 判断（会对任何失败都误报"主机不可达"）。这里改为
    看 `unreachable=<非0>`，并区分"没匹配到 inventory 主机"等常见真因。"""
    blob = ((res.get('stdout', '') or '') + '\n' + (res.get('error', '') or '')).lower()
    if re.search(r'unreachable=[1-9]', blob):
        return ('主机不可达(unreachable)：WinRM/SSH 连接失败——检查目标是否开机、'
                'Windows 的 5985/5986(WinRM) 或 Linux 的 22(SSH) 是否放通、inventory 里的连接变量与凭据')
    if ('no hosts matched' in blob or 'could not match supplied host pattern' in blob
            or 'skipping: no hosts' in blob):
        return ('目标未匹配到 inventory 主机：确认该 IP/主机名已在对应 inventory 中登记'
                '（Windows 走 windows_dynamic.ini，Linux 走 hosts）')
    err = (res.get('error') or '').strip()
    return err or '执行失败'



def detect_os_type(ip: str, explicit: str = '') -> str:
    """判定目标操作系统，按可靠性分层，结果缓存：
      1) 显式指定；
      2) 控制机 inventory 归属——最权威：windows_dynamic.ini 是"哪些是 Windows"的完整清单，
         命中即 windows，能读到该清单但不在其中即 linux（ansible 正是据此选 winrm/ssh）；
      3) 资产表 FirewallHost 的 ansible_group/os_version 关键字；
      4) 控制机 ping 的 TTL 启发式（Windows 默认 128、Linux 默认 64）；
      5) 都拿不到时默认 linux（Windows 机已全部登记在 windows_dynamic.ini，漏判的更可能是 Linux）。
    """
    if explicit in ('windows', 'linux'):
        return explicit
    if ip in _OS_CACHE:
        return _OS_CACHE[ip]

    ost = os_type_by_inventory(ip)

    if ost is None:
        host = FirewallHost.objects.filter(ip=ip).first()
        if host:
            blob = f'{host.ansible_group or ""} {host.os_version or ""}'.lower()
            if any(k in blob for k in ('linux', 'centos', 'ubuntu', 'rhel', 'debian')):
                ost = 'linux'
            elif 'windows' in blob:
                ost = 'windows'

    if ost is None:
        ost = ttl_os_type(ip)

    if ost is None:
        ost = 'linux'

    _OS_CACHE[ip] = ost
    return ost


def _resolve_host(ip: str):
    return FirewallHost.objects.filter(ip=ip).first()


def collect_impact_windows(ip: str, initiated_by: str = 'system',
                           app_log_path: str = '') -> dict:
    """采集 Windows 服务器影响分析快照；返回 {'ok':bool,'data':dict,'error':str}。

    Windows 机全部登记在 windows_dynamic.ini(winrm)，故只用该 inventory。
    不再回退到 hosts：hosts 是 Linux 清单，回退只会产生 'no hosts matched' 的
    误导性错误（真正的失败原因会被这条兜底错误盖掉，排查时极易看错）。
    app_log_path 非空时，采集脚本额外只读探测该日志文件的新鲜度(data.app_log)，
    供故障排查作为"应用是否在跑"的旁证。
    os_log_days 控制 data.os_logs 采集近几日操作系统事件日志（重启/服务失败/补丁/崩溃等）。"""
    inv = windows_inventory()
    res = ops_run_playbook(
        'ops_impact_windows.yml', {'target_host': ip, 'app_log_path': app_log_path or '',
                                   'os_log_days': os_log_days()},
        # 300s：除进程/端口枚举外还要跑 5 类 Get-WinEvent 查询，留足余量避免超时误判为不可达
        timeout=300, initiated_by=initiated_by,
        name='ops_impact_windows', inventory=inv,
    )
    if not res['ok']:
        reason = failure_reason(res)
        logger.warning('ops 影响采集(Windows)失败 %s [inventory=%s]: %s', ip, inv, reason)
        return {'ok': False, 'data': {}, 'error': reason}
    data = parse_host_json(res['stdout'], ip)
    if data is None:
        reason = '采集输出解析失败（inventory=%s 未匹配到主机或脚本无输出）' % inv
        logger.warning('ops 影响采集(Windows)输出解析失败 %s [inventory=%s]', ip, inv)
        return {'ok': False, 'data': {}, 'error': reason}
    return {'ok': True, 'data': data, 'error': ''}


def collect_impact_linux(ip: str, initiated_by: str = 'system',
                         app_log_path: str = '') -> dict:
    """采集 Linux 服务器影响分析快照（P3 实现）。"""
    from opsanalysis.services import collectors_linux
    return collectors_linux.collect_impact_linux(ip, initiated_by=initiated_by,
                                                 app_log_path=app_log_path)


def collect_impact_snapshot(ip: str, os_type: str = '', initiated_by: str = 'system',
                            app_log_path: str = '') -> dict:
    """按 OS 路由采集影响分析快照。返回 {'ok','data','error','os_type','host_id'}。"""
    ost = detect_os_type(ip, os_type)
    if ost == 'linux':
        r = collect_impact_linux(ip, initiated_by=initiated_by, app_log_path=app_log_path)
    else:
        r = collect_impact_windows(ip, initiated_by=initiated_by, app_log_path=app_log_path)
    host = _resolve_host(ip)
    r['os_type'] = ost
    r['host_id'] = host.id if host else None
    return r


def now_iso() -> str:
    return timezone.now().isoformat()
