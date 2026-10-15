"""运维分析——Linux 采集实现（只读）。

与 collect_impact_windows 对称：经 firewall.services.ansible_executor.run_playbook
下发 ops_impact_linux.yml 到 Ansible 控制机执行，回传单行 JSON 用 parse_host_json 解析。
Linux 采集器产出的 snapshot 结构与 Windows 完全一致，故 impact_rules 无需区分 OS。

红线：全程只读，绝不触发关机/重启/停服务等改变系统状态的操作。
"""
import logging

from firewall.services.ansible_executor import parse_host_json

from opsanalysis.services.collectors import failure_reason, os_log_days
from opsanalysis.services.sync import ops_run_playbook

logger = logging.getLogger(__name__)


def collect_impact_linux(ip: str, initiated_by: str = 'system',
                         app_log_path: str = '') -> dict:
    """采集 Linux 服务器影响分析快照；返回 {'ok':bool,'data':dict,'error':str}。

    app_log_path 非空时，采集脚本额外只读探测该日志文件的新鲜度(data.app_log)，
    供故障排查作为"应用是否在跑"的旁证。
    os_log_days 控制 data.os_logs 采集近几日操作系统事件日志（重启/OOM/服务失败/sudo/补丁等）。"""
    res = ops_run_playbook(
        'ops_impact_linux.yml', {'target_host': ip, 'app_log_path': app_log_path or '',
                                 'os_log_days': os_log_days()},
        timeout=300, initiated_by=initiated_by,
        name='ops_impact_linux',
    )
    if not res['ok']:
        reason = failure_reason(res)
        logger.warning('ops 影响采集(Linux)失败 %s: %s', ip, reason)
        return {'ok': False, 'data': {}, 'error': reason}
    data = parse_host_json(res['stdout'], ip)
    if data is None:
        logger.warning('ops 影响采集(Linux)输出解析失败 %s', ip)
        return {'ok': False, 'data': {}, 'error': '采集输出解析失败'}
    return {'ok': True, 'data': data, 'error': ''}
