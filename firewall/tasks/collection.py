"""采集相关 Celery 任务。

由 CELERY_BEAT_SCHEDULE 调度（见 h8667_vmplatform/settings.py）：
- firewall.tasks.collection.collect_all_hosts_task  每 30 分钟
- firewall.tasks.collection.sync_inventory_task     每日 02:00
页面"重新采集"按钮 POST 后也可异步触发 collect_host_task。
"""
import logging

from celery import shared_task

from firewall.models import FirewallHost
from firewall.services import collectors

logger = logging.getLogger(__name__)


@shared_task
def collect_host_task(host_id):
    """采集单台主机（状态/规则/连接/事件全量）。"""
    try:
        host = FirewallHost.objects.get(id=host_id)
    except FirewallHost.DoesNotExist:
        logger.warning('collect_host_task: 主机不存在 id=%s', host_id)
        return None
    logger.info('collect_host_task 开始 host=%s(%s)', host.hostname, host.ip)
    return collectors.collect_host_all(host.id)


@shared_task
def collect_all_hosts_task(kind='all'):
    """对 enabled=True 的 FirewallHost 逐个 fan-out collect_host_task；返回分发数。

    kind 预留（当前仅支持 'all'）。
    """
    host_ids = list(
        FirewallHost.objects.filter(enabled=True).values_list('id', flat=True)
    )
    for host_id in host_ids:
        collect_host_task.delay(host_id)
    logger.info('collect_all_hosts_task 分发 %d 台主机 kind=%s',
                len(host_ids), kind)
    return len(host_ids)


@shared_task
def sync_inventory_task():
    """从 Ansible inventory 同步 windows 组主机到 FirewallHost。"""
    count = collectors.sync_hosts_from_inventory()
    logger.info('sync_inventory_task 完成，同步 %d 台主机', count)
    return count
