"""病毒检测采集 Celery 任务。

由 CELERY_BEAT_SCHEDULE 调度（见 h8667_vmplatform/settings.py）：
- antivirus.tasks.collection.collect_all_hosts_task  每 30 分钟
页面"立即采集"按钮 POST 后也可异步触发 collect_host_task。

断点续采由服务层 AvCollectState 水位保证，任务本身无状态、可安全重跑。
"""
import logging

from celery import shared_task

from firewall.models import FirewallHost

from antivirus.services import collectors

logger = logging.getLogger(__name__)


@shared_task
def collect_host_task(host_id):
    """采集单台主机的 Defender 检出事件。"""
    try:
        FirewallHost.objects.get(id=host_id)
    except FirewallHost.DoesNotExist:
        logger.warning('av collect_host_task: 主机不存在 id=%s', host_id)
        return None
    return collectors.collect_host_detections(host_id)


@shared_task
def collect_all_hosts_task():
    """对采集白名单(settings.AV_COLLECT_HOST_IPS)内的主机 fan-out 采集；返回分发主机数。

    定时任务与前端"立即采集"都走这里，采集范围以白名单为唯一开关。
    """
    host_ids = collectors.get_av_collect_host_ids()
    for host_id in host_ids:
        collect_host_task.delay(host_id)
    logger.info('av collect_all_hosts_task 分发 %d 台主机(白名单)', len(host_ids))
    return len(host_ids)
