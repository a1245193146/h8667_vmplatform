"""运维分析——服务关联自动发现 Celery 任务（只读）。

由 CELERY_BEAT_SCHEDULE['ops-discover-services'] 每日调度，也可从"服务关联登记"
页面点"运行自动发现"手动异步触发。任务对目标服务器全程只读，可安全重跑。
"""
import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task
def run_discover_task(initiated_by='system'):
    """执行一次全量只读发现，返回 {'ok','summary','stats','errors'}。"""
    from opsanalysis.services import discovery
    try:
        return discovery.run_discovery(initiated_by=initiated_by)
    except Exception as exc:  # 任何异常都不抛出，返回错误信息
        logger.exception('run_discover_task 异常')
        return {'ok': False, 'summary': {}, 'stats': {},
                'errors': ['%s: %s' % (type(exc).__name__, exc)]}
