"""病毒事件处置 Celery 任务（留存/恢复/清理）。

这些动作会经 Ansible 在目标主机执行文件操作，耗时可达数十秒，
故一律异步派发，避免阻塞 HTTP worker（页面提交后提示"任务已提交"）。
复核标记（确认恶意/误报）是纯 DB 操作，在视图内同步完成，不走此处。
"""
import logging

from celery import shared_task

from antivirus.models import AvDetection

logger = logging.getLogger(__name__)


@shared_task
def preserve_quarantine_task(detection_id, operator):
    """把检出文件留存到 UNC 隔离目录，并写操作留痕。"""
    from antivirus.services import audit, collectors
    try:
        detection = AvDetection.objects.get(id=detection_id)
    except AvDetection.DoesNotExist:
        logger.warning('preserve_quarantine_task: 事件不存在 id=%s', detection_id)
        return None
    ok, msg = collectors.preserve_quarantine_file(detection_id, operator=operator)
    detection.refresh_from_db()
    audit.log_action(
        operator, 'preserve', detection=detection,
        object_repr=f'病毒事件#{detection.id} {detection.file_name}',
        new_status=detection.quarantine_status,
        result='success' if ok else 'failed', detail=msg)
    return ok


@shared_task
def restore_file_task(detection_id, operator, reason):
    """从 UNC 留存副本恢复文件到原始路径（服务层内部已写审计）。"""
    from antivirus.services import actions
    ok, msg = actions.restore_file(detection_id, operator, reason)
    logger.info('restore_file_task id=%s ok=%s msg=%s', detection_id, ok, msg)
    return ok


@shared_task
def cleanup_file_task(detection_id, operator, reason):
    """清理 UNC 留存副本（服务层内部已写审计）。"""
    from antivirus.services import actions
    ok, msg = actions.cleanup_file(detection_id, operator, reason)
    logger.info('cleanup_file_task id=%s ok=%s msg=%s', detection_id, ok, msg)
    return ok
