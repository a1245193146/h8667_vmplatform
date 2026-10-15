"""病毒模块操作留痕服务。

红线：审计写入失败绝不向上抛异常，只记日志，避免影响主流程。
所有隔离、恢复、清理、复核操作都必须经此留痕（人员/时间/原因）。
"""
import logging

from antivirus.models import AvAuditLog

logger = logging.getLogger(__name__)


def log_action(username, action, detection=None, object_repr='', old_status='',
               new_status='', reason='', task_ref='', result='success',
               detail=''):
    """写一条 AvAuditLog；任何异常吞掉并记日志，返回 log 对象或 None。"""
    try:
        return AvAuditLog.objects.create(
            username=username or 'system',
            detection=detection,
            action=action,
            object_repr=object_repr or '',
            old_status=old_status or '',
            new_status=new_status or '',
            reason=reason or '',
            ansible_task_ref=task_ref or '',
            result=result or 'success',
            detail=detail or '',
        )
    except Exception as exc:  # 审计失败不阻断业务
        logger.exception('病毒模块审计写入失败 action=%s object=%s: %s',
                         action, object_repr, exc)
        return None
