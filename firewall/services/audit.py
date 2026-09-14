"""防火墙审计日志服务。

红线：审计写入失败绝不向上抛异常，只记日志，避免影响主流程。
"""
import logging

from firewall.models import FirewallAuditLog

logger = logging.getLogger(__name__)


def log_action(username, action, host=None, object_repr='', old=None, new=None,
               task_ref='', result='success', detail=''):
    """写一条 FirewallAuditLog；任何异常吞掉并记日志，返回 log 对象或 None。"""
    try:
        return FirewallAuditLog.objects.create(
            username=username or 'system',
            host=host,
            action=action,
            object_repr=object_repr or '',
            old_value=old,
            new_value=new,
            ansible_task_ref=task_ref or '',
            result=result or 'success',
            detail=detail or '',
        )
    except Exception as exc:  # 审计失败不阻断业务
        logger.exception('审计写入失败 action=%s object=%s: %s',
                         action, object_repr, exc)
        return None
