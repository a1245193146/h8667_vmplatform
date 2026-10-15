"""病毒事件人工复核与处置动作。

红线：
- 所有动作（确认恶意/误报/恢复/清理）必须留痕（人员、时间、原因）；
- "恢复/清理"只操作本系统留存到 UNC 的副本，绝不触碰 Defender 内部隔离目录，
  也不直接删除业务原文件——恢复是把留存副本写回原路径，清理是删除留存副本；
- 页面动作经此服务层触发 Ansible，结果回写状态并记审计。
"""
import logging

from django.utils import timezone

from firewall.services.ansible_executor import parse_host_json, run_playbook

from antivirus.models import AvDetection
from antivirus.services import audit

logger = logging.getLogger(__name__)

# 复核动作 → 目标状态
_REVIEW_STATUS = {
    'confirm': 'confirmed_malicious',
    'false_positive': 'false_positive',
}


def _set_review(detection: AvDetection, status: str, operator: str,
                reason: str):
    detection.status = status
    detection.reviewer = operator[:100]
    detection.reviewed_at = timezone.now()
    if reason:
        detection.remark = reason
    detection.save(update_fields=['status', 'reviewer', 'reviewed_at',
                                  'remark', 'updated_at'])


def mark_detection(detection_id, op, operator, reason=''):
    """人工复核：确认恶意 / 标记误报。返回 (ok, message)。"""
    detection = AvDetection.objects.get(id=detection_id)
    new_status = _REVIEW_STATUS.get(op)
    if new_status is None:
        return False, '不支持的复核操作'

    old_status = detection.status
    _set_review(detection, new_status, operator, reason)
    audit.log_action(
        operator, op, detection=detection,
        object_repr=f'病毒事件#{detection.id} {detection.threat_name}',
        old_status=old_status, new_status=new_status, reason=reason)
    label = '确认恶意' if op == 'confirm' else '标记误报'
    return True, f'已{label}'


def restore_file(detection_id, operator, reason=''):
    """恢复文件：把本系统留存的 UNC 副本写回原始路径（用于误报恢复）。

    前置：quarantine_status 必须为 preserved（确有留存副本）。
    返回 (ok, message)。
    """
    detection = AvDetection.objects.get(id=detection_id)
    if detection.quarantine_status != 'preserved' or not detection.quarantine_path:
        return False, '无可恢复的留存副本（未留存或原文件已不可得）'
    if not reason.strip():
        return False, '恢复文件必须填写原因'

    old_status = detection.status
    res = run_playbook(
        'av_restore_file.yml',
        {'target_host': detection.host.ip,
         'source_path': detection.quarantine_path,
         'dest_path': detection.original_path},
        name='av_restore_file', initiated_by=operator)

    ok = bool(res.get('ok'))
    data = parse_host_json(res['stdout'], detection.host.ip) if ok else None
    if ok and data is not None and data.get('restored') is False:
        ok = False

    if ok:
        detection.status = 'restored'
        detection.quarantine_status = 'restored'
        detection.reviewer = operator[:100]
        detection.reviewed_at = timezone.now()
        detection.remark = reason
        detection.save(update_fields=['status', 'quarantine_status', 'reviewer',
                                      'reviewed_at', 'remark', 'updated_at'])
        message = '文件已恢复到原始路径'
    else:
        message = res.get('error') or '恢复任务执行失败'

    audit.log_action(
        operator, 'restore', detection=detection,
        object_repr=f'病毒事件#{detection.id} {detection.file_name}',
        old_status=old_status,
        new_status='restored' if ok else old_status,
        reason=reason, task_ref=res.get('task_ref', ''),
        result='success' if ok else 'failed',
        detail='' if ok else message)
    return ok, message


def cleanup_file(detection_id, operator, reason=''):
    """最终清理：删除本系统留存到 UNC 的隔离副本（不动 Defender 内部目录）。

    返回 (ok, message)。
    """
    detection = AvDetection.objects.get(id=detection_id)
    if not detection.quarantine_path:
        return False, '无留存副本可清理'
    if not reason.strip():
        return False, '清理操作必须填写原因'

    old_status = detection.status
    res = run_playbook(
        'av_cleanup_file.yml',
        {'target_host': detection.host.ip,
         'path': detection.quarantine_path},
        name='av_cleanup_file', initiated_by=operator)

    ok = bool(res.get('ok'))
    data = parse_host_json(res['stdout'], detection.host.ip) if ok else None
    if ok and data is not None and data.get('cleaned') is False:
        ok = False

    if ok:
        detection.status = 'cleaned'
        detection.quarantine_status = 'cleaned'
        detection.reviewer = operator[:100]
        detection.reviewed_at = timezone.now()
        detection.remark = reason
        detection.save(update_fields=['status', 'quarantine_status', 'reviewer',
                                      'reviewed_at', 'remark', 'updated_at'])
        message = '留存副本已清理'
    else:
        message = res.get('error') or '清理任务执行失败'

    audit.log_action(
        operator, 'cleanup', detection=detection,
        object_repr=f'病毒事件#{detection.id} {detection.file_name}',
        old_status=old_status,
        new_status='cleaned' if ok else old_status,
        reason=reason, task_ref=res.get('task_ref', ''),
        result='success' if ok else 'failed',
        detail='' if ok else message)
    return ok, message
