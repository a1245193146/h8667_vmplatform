"""运维分析 Celery 任务。

第一阶段仅"影响分析"任务：采集(只读) → 规则分析 → 落 AnalysisResult。
任务无副作用于目标服务器，可安全重跑。页面提交后异步派发，避免阻塞 HTTP worker。
"""
import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task
def run_impact_task(task_id):
    """执行一次服务器操作影响分析任务。"""
    from opsanalysis.models import AnalysisResult, AnalysisTask
    from opsanalysis.services import collectors, impact_rules

    try:
        task = AnalysisTask.objects.get(id=task_id)
    except AnalysisTask.DoesNotExist:
        logger.warning('run_impact_task: 任务不存在 id=%s', task_id)
        return None

    task.status = 'running'
    task.save(update_fields=['status'])

    ip = task.target
    params = task.params or {}
    op_type = params.get('op_type') or 'shutdown'
    os_type = params.get('os_type') or ''

    try:
        snap = collectors.collect_impact_snapshot(
            ip, os_type=os_type, initiated_by=task.initiated_by)
        if not snap.get('ok'):
            task.status = 'failed'
            task.error = snap.get('error') or '采集失败'
            task.finished_at = timezone.now()
            task.save(update_fields=['status', 'error', 'finished_at'])
            return task.id

        # 关联到资产表主机（若存在）
        if snap.get('host_id') and task.host_id is None:
            task.host_id = snap['host_id']
            task.save(update_fields=['host'])

        analysis = impact_rules.analyze_impact(snap.get('data') or {}, op_type, ip)

        AnalysisResult.objects.update_or_create(
            task=task,
            defaults={
                'snapshot': snap.get('data') or {},
                'analysis': analysis,
                'collected_at': timezone.now(),
            },
        )
        task.status = 'success'
        task.error = ''
        task.finished_at = timezone.now()
        task.save(update_fields=['status', 'error', 'finished_at'])
        logger.info('ops 影响分析完成 task=%s ip=%s os=%s', task.id, ip, snap.get('os_type'))
        return task.id
    except Exception as exc:  # 采集/分析任何异常都不抛出，落 failed
        logger.exception('run_impact_task 异常 task=%s', task_id)
        task.status = 'failed'
        task.error = f'{type(exc).__name__}: {exc}'
        task.finished_at = timezone.now()
        task.save(update_fields=['status', 'error', 'finished_at'])
        return task.id


@shared_task
def run_troubleshoot_task(task_id):
    """执行一次服务故障辅助排查：只读采集多源信号 → 时间线 → 落 AnalysisResult/TimelineEvent。"""
    from opsanalysis.models import (
        AnalysisResult, AnalysisTask, ServiceRegistry, TimelineEvent,
    )
    from opsanalysis.services import troubleshoot

    try:
        task = AnalysisTask.objects.get(id=task_id)
    except AnalysisTask.DoesNotExist:
        logger.warning('run_troubleshoot_task: 任务不存在 id=%s', task_id)
        return None

    task.status = 'running'
    task.save(update_fields=['status'])

    params = task.params or {}
    window_min = int(params.get('window_min') or troubleshoot.DEFAULT_WINDOW_MIN)
    service_id = params.get('service_id')

    try:
        svc = None
        if service_id:
            svc = ServiceRegistry.objects.filter(id=service_id).first()
        if svc is None and task.service_id:
            svc = task.service

        gathered = troubleshoot.gather(svc, window_min=window_min,
                                       initiated_by=task.initiated_by)
        analysis = troubleshoot.analyze(gathered)

        if svc is not None and task.service_id is None:
            task.service = svc
            task.save(update_fields=['service'])

        AnalysisResult.objects.update_or_create(
            task=task,
            defaults={
                'snapshot': gathered,
                'analysis': analysis,
                'collected_at': timezone.now(),
            },
        )

        # 时间线落库（先清后写，保证可安全重跑）
        TimelineEvent.objects.filter(task=task).delete()
        rows = []
        for e in analysis.get('timeline') or []:
            rows.append(TimelineEvent(
                task=task, ts=e.get('ts'), source=e.get('source', ''),
                event_type=e.get('event_type', ''), summary=e.get('summary', ''),
                evidence=e.get('evidence') or {}, kind=e.get('kind', 'fact'),
            ))
        if rows:
            TimelineEvent.objects.bulk_create(rows)

        task.status = 'success'
        task.error = ''
        task.finished_at = timezone.now()
        task.save(update_fields=['status', 'error', 'finished_at'])
        logger.info('ops 服务排查完成 task=%s service=%s facts=%d',
                    task.id, (svc.canonical_name if svc else task.target),
                    len(analysis.get('facts') or []))
        return task.id
    except Exception as exc:
        logger.exception('run_troubleshoot_task 异常 task=%s', task_id)
        task.status = 'failed'
        task.error = f'{type(exc).__name__}: {exc}'
        task.finished_at = timezone.now()
        task.save(update_fields=['status', 'error', 'finished_at'])
        return task.id
