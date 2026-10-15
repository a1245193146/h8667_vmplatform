"""运维分析——大模型辅助分析 Celery 任务。

手动按钮触发（用户明确要求"手动"，不做自动调用）：把已落库的分析结果打包成证据，
交给内网模型生成一段辅助意见；证据超过单次预算时分批作答再汇总（见 services.llm）。

红线：
- 只写 analysis['llm'] 这一个键，原有 snapshot/analysis 内容一字不改（模型意见绝不
  覆盖或隐藏真实采集数据）；
- 模型输出只作为"推测/建议"参考展示，不进 facts/correlations 时间线；
- 每次调用都在 LlmAnalysisRecord 留全量痕迹（证据 + 各批输出 + 最终意见），供事后
  复用与更深层次分析；analysis['llm'] 只放精简摘要 + record_id；
- 模型不可用时降级为 status=failed/disabled + 可读原因，页面照常显示规则分析结果；
- 任务本身对目标服务器零动作（纯 HTTP 问答），可安全重跑。

注意：分批模式下一次点击最多产生 MAX_BATCHES+1 次模型调用，Celery -P solo 会独占
worker 一个槽位直到全部结束（默认最长约 (3+1)*TIMEOUT），故按钮侧有"进行中"防重入。
"""
import logging
import time

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


def _mark(result, analysis, patch, replace=False):
    """更新 analysis['llm'] 后落库；其余键原样保留。

    replace=True 时整体替换 llm 块——避免上一次运行残留的键（如旧 record_id、
    旧批次明细）在本次失败路径里被误当成当前状态。
    """
    analysis = dict(analysis or {})
    if replace:
        analysis['llm'] = dict(patch)
    else:
        llm_block = dict(analysis.get('llm') or {})
        llm_block.update(patch)
        analysis['llm'] = llm_block
    result.analysis = analysis
    result.save(update_fields=['analysis'])
    return analysis


@shared_task
def run_llm_analysis(task_id, requested_by=''):
    """对一次已完成的分析任务追加"大模型辅助分析"，并把全过程留痕入库。"""
    from opsanalysis.models import AnalysisResult, AnalysisTask, LlmAnalysisRecord
    from opsanalysis.services import llm

    try:
        task = AnalysisTask.objects.get(id=task_id)
    except AnalysisTask.DoesNotExist:
        logger.warning('run_llm_analysis: 任务不存在 id=%s', task_id)
        return {'ok': False, 'error': '任务不存在'}

    result = AnalysisResult.objects.filter(task=task).first()
    if result is None:
        return {'ok': False, 'error': '该任务尚无采集结果，请先完成一次分析'}

    scope = 'impact' if task.kind == 'impact' else 'troubleshoot'
    analysis = dict(result.analysis or {})
    who = requested_by or task.initiated_by or ''

    if not llm.enabled():
        _mark(result, analysis, {
            'status': 'disabled', 'scope': scope, 'text': '',
            'error': llm.disabled_reason() or '未启用大模型辅助分析',
            'requested_by': who, 'requested_at': llm.now_text(),
            'finished_at': llm.now_text(), 'started_epoch': 0,
        }, replace=True)
        return {'ok': False, 'error': '未启用大模型辅助分析'}

    cfg = llm.config()
    rec = LlmAnalysisRecord.objects.create(
        task=task, scope=scope, status='running', model=cfg['MODEL'],
        temperature=cfg['TEMPERATURE'], prompt_version=llm.PROMPT_VERSION,
        base_url=cfg['BASE_URL'], requested_by=who, requested_at=timezone.now())

    _mark(result, analysis, {
        'status': 'running', 'scope': scope, 'text': '', 'error': '',
        'model': cfg['MODEL'], 'temperature': cfg['TEMPERATURE'],
        'prompt_version': llm.PROMPT_VERSION, 'base_url': cfg['BASE_URL'],
        'requested_by': who, 'requested_at': llm.now_text(), 'finished_at': '',
        'record_id': rec.id, 'batch_count': 0, 'batches': [],
        'started_epoch': time.time(),
    }, replace=True)

    try:
        # 绝不把上一次的模型输出当证据喂回去（会自我强化幻觉）
        evidence_src = {k: v for k, v in analysis.items() if k != 'llm'}
        out = llm.analyze(scope, evidence_src, requested_by=who)

        rec.status = out.get('status') or 'failed'
        rec.evidence = out.get('evidence_text') or ''
        rec.batches = out.get('batches') or []
        rec.output = out.get('text') or ''
        rec.error = out.get('error') or ''
        rec.prompt_chars = int(out.get('prompt_chars') or 0)
        rec.evidence_chars = int(out.get('evidence_chars') or 0)
        rec.batch_count = int(out.get('batch_count') or 0)
        rec.latency_ms = int(out.get('latency_ms') or 0)
        rec.finished_at = timezone.now()
        rec.save()

        slim = llm.slim_for_storage(out, record_id=rec.id)
        slim['started_epoch'] = 0
        _mark(result, analysis, slim, replace=True)
        logger.info('ops LLM 辅助分析完成 task=%s record=%s scope=%s status=%s 批次=%s 耗时=%sms',
                    task.id, rec.id, scope, out.get('status'),
                    out.get('batch_count'), out.get('latency_ms'))
        return {'ok': out.get('status') == 'success', 'status': out.get('status'),
                'record_id': rec.id, 'error': out.get('error') or ''}
    except Exception as exc:
        logger.exception('run_llm_analysis 异常 task=%s', task_id)
        err = '%s: %s' % (type(exc).__name__, exc)
        rec.status = 'failed'
        rec.error = err
        rec.finished_at = timezone.now()
        rec.save(update_fields=['status', 'error', 'finished_at'])
        _mark(result, analysis, {
            'status': 'failed', 'scope': scope, 'text': '', 'error': err,
            'model': cfg['MODEL'], 'requested_by': who,
            'requested_at': llm.now_text(), 'finished_at': llm.now_text(),
            'record_id': rec.id, 'started_epoch': 0,
        }, replace=True)
        return {'ok': False, 'error': err}
