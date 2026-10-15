"""运维分析模块视图。

红线：
- 全部视图 @sso_required；触发采集/维护关联登记 → ops_admin_required（仅管理员）；
- 第一阶段一切只读，"模拟操作"只产出分析结论，绝不触发关机/重启等危险动作；
- 页面请求读库展示，耗时采集经 Celery 异步派发，提交后提示"分析中，稍后刷新"。
"""
import ipaddress
import logging
import time

from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from resize.sso_utils import get_sso_username, sso_required

from opsanalysis.models import (
    AnalysisResult, AnalysisTask, LlmAnalysisRecord, ServiceRegistry,
)
from opsanalysis.services import llm as llm_svc
from opsanalysis.utils.rbac import ops_admin_required

logger = logging.getLogger(__name__)

OP_TYPES = [('shutdown', '关机'), ('restart', '重启'), ('stop_service', '停止服务')]
OS_TYPES = [('', '自动判断'), ('windows', 'Windows'), ('linux', 'Linux')]
REG_OS_TYPES = [('windows', 'Windows'), ('linux', 'Linux'), ('unknown', '未知')]


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _result_url(task) -> str:
    """任务对应的结果页 URL（影响分析/排查页各一个）。"""
    if task.kind == 'impact':
        return reverse('ops_impact_result', kwargs={'task_id': task.id})
    if task.kind == 'troubleshoot':
        return reverse('ops_troubleshoot_result', kwargs={'task_id': task.id})
    return reverse('ops_tasks')


def _llm_context(task, result):
    """两个结果页共用的大模型面板上下文。

    只读 analysis['llm'] 与该任务的历史 LlmAnalysisRecord，绝不因为模型意见而
    改动其它采集/分析数据。历史记录用于"多次分析横向对比"，故一并给出。"""
    block = ((result.analysis or {}).get('llm') if result else None) or {}
    records = []
    if task is not None:
        records = list(task.llm_records.order_by('-id')[:10])
    return {
        'llm': block,
        'llm_records': records,
        'llm_enabled': llm_svc.enabled(),
        'llm_reason': llm_svc.disabled_reason(),
        'llm_model': llm_svc.config()['MODEL'],
    }


def _llm_stale_seconds() -> int:
    """running 标记多久算"陈旧"（worker 被杀时会留下）。

    分批模式一次点击最多 MAX_BATCHES+1 次模型调用，每次都可能是完整 TIMEOUT，
    所以阈值必须按批数放大，否则正常跑长分析时会被人误判为卡死而重复触发。"""
    cfg = llm_svc.config()
    return (cfg['MAX_BATCHES'] + 1) * cfg['TIMEOUT'] + 60


# ---------------------------------------------------------------- 首页

@sso_required
def index(request):
    """运维分析首页：两个功能入口 + 关联登记/任务概览。"""
    return render(request, 'opsanalysis/index.html', {
        'service_total': ServiceRegistry.objects.count(),
        'service_confirmed': ServiceRegistry.objects.filter(status='confirmed').count(),
        'service_candidate': ServiceRegistry.objects.filter(status='candidate').count(),
        'task_total': AnalysisTask.objects.count(),
    })


# ---------------------------------------------------------------- 影响分析

@sso_required
def impact_form(request):
    """影响分析入口：输入服务器 IP + 选择模拟操作类型。"""
    return render(request, 'opsanalysis/impact_form.html', {
        'op_types': OP_TYPES,
        'os_types': OS_TYPES,
        'prefill_ip': request.GET.get('ip', ''),
    })


@sso_required
@ops_admin_required
@require_POST
def impact_run(request):
    """创建影响分析任务并异步派发采集；仅管理员可触发（会向目标机下发只读采集）。"""
    ip = (request.POST.get('ip') or '').strip()
    op_type = request.POST.get('op_type') or 'shutdown'
    os_type = request.POST.get('os_type') or ''

    if not _valid_ip(ip):
        messages.error(request, '请输入合法的服务器 IP。')
        return redirect('ops_impact_form')
    if op_type not in dict(OP_TYPES):
        op_type = 'shutdown'

    task = AnalysisTask.objects.create(
        kind='impact',
        target=ip,
        params={'op_type': op_type, 'os_type': os_type},
        status='pending',
        initiated_by=get_sso_username(request) or 'system',
    )

    from opsanalysis.tasks.analysis import run_impact_task
    run_impact_task.delay(task.id)

    messages.success(request, '分析任务已提交，正在采集（只读），稍候自动刷新结果。')
    return redirect('ops_impact_result', task_id=task.id)


@sso_required
def impact_result(request, task_id):
    """影响分析结果页：任务进行中则提示刷新；成功则展示技术/业务影响与风险。"""
    task = get_object_or_404(AnalysisTask, id=task_id, kind='impact')
    result = AnalysisResult.objects.filter(task=task).first()
    return render(request, 'opsanalysis/impact_result.html', {
        'task': task,
        'result': result,
        'analysis': (result.analysis if result else None),
        'op_types': OP_TYPES,
        **_llm_context(task, result),
    })


@sso_required
def api_impact_result(request, task_id):
    """轮询任务状态与结果（供结果页自动刷新用）。"""
    task = get_object_or_404(AnalysisTask, id=task_id, kind='impact')
    result = AnalysisResult.objects.filter(task=task).first()
    payload = {
        'status': task.status,
        'error': task.error,
        'finished': task.status in ('success', 'failed'),
    }
    if result:
        payload['analysis'] = result.analysis
    return JsonResponse(payload)


# ---------------------------------------------------------------- 任务列表

@sso_required
def tasks(request):
    """分析任务列表。"""
    qs = AnalysisTask.objects.select_related('host', 'service').order_by('-id')
    kind = request.GET.get('kind', '')
    if kind:
        qs = qs.filter(kind=kind)
    return render(request, 'opsanalysis/tasks.html', {
        'tasks': qs[:200],
        'kind': kind,
    })


# ---------------------------------------------------------------- 服务关联登记

def _split_lines(text):
    """把 textarea/输入里以逗号或换行分隔的项拆成去重去空的列表。"""
    out = []
    for chunk in (text or '').replace(',', '\n').replace('，', '\n').split('\n'):
        v = chunk.strip()
        if v and v not in out:
            out.append(v)
    return out


def _integration(s):
    """统计一条登记记录集成了几个发现来源：nginx / supervisor / jenkins / git。
    返回 (命中数, [中文标签...])，供列表排序与徽章展示。"""
    sources = []
    if (s.domains or s.nginx_access_log or s.nginx_error_log):
        sources.append('Nginx')
    if s.supervisor_program:
        sources.append('Supervisor')
    if s.jenkins_job:
        sources.append('Jenkins')
    if s.git_project:
        sources.append('Git')
    return len(sources), sources


@sso_required
def services(request):
    """服务关联登记列表：按状态筛选 + 关键字搜索；顶部可触发只读自动发现。

    排序按"集成度"降序：nginx / supervisor / jenkins / git 四个来源命中越多越靠前
    （四者齐全排最前），同分再按 状态、统一名。集成来源以徽章直观展示，便于阅读。"""
    qs = ServiceRegistry.objects.all()
    status = request.GET.get('status', '')
    q = (request.GET.get('q', '') or '').strip()
    if status in ('candidate', 'confirmed'):
        qs = qs.filter(status=status)
    if q:
        from django.db.models import Q
        qs = qs.filter(
            Q(canonical_name__icontains=q) | Q(jenkins_job__icontains=q) |
            Q(supervisor_program__icontains=q) | Q(git_project__icontains=q) |
            Q(aliases__icontains=q) | Q(domains__icontains=q) |
            Q(server_ips__icontains=q)
        )
    rows = list(qs)
    for s in rows:
        score, sources = _integration(s)
        s.integration_score = score
        s.integration_sources = sources
    rows.sort(key=lambda s: (-s.integration_score,
                             0 if s.status == 'candidate' else 1,
                             s.canonical_name or ''))
    page = Paginator(rows, 30).get_page(request.GET.get('page'))
    return render(request, 'opsanalysis/services.html', {
        'page_obj': page,
        'services': page.object_list,
        'status': status,
        'q': q,
        'candidate_count': ServiceRegistry.objects.filter(status='candidate').count(),
        'confirmed_count': ServiceRegistry.objects.filter(status='confirmed').count(),
    })


@sso_required
def service_detail(request, pk):
    """服务关联登记详情/编辑页。"""
    svc = get_object_or_404(ServiceRegistry, pk=pk)
    return render(request, 'opsanalysis/service_detail.html', {
        'svc': svc,
        'os_types': REG_OS_TYPES,
        'aliases_text': '\n'.join(svc.aliases or []),
        'domains_text': '\n'.join(svc.domains or []),
        'server_ips_text': '\n'.join(str(x) for x in (svc.server_ips or [])),
        'related_tasks': svc.analysis_tasks.order_by('-id')[:20],
    })


@sso_required
@ops_admin_required
@require_POST
def service_update(request, pk):
    """保存人工维护的关联登记（统一名/别名/域名/IP/端口/日志路径/备注/状态）。"""
    svc = get_object_or_404(ServiceRegistry, pk=pk)
    canonical = (request.POST.get('canonical_name') or '').strip()
    if not canonical:
        messages.error(request, '应用统一名不能为空。')
        return redirect('ops_service_detail', pk=svc.pk)
    # 唯一性校验（排除自身）
    if ServiceRegistry.objects.filter(canonical_name=canonical).exclude(pk=svc.pk).exists():
        messages.error(request, f'应用统一名"{canonical}"已被其它记录占用，请换一个。')
        return redirect('ops_service_detail', pk=svc.pk)

    svc.canonical_name = canonical[:128]
    svc.aliases = _split_lines(request.POST.get('aliases_text'))
    svc.domains = _split_lines(request.POST.get('domains_text'))
    svc.server_ips = _split_lines(request.POST.get('server_ips_text'))
    os_type = request.POST.get('os_type') or 'unknown'
    svc.os_type = os_type if os_type in dict(REG_OS_TYPES) else 'unknown'
    port_raw = (request.POST.get('port') or '').strip()
    svc.port = int(port_raw) if port_raw.isdigit() and 1 <= int(port_raw) <= 65535 else None
    svc.supervisor_program = (request.POST.get('supervisor_program') or '').strip()[:255]
    svc.jenkins_job = (request.POST.get('jenkins_job') or '').strip()[:255]
    svc.git_project = (request.POST.get('git_project') or '').strip()[:255]
    svc.app_log_path = (request.POST.get('app_log_path') or '').strip()[:500]
    svc.nginx_access_log = (request.POST.get('nginx_access_log') or '').strip()[:500]
    svc.nginx_error_log = (request.POST.get('nginx_error_log') or '').strip()[:500]
    svc.remark = (request.POST.get('remark') or '').strip()
    status = request.POST.get('status') or svc.status
    svc.status = status if status in ('candidate', 'confirmed') else svc.status
    # 人工编辑后来源标记为 manual（表示已人工介入）
    svc.source = 'manual'
    svc.save()
    messages.success(request, '已保存关联登记。')
    return redirect('ops_service_detail', pk=svc.pk)


@sso_required
@ops_admin_required
@require_POST
def service_confirm(request, pk):
    """把候选关联标记为已确认（人工背书）。"""
    svc = get_object_or_404(ServiceRegistry, pk=pk)
    svc.status = 'confirmed'
    svc.save(update_fields=['status', 'updated_at'])
    messages.success(request, f'已将"{svc.canonical_name}"标记为已确认。')
    nxt = request.POST.get('next') or ''
    if nxt.startswith('/'):
        return redirect(nxt)
    return redirect('ops_service_detail', pk=svc.pk)


@sso_required
@ops_admin_required
@require_POST
def service_delete(request, pk):
    """删除一条（多为误报的候选）关联登记。"""
    svc = get_object_or_404(ServiceRegistry, pk=pk)
    name = svc.canonical_name
    svc.delete()
    messages.success(request, f'已删除关联登记"{name}"。')
    return redirect('ops_services')


@sso_required
@ops_admin_required
@require_POST
def discover_run(request):
    """手动触发一次只读自动发现（异步）。完成后刷新列表查看新增/更新的候选。"""
    from opsanalysis.tasks.discovery import run_discover_task
    run_discover_task.delay(initiated_by=get_sso_username(request) or 'system')
    messages.success(request, '自动发现任务已提交（全程只读），稍后刷新本页查看新增候选。')
    return redirect('ops_services')


# ---------------------------------------------------------------- 服务故障辅助排查

WINDOW_CHOICES = [(15, '近15分钟'), (30, '近30分钟'), (60, '近1小时'), (180, '近3小时')]


@sso_required
def troubleshoot_form(request):
    """排查入口：选择一个已登记服务（关联域名/IP/端口/日志/job）+ 时间窗口。"""
    services = ServiceRegistry.objects.all().order_by('status', 'canonical_name')
    preselect = request.GET.get('service', '')
    return render(request, 'opsanalysis/troubleshoot_form.html', {
        'services': services,
        'window_choices': WINDOW_CHOICES,
        'preselect': preselect,
    })


@sso_required
@ops_admin_required
@require_POST
def troubleshoot_run(request):
    """创建排查任务并异步派发（只读采集多源信号）。"""
    service_id = (request.POST.get('service_id') or '').strip()
    window_raw = (request.POST.get('window_min') or '30').strip()
    window_min = int(window_raw) if window_raw.isdigit() else 30
    if window_min not in dict(WINDOW_CHOICES):
        window_min = 30

    svc = None
    if service_id and service_id.isdigit():
        svc = ServiceRegistry.objects.filter(id=int(service_id)).first()
    if svc is None:
        messages.error(request, '请选择一个已登记的服务进行排查。')
        return redirect('ops_troubleshoot_form')

    task = AnalysisTask.objects.create(
        kind='troubleshoot',
        target=svc.canonical_name,
        service=svc,
        params={'service_id': svc.id, 'window_min': window_min},
        status='pending',
        initiated_by=get_sso_username(request) or 'system',
    )
    from opsanalysis.tasks.analysis import run_troubleshoot_task
    run_troubleshoot_task.delay(task.id)
    messages.success(request, '排查任务已提交（全程只读采集），稍候自动刷新结果。')
    return redirect('ops_troubleshoot_result', task_id=task.id)


@sso_required
def troubleshoot_result(request, task_id):
    """排查结果页：进行中提示刷新；成功展示时间线（严格四分类）。"""
    task = get_object_or_404(AnalysisTask, id=task_id, kind='troubleshoot')
    result = AnalysisResult.objects.filter(task=task).first()
    return render(request, 'opsanalysis/troubleshoot_result.html', {
        'task': task,
        'result': result,
        'analysis': (result.analysis if result else None),
        'timeline_events': task.timeline_events.order_by('ts') if result else [],
        **_llm_context(task, result),
    })


@sso_required
def api_troubleshoot_result(request, task_id):
    """轮询排查任务状态。"""
    task = get_object_or_404(AnalysisTask, id=task_id, kind='troubleshoot')
    payload = {
        'status': task.status,
        'error': task.error,
        'finished': task.status in ('success', 'failed'),
    }
    return JsonResponse(payload)


# ---------------------------------------------------------------- 大模型辅助分析

@sso_required
@ops_admin_required
@require_POST
def llm_run(request, task_id):
    """手动触发一次大模型辅助分析（异步）。

    只对"已成功产出分析结果"的任务生效；模型只读证据、只写 analysis['llm']，
    不改动任何采集数据，也不具备任何执行能力。"""
    task = get_object_or_404(AnalysisTask, id=task_id)
    back = _result_url(task)
    result = AnalysisResult.objects.filter(task=task).first()
    if result is None:
        messages.error(request, '该任务尚无采集结果，请先完成一次分析再调用模型。')
        return redirect(back)
    if task.status != 'success':
        messages.error(request, '任务未成功完成（当前状态：%s），无法调用模型辅助分析。' % task.status)
        return redirect(back)
    if not llm_svc.enabled():
        messages.error(request, llm_svc.disabled_reason() or '未启用大模型辅助分析。')
        return redirect(back)

    cur = (result.analysis or {}).get('llm') or {}
    if cur.get('status') == 'running':
        # worker 中途被杀会留下 running 标记；超过"批数×超时+60s"视为陈旧，允许重新触发，
        # 否则按钮会被永久锁死。
        stale_after = _llm_stale_seconds()
        try:
            waited = time.time() - float(cur.get('started_epoch') or 0)
        except (TypeError, ValueError):
            waited = stale_after + 1
        if waited < stale_after:
            messages.info(request, '模型分析正在进行中（已等待 %d 秒，分批分析可能需要数分钟），'
                                   '请稍候刷新页面。' % int(waited))
            return redirect(back)

    from opsanalysis.tasks.llm import run_llm_analysis
    run_llm_analysis.delay(task.id, get_sso_username(request) or 'system')
    messages.success(request, '已提交大模型辅助分析（模型仅给参考意见，不作为结论），页面会自动刷新。')
    return redirect(back)


@sso_required
def api_llm_result(request, task_id):
    """轮询大模型分析状态/结果（结果页按钮点击后自动刷新用）。"""
    task = get_object_or_404(AnalysisTask, id=task_id)
    result = AnalysisResult.objects.filter(task=task).first()
    block = ((result.analysis or {}).get('llm') if result else None) or {}
    status = block.get('status') or 'none'
    return JsonResponse({
        'enabled': llm_svc.enabled(),
        'status': status,
        'finished': status in ('success', 'failed', 'disabled'),
        'text': block.get('text') or '',
        'error': block.get('error') or '',
        'model': block.get('model') or '',
        'latency_ms': block.get('latency_ms') or 0,
        'requested_by': block.get('requested_by') or '',
        'requested_at': block.get('requested_at') or '',
        'finished_at': block.get('finished_at') or '',
        'evidence_chars': block.get('evidence_chars') or 0,
        'evidence_sections': block.get('evidence_sections') or [],
        'evidence_dropped': block.get('evidence_dropped') or [],
        'batch_count': block.get('batch_count') or 0,
        'batches': block.get('batches') or [],
        'prompt_version': block.get('prompt_version') or '',
        'record_id': block.get('record_id'),
    })


@sso_required
def llm_record_detail(request, pk):
    """一次大模型分析的完整留痕：当时送进去的证据全文 + 每批输出 + 最终意见。

    存在的意义是"可复用"：事后回看模型当时到底看到了什么、分批各说了什么，
    才能判断结论可不可信，也才能拿历史意见做更深层次的对比分析。"""
    rec = get_object_or_404(LlmAnalysisRecord.objects.select_related('task'), pk=pk)
    return render(request, 'opsanalysis/llm_record.html', {
        'rec': rec,
        'task': rec.task,
        'back_url': _result_url(rec.task),
    })


@sso_required
@ops_admin_required
@require_POST
def llm_ping(request):
    """测试模型连通性（同步）。

    管理员手动点按钮才调用。超时 60s：请求体不带 max_tokens（带了会让思考型模型
    回空内容），35B 模型首答可能十几秒，10s 会把"其实是通的"误报成超时。
    最坏情况占住一个 web worker 60 秒，仅此一个管理员按钮，可接受。"""
    r = llm_svc.ping(timeout=60)
    return JsonResponse({
        'ok': bool(r.get('ok')),
        'error': r.get('error') or '',
        'model': r.get('model') or '',
        'latency_ms': r.get('latency_ms') or 0,
        'base_url': r.get('base_url') or llm_svc.config()['BASE_URL'],
        'reply': (r.get('text') or '')[:50],
    })
