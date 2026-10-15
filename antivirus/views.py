"""病毒检测与隔离模块视图。

红线：
- 全部视图 @sso_required；留存/恢复/清理/复核 → av_admin_required（仅管理员）；
- 页面请求一律读库展示，绝不实时调 Ansible；
- 复核标记（确认恶意/误报）纯 DB 同步完成；留存/恢复/清理经 Celery 异步派发，
  避免阻塞 HTTP worker，提交后提示"任务已提交，稍后刷新查看"。
- 服务层一律函数内延迟导入，避免模块合并顺序导致视图无法加载。
"""
import logging

from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from resize.sso_utils import get_sso_username, sso_required

from firewall.models import AnsibleTaskRecord, FirewallHost

from antivirus.models import AvAuditLog, AvDetection
from antivirus.serializers import build_dashboard_data
from antivirus.utils.rbac import av_admin_required

logger = logging.getLogger(__name__)

PAGE_SIZE = 20


# ---------------------------------------------------------------- 辅助

def _paginate(request, qs):
    return Paginator(qs, PAGE_SIZE).get_page(request.GET.get('page'))


def _query_string(request):
    params = request.GET.copy()
    params.pop('page', None)
    return params.urlencode()


def _safe_next(request, default='av_detections'):
    nxt = request.POST.get('next', '')
    if nxt.startswith('/'):
        return nxt
    return default


# ---------------------------------------------------------------- 看板

@sso_required
def dashboard(request):
    """统计看板：检测总数/待复核/确认恶意/误报 + 按服务器/威胁类型/时间统计。"""
    return render(request, 'antivirus/dashboard.html', {
        'data': build_dashboard_data(),
    })


@sso_required
def api_dashboard(request):
    return JsonResponse(build_dashboard_data())


# ---------------------------------------------------------------- 事件列表 / 详情

@sso_required
def detections(request):
    qs = (AvDetection.objects.select_related('host')
          .order_by('-detected_at'))
    status = request.GET.get('status', '')
    qstatus = request.GET.get('quarantine_status', '')
    q = request.GET.get('q', '').strip()
    date_from = request.GET.get('date_from', '').strip()
    date_to = request.GET.get('date_to', '').strip()
    if status:
        qs = qs.filter(status=status)
    if qstatus:
        qs = qs.filter(quarantine_status=qstatus)
    if q:
        qs = (qs.filter(file_name__icontains=q)
              | qs.filter(original_path__icontains=q)
              | qs.filter(threat_name__icontains=q)
              | qs.filter(sha256__icontains=q)
              | qs.filter(host__hostname__icontains=q)
              | qs.filter(host__ip__icontains=q))
    if date_from:
        qs = qs.filter(detected_at__date__gte=date_from)
    if date_to:
        qs = qs.filter(detected_at__date__lte=date_to)
    return render(request, 'antivirus/detections.html', {
        'page_obj': _paginate(request, qs),
        'status_choices': AvDetection._meta.get_field('status').choices,
        'quarantine_choices': AvDetection._meta.get_field('quarantine_status').choices,
        'f_status': status,
        'f_qstatus': qstatus,
        'f_q': q,
        'f_date_from': date_from,
        'f_date_to': date_to,
        'query': _query_string(request),
    })


@sso_required
def detection_detail(request, did):
    detection = get_object_or_404(
        AvDetection.objects.select_related('host'), id=did)
    logs = detection.audit_logs.order_by('-created_at')
    return render(request, 'antivirus/detection_detail.html', {
        'detection': detection,
        'logs': logs,
    })


# ---------------------------------------------------------------- 采集

@sso_required
@require_POST
def collect_all(request):
    """触发全量采集（POST → Celery）。"""
    try:
        from antivirus.tasks.collection import collect_all_hosts_task
        collect_all_hosts_task.delay()
        messages.success(request, '病毒事件采集任务已提交，稍后请刷新查看')
    except Exception as exc:
        messages.error(request, f'采集任务提交失败：{exc}')
    return redirect(_safe_next(request, 'av_detections'))


@sso_required
@require_POST
def host_collect(request, hid):
    """触发单台主机采集（POST → Celery）。"""
    host = get_object_or_404(FirewallHost, id=hid)
    try:
        from antivirus.tasks.collection import collect_host_task
        collect_host_task.delay(host.id)
        messages.success(request, f'主机 {host.hostname} 采集任务已提交')
    except Exception as exc:
        messages.error(request, f'采集任务提交失败：{exc}')
    return redirect(_safe_next(request, 'av_detections'))


# ---------------------------------------------------------------- 留存 / 复核 / 恢复 / 清理

@av_admin_required
@require_POST
def detection_preserve(request, did):
    """留存隔离文件到 UNC（仅管理员，异步）。"""
    detection = get_object_or_404(AvDetection, id=did)
    if not detection.original_path:
        messages.error(request, '该事件无原始文件路径，无法留存')
        return redirect('av_detection_detail', did=did)
    username = get_sso_username(request)
    try:
        from antivirus.tasks.actions import preserve_quarantine_task
        preserve_quarantine_task.delay(detection.id, username)
        messages.success(request, '隔离留存任务已提交，稍后请刷新查看结果')
    except Exception as exc:
        messages.error(request, f'留存任务提交失败：{exc}')
    return redirect('av_detection_detail', did=did)


@av_admin_required
@require_POST
def detection_review(request, did, op):
    """人工复核：确认恶意 / 标记误报（仅管理员，纯 DB 同步）。"""
    detection = get_object_or_404(AvDetection, id=did)
    username = get_sso_username(request)
    reason = request.POST.get('reason', '').strip()
    try:
        from antivirus.services import actions
        ok, msg = actions.mark_detection(detection.id, op, username, reason)
    except Exception as exc:
        messages.error(request, f'复核操作异常：{exc}')
        return redirect('av_detection_detail', did=did)
    if ok:
        messages.success(request, msg)
    else:
        messages.error(request, msg)
    return redirect('av_detection_detail', did=did)


@av_admin_required
@require_POST
def detection_restore(request, did):
    """恢复文件（仅管理员，异步；必须填写原因）。"""
    detection = get_object_or_404(AvDetection, id=did)
    username = get_sso_username(request)
    reason = request.POST.get('reason', '').strip()
    if not reason:
        messages.error(request, '恢复文件必须填写原因')
        return redirect('av_detection_detail', did=did)
    try:
        from antivirus.tasks.actions import restore_file_task
        restore_file_task.delay(detection.id, username, reason)
        messages.success(request, '文件恢复任务已提交，稍后请刷新查看结果')
    except Exception as exc:
        messages.error(request, f'恢复任务提交失败：{exc}')
    return redirect('av_detection_detail', did=did)


@av_admin_required
@require_POST
def detection_cleanup(request, did):
    """最终清理留存副本（仅管理员，异步；必须填写原因）。"""
    detection = get_object_or_404(AvDetection, id=did)
    username = get_sso_username(request)
    reason = request.POST.get('reason', '').strip()
    if not reason:
        messages.error(request, '清理操作必须填写原因')
        return redirect('av_detection_detail', did=did)
    try:
        from antivirus.tasks.actions import cleanup_file_task
        cleanup_file_task.delay(detection.id, username, reason)
        messages.success(request, '清理任务已提交，稍后请刷新查看结果')
    except Exception as exc:
        messages.error(request, f'清理任务提交失败：{exc}')
    return redirect('av_detection_detail', did=did)


# ---------------------------------------------------------------- 审计 / 任务

@sso_required
def audit(request):
    qs = (AvAuditLog.objects.select_related('detection')
          .order_by('-created_at'))
    action = request.GET.get('action', '').strip()
    q = request.GET.get('q', '').strip()
    if action:
        qs = qs.filter(action=action)
    if q:
        qs = (qs.filter(username__icontains=q)
              | qs.filter(object_repr__icontains=q))
    actions = (AvAuditLog.objects.values_list('action', flat=True)
               .distinct().order_by('action'))
    return render(request, 'antivirus/audit.html', {
        'page_obj': _paginate(request, qs),
        'actions': actions,
        'f_action': action,
        'f_q': q,
        'query': _query_string(request),
    })


@sso_required
def tasks(request):
    """本模块触发的 Ansible 任务（playbook 以 av_ 开头）。"""
    qs = AnsibleTaskRecord.objects.filter(playbook__startswith='av_')
    status = request.GET.get('status', '')
    if status:
        qs = qs.filter(status=status)
    qs = qs.order_by('-created_at')
    return render(request, 'antivirus/tasks.html', {
        'page_obj': _paginate(request, qs),
        'status_choices': AnsibleTaskRecord._meta.get_field('status').choices,
        'f_status': status,
        'query': _query_string(request),
    })
