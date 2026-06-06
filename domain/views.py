from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from resize.sso_utils import admin_required, get_sso_username, is_admin, sso_required

from .forms import DomainTaskForm
from .models import DomainTask
from .tasks import execute_domain_task


@sso_required
def submit_domain(request):
    """提交域名配置申请。"""
    if request.method == 'POST':
        form = DomainTaskForm(request.POST)
        if form.is_valid():
            task = form.save(commit=False)
            task.applicant = get_sso_username(request)
            task.approval_status = 'pending'
            task.status = 'pending_approval'
            task.save()
            return redirect('domain:history')
    else:
        form = DomainTaskForm()

    return render(request, 'domain/submit.html', {
        'form': form,
    })


@sso_required
def domain_history(request):
    """域名配置历史记录。"""
    if is_admin(request):
        tasks = DomainTask.objects.all()
    else:
        tasks = DomainTask.objects.filter(
            applicant=get_sso_username(request)
        )

    return render(request, 'domain/history.html', {
        'tasks': tasks,
    })


@sso_required
def domain_detail(request, task_id):
    """域名配置任务详情。"""
    task = get_object_or_404(DomainTask, id=task_id)

    return render(request, 'domain/detail.html', {
        'task': task,
    })


@admin_required
def domain_admin_pending(request):
    """域名配置管理员审批列表。"""
    tasks = DomainTask.objects.filter(
        approval_status='pending'
    )

    return render(request, 'domain/admin_pending.html', {
        'tasks': tasks,
    })


@admin_required
@require_POST
def domain_admin_approve(request, task_id):
    """管理员批准域名配置申请。"""
    task = get_object_or_404(DomainTask, id=task_id)

    if task.approval_status != 'pending':
        return JsonResponse({'error': '该申请已处理'}, status=400)

    task.approval_status = 'approved'
    task.approved_by = get_sso_username(request)
    task.approved_at = timezone.now()
    task.status = 'pending'
    task.save()

    execute_domain_task.delay(task.id)

    return redirect('domain:admin_pending')


@admin_required
@require_POST
def domain_admin_reject(request, task_id):
    """管理员驳回域名配置申请。"""
    task = get_object_or_404(DomainTask, id=task_id)

    if task.approval_status != 'pending':
        return JsonResponse({'error': '该申请已处理'}, status=400)

    reject_reason = request.POST.get('reject_reason', '')

    task.approval_status = 'rejected'
    task.approved_by = get_sso_username(request)
    task.approved_at = timezone.now()
    task.reject_reason = reject_reason
    task.status = 'rejected'
    task.save()

    return redirect('domain:admin_pending')


@sso_required
def domain_ledger(request):
    """域名管理台账：展示所有成功或部分成功配置的域名。"""
    tasks = DomainTask.objects.filter(
        status__in=['success', 'partial_success']
    )

    return render(request, 'domain/ledger.html', {
        'tasks': tasks,
    })
