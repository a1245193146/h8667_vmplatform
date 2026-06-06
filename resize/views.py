import json

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_POST

from .forms import DiskResizeForm
from .models import DiskResizeTask
from .tasks import execute_resize_task
from .sso_utils import (
    sso_required,
    admin_required,
    get_sso_username,
    is_admin,
)
from .services.vc_service import (
    get_vm_disk_list,
    check_vm_status,
)


@sso_required
def index(request):
    """首页"""

    return render(request, 'resize/index.html')


@sso_required
def submit_resize(request):
    """提交扩容申请"""

    if request.method == 'POST':

        form = DiskResizeForm(request.POST)

        if form.is_valid():

            task = form.save(commit=False)
            task.applicant = get_sso_username(request)

            # 需求 #5: <200GB 且存储空间充足
            # 自动审批并立即异步执行
            if not task.needs_approval:

                task.approval_status = 'auto_approved'
                task.approved_by = 'system'
                task.approved_at = timezone.now()
                task.status = 'pending'
                task.save()

                # 需求 #3: 异步执行
                execute_resize_task.delay(task.id)

                return redirect('history')

            # >=200GB: 进入人工审批
            task.approval_status = 'pending'
            task.status = 'pending_approval'
            task.save()

            return redirect('history')

    else:

        form = DiskResizeForm()

    return render(request, 'resize/submit.html', {
        'form': form,
    })


@sso_required
def history(request):
    """扩容历史记录"""

    if is_admin(request):
        tasks = DiskResizeTask.objects.all()
    else:
        tasks = DiskResizeTask.objects.filter(
            applicant=get_sso_username(request)
        )

    return render(request, 'resize/history.html', {
        'tasks': tasks,
    })


@sso_required
def detail(request, task_id):
    """任务详情"""

    task = get_object_or_404(
        DiskResizeTask, id=task_id
    )

    return render(request, 'resize/detail.html', {
        'task': task,
    })


@admin_required
def admin_pending(request):
    """管理员审批列表"""

    tasks = DiskResizeTask.objects.filter(
        approval_status='pending'
    )

    return render(request, 'resize/admin_pending.html', {
        'tasks': tasks,
    })


@admin_required
@require_POST
def admin_approve(request, task_id):
    """管理员批准"""

    task = get_object_or_404(
        DiskResizeTask, id=task_id
    )

    if task.approval_status != 'pending':
        return JsonResponse(
            {'error': '该申请已处理'}, status=400
        )

    task.approval_status = 'approved'
    task.approved_by = get_sso_username(request)
    task.approved_at = timezone.now()
    task.status = 'pending'
    task.save()

    # 需求 #3: 批准后异步执行
    execute_resize_task.delay(task.id)

    return redirect('admin_pending')


@admin_required
@require_POST
def admin_reject(request, task_id):
    """管理员驳回"""

    task = get_object_or_404(
        DiskResizeTask, id=task_id
    )

    if task.approval_status != 'pending':
        return JsonResponse(
            {'error': '该申请已处理'}, status=400
        )

    reject_reason = request.POST.get(
        'reject_reason', ''
    )

    task.approval_status = 'rejected'
    task.approved_by = get_sso_username(request)
    task.approved_at = timezone.now()
    task.reject_reason = reject_reason
    task.status = 'rejected'
    task.save()

    return redirect('admin_pending')


@sso_required
def api_vm_disks(request):
    """AJAX 接口: 根据 IP 查询 VM 磁盘列表。

    需求 #6: 解决同大小磁盘无法区分问题。
    GET /api/vm-disks/?ip=x.x.x.x
    """

    vm_ip = request.GET.get('ip', '').strip()

    if not vm_ip:
        return JsonResponse(
            {'error': 'IP 不能为空'}, status=400
        )

    try:

        disks = get_vm_disk_list(vm_ip)
        vm_status = check_vm_status(vm_ip)

        return JsonResponse({
            'disks': disks,
            'vm_status': vm_status,
        })

    except Exception as e:

        return JsonResponse(
            {'error': str(e)}, status=500
        )
