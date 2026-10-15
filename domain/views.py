from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from resize.sso_utils import admin_required, get_sso_username, is_admin, sso_required

from .models import DomainTask
from .tasks import execute_domain_task


@sso_required
def submit_domain(request):
    """旧入口，已停用：跳转到现在真正在用的 resize 域名申请页。

    这个 app 是早期原型，它的 DomainTask 和 resize.DomainTask 是两张不同的表，
    服务层也只是 POST 一个 nginx reload 接口；resize 那套才做完整的
    nginx 反代 + DNS A 记录 + ADCS 签发证书。

    项目 urls 里 resize.urls 先 include，所以 /domain/history/ 和
    /domain/approval/* 全被 resize 的同名路径挡在前面。从这里提交的申请
    写进的是本 app 的表，可审批页读的是 resize 的表——那条申请永远进不了
    审批队列，申请人回到记录页也看不到自己刚提交的东西，像是凭空消失了。
    留一个能填但填了没用的表单比 404 更坏，所以直接把入口指到能跑通的那套。

    模型、数据表和 admin.py 的注册都保留，历史数据仍可在 /admin/ 里查。
    """
    messages.info(request, '该入口已停用，已为你跳转到当前使用的域名申请页。')
    return redirect('domain_submit')


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
    """旧台账入口，已停用：跳转到 resize 的域名记录页。

    台账筛的是本 app DomainTask 里 success/partial_success 的记录，而这张表
    因为 submit_domain 里说的原因是空的，所以这个页面永远只有一片空白。

    也不能拿 resize 的数据把它喂活：ledger.html 和 history.html 里的详情链接
    走 domain:detail，生成的 /domain/detail/<id>/ 会被 resize.urls 抢先匹配，
    id 被当成 resize 的任务号，点开看到的是另一条毫不相干的记录。
    与其给一个空白页或者一个会串号的页面，不如直接跳到有真数据的那一页。
    """
    messages.info(request, '该入口已停用，已为你跳转到当前使用的域名记录页。')
    return redirect('domain_history')
