import json

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_POST
from hpjx.hpjx_sso import sso_require_login
from .forms import DiskResizeForm, DomainForm, ServerAuthForm, TrustSiteForm
from .models import DiskResizeTask, DomainTask, ServerAuthTask, TrustSiteTask
from .tasks import (
    execute_resize_task,
    execute_domain_task,
    execute_server_auth_task,
    execute_trust_site_task,
)
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

@sso_require_login(sso_verify_type="normal", response_type="html")
# @sso_required
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

            # 虚拟机磁盘 <=200GB: 自动审批并立即异步执行
            if not task.needs_approval:

                task.approval_status = 'auto_approved'
                task.approved_by = 'system'
                task.approved_at = timezone.now()
                task.status = 'pending'
                task.save()

                # 需求 #3: 异步执行
                execute_resize_task.delay(task.id)

                return redirect('history')

            # 虚拟机磁盘 >200GB: 进入人工审批
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


def sso_logout_init(request):
    """初始化 SSO 退出流程：调用 SSO 退出接口，成功后清除 SsoUserInfo 并返回 JSON。"""
    import requests as http_requests
    from django.conf import settings
    from django.http import JsonResponse

    def JsonYes(data=None, msg='成功'):
        """返回成功 JSON 响应"""
        result = {'status': 'yes', 'code': '50000', 'msg': msg}
        if data:
            result.update(data)
        return JsonResponse(result)

    def JsonNo(msg='失败'):
        """返回失败 JSON 响应"""
        return JsonResponse({'status': 'no', 'code': '50001', 'msg': msg})

    # 获取当前用户的 token（从 Cookie）
    token = request.COOKIES.get(settings.TOKEN_KEY, '')
    if not token:
        return JsonNo('缺少 token')

    # 获取 SSO 用户信息
    sso_user_info = getattr(request, 'SsoUserInfo', None)
    if not sso_user_info:
        return JsonNo('未登录')

    card_no = sso_user_info.get('card_no', '')

    # 构建 SSO 退出参数
    app_id = getattr(settings, 'SSO_APP_ID', '')
    app_secret = getattr(settings, 'SSO_APP_SECRET', '')
    
    if hasattr(settings, 'SSO_IS_DEBUG') and settings.SSO_IS_DEBUG:
        app_id = getattr(settings, 'DEV_SSO_APP_ID', app_id)
        app_secret = getattr(settings, 'DEV_SSO_APP_SECRET', app_secret)

    # 构建 SSO 退出 URL（使用 http）
    sso_logout_uri = getattr(settings, 'SSO_LOGOUT_URI', '')
    if hasattr(settings, 'SSO_IS_DEBUG') and settings.SSO_IS_DEBUG:
        sso_logout_uri = getattr(settings, 'DEV_SSO_LOGOUT_URI', sso_logout_uri)
    
    if sso_logout_uri and not sso_logout_uri.startswith(('http://', 'https://')):
        sso_logout_uri = 'http://' + sso_logout_uri

    # 调用 SSO 退出接口（使用 data 表单提交）
    try:
        response = http_requests.post(
            sso_logout_uri,
            data={
                'app_id': app_id,
                'app_secure': app_secret,
                'token': token,
                'card_no': card_no,
            },
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'yes':
                # SSO 退出成功，清除本地 SsoUserInfo
                request.SsoUserInfo = {}
                
                # 清除 Django 会话
                if hasattr(request, 'session') and request.session.exists(request.session.session_key):
                    request.session.flush()
                
                # 构建 SSO 登录页面 URL（带 redirect_url 参数）
                login_url = getattr(settings, 'SSO_LOGIN_INDEX_URL', 'sso.4307.com/ctrl/login/')
                if hasattr(settings, 'SSO_IS_DEBUG') and settings.SSO_IS_DEBUG:
                    login_url = getattr(settings, 'DEV_SSO_LOGIN_INDEX_URL', login_url)
                
                if login_url and not login_url.startswith(('http://', 'https://')):
                    login_url = 'https://' + login_url
                
                # 构建 redirect_url（当前站点主页）
                redirect_url = request.build_absolute_uri('/')
                sso_login_url = f'{login_url}?redirect_url={redirect_url}'
                
                return JsonYes({'logout_url': sso_login_url}, '退出成功')
            else:
                return JsonNo(result.get('desc', 'SSO 退出失败'))
        else:
            return JsonNo(f'SSO 响应状态码: {response.status_code}')
            
    except Exception as e:
        # 调用失败，清除本地会话
        if hasattr(request, 'session') and request.session.exists(request.session.session_key):
            request.session.flush()
        return JsonNo(f'退出登录失败: {str(e)}')


def logout(request):
    """SSO 退出回调：处理 SSO 服务器的注销回调，清除本地会话并重定向到主页。"""
    return sso_logout_init(request)


@sso_required
def domain_submit(request):
    """提交域名配置申请"""

    if request.method == 'POST':

        form = DomainForm(request.POST)

        if form.is_valid():

            task = form.save(commit=False)
            task.applicant = get_sso_username(request)
            task.approval_status = 'pending'
            task.status = 'pending_approval'
            task.save()

            return redirect('domain_history')

    else:

        form = DomainForm()

    return render(request, 'resize/domain_submit.html', {
        'form': form,
    })


@sso_required
def domain_history(request):
    """域名配置历史记录"""

    if is_admin(request):
        tasks = DomainTask.objects.all()
    else:
        tasks = DomainTask.objects.filter(
            applicant=get_sso_username(request)
        )

    return render(request, 'resize/domain_history.html', {
        'tasks': tasks,
    })


@sso_required
def domain_detail(request, task_id):
    """域名配置任务详情"""

    task = get_object_or_404(
        DomainTask, id=task_id
    )

    return render(request, 'resize/domain_detail.html', {
        'task': task,
    })


@admin_required
def domain_admin_pending(request):
    """管理员域名审批列表"""

    tasks = DomainTask.objects.filter(
        approval_status='pending'
    )

    return render(request, 'resize/domain_admin_pending.html', {
        'tasks': tasks,
    })


@admin_required
@require_POST
def domain_admin_approve(request, task_id):
    """管理员批准域名申请"""

    task = get_object_or_404(
        DomainTask, id=task_id
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

    execute_domain_task.delay(task.id)

    return redirect('domain_admin_pending')


@admin_required
@require_POST
def domain_admin_reject(request, task_id):
    """管理员驳回域名申请"""

    task = get_object_or_404(
        DomainTask, id=task_id
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

    return redirect('domain_admin_pending')


# ==================== 服务器授权登录（无需审批） ====================

@sso_required
def server_auth_submit(request):
    """提交服务器授权登录申请（无需审批，提交即异步执行）"""

    if request.method == 'POST':

        form = ServerAuthForm(request.POST)

        if form.is_valid():

            task = form.save(commit=False)
            task.applicant = get_sso_username(request)
            task.approval_status = 'auto_approved'
            task.approved_by = 'system'
            task.approved_at = timezone.now()
            task.status = 'pending'
            task.save()

            execute_server_auth_task.delay(task.id)

            return redirect('server_auth_history')

    else:

        form = ServerAuthForm()

    return render(request, 'resize/server_auth_submit.html', {
        'form': form,
    })


@sso_required
def server_auth_history(request):
    """服务器授权登录历史记录"""

    if is_admin(request):
        tasks = ServerAuthTask.objects.all()
    else:
        tasks = ServerAuthTask.objects.filter(
            applicant=get_sso_username(request)
        )

    return render(request, 'resize/server_auth_history.html', {
        'tasks': tasks,
    })


@sso_required
def server_auth_detail(request, task_id):
    """服务器授权登录任务详情"""

    task = get_object_or_404(
        ServerAuthTask, id=task_id
    )

    return render(request, 'resize/server_auth_detail.html', {
        'task': task,
    })


# ==================== 设置受信任站点（无需审批） ====================

@sso_required
def trust_site_submit(request):
    """提交受信任站点设置申请（无需审批，提交即异步执行）"""

    if request.method == 'POST':

        form = TrustSiteForm(request.POST)

        if form.is_valid():

            task = form.save(commit=False)
            task.applicant = get_sso_username(request)
            task.approval_status = 'auto_approved'
            task.approved_by = 'system'
            task.approved_at = timezone.now()
            task.status = 'pending'
            task.save()

            execute_trust_site_task.delay(task.id)

            return redirect('trust_site_history')

    else:

        form = TrustSiteForm()

    return render(request, 'resize/trust_site_submit.html', {
        'form': form,
    })


@sso_required
def trust_site_history(request):
    """受信任站点设置历史记录"""

    if is_admin(request):
        tasks = TrustSiteTask.objects.all()
    else:
        tasks = TrustSiteTask.objects.filter(
            applicant=get_sso_username(request)
        )

    return render(request, 'resize/trust_site_history.html', {
        'tasks': tasks,
    })


@sso_required
def trust_site_detail(request, task_id):
    """受信任站点设置任务详情"""

    task = get_object_or_404(
        TrustSiteTask, id=task_id
    )

    return render(request, 'resize/trust_site_detail.html', {
        'task': task,
    })
