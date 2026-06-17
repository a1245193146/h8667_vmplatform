from django.urls import path

from . import views

urlpatterns = [

    path(
        '',
        views.index,
        name='index'
    ),

    path(
        'submit/',
        views.submit_resize,
        name='submit'
    ),

    path(
        'history/',
        views.history,
        name='history'
    ),

    path(
        'detail/<int:task_id>/',
        views.detail,
        name='detail'
    ),

    # 管理员审批（使用approval前缀避免与Django Admin冲突）
    path(
        'approval/pending/',
        views.admin_pending,
        name='admin_pending'
    ),

    path(
        'approval/approve/<int:task_id>/',
        views.admin_approve,
        name='admin_approve'
    ),

    path(
        'approval/reject/<int:task_id>/',
        views.admin_reject,
        name='admin_reject'
    ),

    # AJAX API
    path(
        'api/vm-disks/',
        views.api_vm_disks,
        name='api_vm_disks'
    ),

    # 退出登录
    path(
        'logout/',
        views.logout,
        name='logout'
    ),

    path(
        'domain/',
        views.domain_submit,
        name='domain_submit'
    ),

    path(
        'domain/history/',
        views.domain_history,
        name='domain_history'
    ),

    path(
        'domain/detail/<int:task_id>/',
        views.domain_detail,
        name='domain_detail'
    ),

    path(
        'domain/approval/pending/',
        views.domain_admin_pending,
        name='domain_admin_pending'
    ),

    path(
        'domain/approval/approve/<int:task_id>/',
        views.domain_admin_approve,
        name='domain_admin_approve'
    ),

    path(
        'domain/approval/reject/<int:task_id>/',
        views.domain_admin_reject,
        name='domain_admin_reject'
    ),

    # 服务器授权登录（无需审批）
    path(
        'serverauth/',
        views.server_auth_submit,
        name='server_auth_submit'
    ),

    path(
        'serverauth/history/',
        views.server_auth_history,
        name='server_auth_history'
    ),

    path(
        'serverauth/detail/<int:task_id>/',
        views.server_auth_detail,
        name='server_auth_detail'
    ),

    # 设置受信任站点（无需审批）
    path(
        'trustsite/',
        views.trust_site_submit,
        name='trust_site_submit'
    ),

    path(
        'trustsite/history/',
        views.trust_site_history,
        name='trust_site_history'
    ),

    path(
        'trustsite/detail/<int:task_id>/',
        views.trust_site_detail,
        name='trust_site_detail'
    ),
]
