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

    # 管理员审批
    path(
        'admin/pending/',
        views.admin_pending,
        name='admin_pending'
    ),

    path(
        'admin/approve/<int:task_id>/',
        views.admin_approve,
        name='admin_approve'
    ),

    path(
        'admin/reject/<int:task_id>/',
        views.admin_reject,
        name='admin_reject'
    ),

    # AJAX API
    path(
        'api/vm-disks/',
        views.api_vm_disks,
        name='api_vm_disks'
    ),
]
