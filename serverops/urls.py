"""服务器运维模块 URL（name 以 serverops_ 前缀，避免与其它模块冲突）。

路由分三组：命令控制台（下发）、执行记录（追溯）、运维问答（查命令）。
三组都挂 @sso_required；L2/L3 的管理员门槛在 job_run 里按【命令内容】动态判定，
不用装饰器——装饰器只能在进函数前拦，而"这条命令是几级"必须先解析请求体才知道。
"""
from django.urls import path

from . import views

urlpatterns = [
    # 命令控制台
    path('', views.console, name='serverops_console'),
    path('classify/', views.api_classify, name='serverops_classify'),
    path('run/', views.job_run, name='serverops_run'),

    # 执行记录
    path('jobs/', views.job_list, name='serverops_jobs'),
    path('jobs/<int:pk>/', views.job_detail, name='serverops_job_detail'),
    path('jobs/<int:pk>/api/', views.api_job, name='serverops_job_api'),

    # 运维问答
    path('chat/', views.chat_view, name='serverops_chat'),
    path('chat/history/', views.chat_history, name='serverops_chat_history'),
    path('chat/api/send/', views.api_chat_send, name='serverops_chat_send'),
    path('chat/api/<int:pk>/', views.api_chat_poll, name='serverops_chat_poll'),
]
