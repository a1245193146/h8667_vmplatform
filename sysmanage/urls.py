"""系统管理模块 URL（name 以 sys_ 前缀，避免与其它模块冲突）。"""
from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='sys_index'),

    # 执行留痕（第6项「日志管理」）
    path('execlogs/', views.execlogs, name='sys_execlogs'),
    path('execlogs/<int:pk>/', views.execlog_detail, name='sys_execlog_detail'),
    path('execlogs/purge/', views.execlog_purge, name='sys_execlog_purge'),

    # 配置管理（第5项）
    path('config/', views.config_list, name='sys_config'),
    path('config/save/', views.config_save, name='sys_config_save'),
    path('config/reset/', views.config_reset, name='sys_config_reset'),
    path('config/audit/', views.config_audit, name='sys_config_audit'),
]
