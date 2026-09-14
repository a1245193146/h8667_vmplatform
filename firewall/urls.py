"""防火墙模块 URL 配置（SPEC-firewall.md §6，name 冻结）。"""
from django.urls import path

from . import views

urlpatterns = [
    path('', views.dashboard, name='fw_dashboard'),
    path('hosts/', views.hosts, name='fw_hosts'),
    path('hosts/sync/', views.hosts_sync, name='fw_hosts_sync'),
    path('hosts/<int:hid>/', views.host_detail, name='fw_host_detail'),
    path('hosts/<int:hid>/collect/', views.host_collect,
         name='fw_host_collect'),
    path('hosts/<int:hid>/firewall/<str:op>/', views.host_firewall,
         name='fw_host_firewall'),
    path('rules/', views.rules, name='fw_rules'),
    path('rules/<int:rid>/remove/', views.rule_remove, name='fw_rule_remove'),
    path('rules/<int:rid>/rollback/', views.rule_rollback,
         name='fw_rule_rollback'),
    path('requests/', views.requests, name='fw_requests'),
    path('requests/new/', views.request_new, name='fw_request_new'),
    path('requests/<int:rid>/review/<str:op>/', views.request_review,
         name='fw_request_review'),
    path('communications/', views.communications, name='fw_communications'),
    path('audit/', views.audit, name='fw_audit'),
    path('tasks/', views.tasks, name='fw_tasks'),
    path('api/dashboard/', views.api_dashboard, name='fw_api_dashboard'),
]
