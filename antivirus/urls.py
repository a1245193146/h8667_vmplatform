"""病毒检测与隔离模块 URL 配置（name 以 av_ 前缀，避免与 firewall 冲突）。"""
from django.urls import path

from . import views

urlpatterns = [
    path('', views.dashboard, name='av_dashboard'),
    path('api/dashboard/', views.api_dashboard, name='av_api_dashboard'),
    path('detections/', views.detections, name='av_detections'),
    path('detections/<int:did>/', views.detection_detail,
         name='av_detection_detail'),
    path('detections/<int:did>/preserve/', views.detection_preserve,
         name='av_detection_preserve'),
    path('detections/<int:did>/review/<str:op>/', views.detection_review,
         name='av_detection_review'),
    path('detections/<int:did>/restore/', views.detection_restore,
         name='av_detection_restore'),
    path('detections/<int:did>/cleanup/', views.detection_cleanup,
         name='av_detection_cleanup'),
    path('collect/', views.collect_all, name='av_collect_all'),
    path('hosts/<int:hid>/collect/', views.host_collect, name='av_host_collect'),
    path('audit/', views.audit, name='av_audit'),
    path('tasks/', views.tasks, name='av_tasks'),
]
