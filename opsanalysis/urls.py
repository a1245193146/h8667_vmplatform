"""运维分析模块 URL 配置（name 以 ops_ 前缀，避免与其他模块冲突）。"""
from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='ops_index'),
    path('impact/', views.impact_form, name='ops_impact_form'),
    path('impact/run/', views.impact_run, name='ops_impact_run'),
    path('impact/<int:task_id>/', views.impact_result, name='ops_impact_result'),
    path('impact/<int:task_id>/api/', views.api_impact_result, name='ops_api_impact_result'),
    path('tasks/', views.tasks, name='ops_tasks'),

    # 服务关联登记（P4）
    path('services/', views.services, name='ops_services'),
    path('services/<int:pk>/', views.service_detail, name='ops_service_detail'),
    path('services/<int:pk>/update/', views.service_update, name='ops_service_update'),
    path('services/<int:pk>/confirm/', views.service_confirm, name='ops_service_confirm'),
    path('services/<int:pk>/delete/', views.service_delete, name='ops_service_delete'),
    path('services/discover/', views.discover_run, name='ops_discover_run'),

    # 服务故障辅助排查（P5）
    path('troubleshoot/', views.troubleshoot_form, name='ops_troubleshoot_form'),
    path('troubleshoot/run/', views.troubleshoot_run, name='ops_troubleshoot_run'),
    path('troubleshoot/<int:task_id>/', views.troubleshoot_result, name='ops_troubleshoot_result'),
    path('troubleshoot/<int:task_id>/api/', views.api_troubleshoot_result, name='ops_api_troubleshoot_result'),

    # 大模型辅助分析（手动按钮触发；模型只读证据、只出参考意见，不执行任何动作）
    path('llm/<int:task_id>/run/', views.llm_run, name='ops_llm_run'),
    path('llm/<int:task_id>/api/', views.api_llm_result, name='ops_api_llm_result'),
    path('llm/ping/', views.llm_ping, name='ops_llm_ping'),
    # 单次分析的完整留痕（证据全文 + 各批输出 + 最终意见），供事后复用/对比
    path('llm/record/<int:pk>/', views.llm_record_detail, name='ops_llm_record'),
]
