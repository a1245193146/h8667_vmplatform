from django.urls import path

from . import views

app_name = 'domain'

urlpatterns = [
    path('submit/', views.submit_domain, name='submit'),
    path('history/', views.domain_history, name='history'),
    path('detail/<int:task_id>/', views.domain_detail, name='detail'),
    path('approval/pending/', views.domain_admin_pending, name='admin_pending'),
    path('approval/approve/<int:task_id>/', views.domain_admin_approve, name='admin_approve'),
    path('approval/reject/<int:task_id>/', views.domain_admin_reject, name='admin_reject'),
    path('ledger/', views.domain_ledger, name='ledger'),
]
