from django.contrib import admin

from .models import DomainTask


@admin.register(DomainTask)
class DomainTaskAdmin(admin.ModelAdmin):
    list_display = ('domain', 'target_ip', 'target_port', 'applicant', 'approval_status', 'status', 'create_time')
    list_filter = ('approval_status', 'status')
    search_fields = ('domain', 'target_ip', 'applicant')
