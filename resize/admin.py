from django.contrib import admin

from .models import DiskResizeTask


@admin.register(DiskResizeTask)
class DiskResizeTaskAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'vm_ip', 'disk_label', 'add_size',
        'applicant', 'approval_status', 'status',
        'create_time',
    )
    list_filter = ('approval_status', 'status')
    search_fields = ('vm_ip', 'applicant', 'disk_label')
    readonly_fields = ('create_time', 'finish_time')
    ordering = ('-id',)
