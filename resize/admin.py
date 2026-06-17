from django.contrib import admin

from .models import DiskResizeTask, DomainTask, ServerAuthTask, TrustSiteTask


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


@admin.register(DomainTask)
class DomainTaskAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'domain', 'backend_ip', 'port',
        'applicant', 'approval_status', 'status',
        'create_time',
    )
    list_filter = ('approval_status', 'status')
    search_fields = ('domain', 'applicant', 'backend_ip')
    readonly_fields = ('create_time', 'finish_time')
    ordering = ('-id',)


@admin.register(ServerAuthTask)
class ServerAuthTaskAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'login_account', 'hostname_ip',
        'applicant', 'status', 'create_time',
    )
    list_filter = ('status',)
    search_fields = ('login_account', 'applicant', 'hostname_ip')
    readonly_fields = ('create_time', 'finish_time')
    ordering = ('-id',)


@admin.register(TrustSiteTask)
class TrustSiteTaskAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'domain', 'applicant', 'status', 'create_time',
    )
    list_filter = ('status',)
    search_fields = ('domain', 'applicant')
    readonly_fields = ('create_time', 'finish_time')
    ordering = ('-id',)
