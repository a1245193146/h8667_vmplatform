from django.contrib import admin

from .models import AvAuditLog, AvCollectState, AvDetection


@admin.register(AvDetection)
class AvDetectionAdmin(admin.ModelAdmin):
    list_display = ('detected_at', 'host', 'file_name', 'threat_name',
                    'action_taken', 'status', 'quarantine_status', 'reviewer')
    list_filter = ('status', 'quarantine_status', 'action_taken', 'severity',
                   'detection_source')
    search_fields = ('file_name', 'original_path', 'threat_name', 'sha256',
                     'host__hostname', 'host__ip')
    date_hierarchy = 'detected_at'
    readonly_fields = ('event_hash', 'defender_record_id', 'created_at',
                       'updated_at')


@admin.register(AvCollectState)
class AvCollectStateAdmin(admin.ModelAdmin):
    list_display = ('host', 'last_record_id', 'last_collect_time', 'last_status')
    search_fields = ('host__hostname', 'host__ip')


@admin.register(AvAuditLog)
class AvAuditLogAdmin(admin.ModelAdmin):
    list_display = ('username', 'action', 'object_repr', 'old_status',
                    'new_status', 'result', 'created_at')
    list_filter = ('action', 'result')
    search_fields = ('username', 'object_repr', 'reason', 'ansible_task_ref')
    date_hierarchy = 'created_at'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
