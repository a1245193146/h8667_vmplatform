from django.contrib import admin

from .models import (AnsibleTaskRecord, CommunicationRelation, DailyFirewallStat,
                     FirewallAuditLog, FirewallEvent, FirewallHost, FirewallRule,
                     FirewallRuleRequest)


@admin.register(FirewallHost)
class FirewallHostAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'ip', 'department', 'ansible_group', 'firewall_status',
                    'is_online', 'enabled', 'last_collection_time')
    list_filter = ('firewall_status', 'is_online', 'enabled', 'department', 'ansible_group')
    search_fields = ('hostname', 'ip', 'department')


@admin.register(FirewallEvent)
class FirewallEventAdmin(admin.ModelAdmin):
    list_display = ('host', 'timestamp', 'action', 'protocol', 'direction',
                    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'process_name')
    list_filter = ('action', 'protocol', 'direction')
    search_fields = ('src_ip', 'dst_ip', 'process_name', 'event_hash')
    date_hierarchy = 'timestamp'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(FirewallRule)
class FirewallRuleAdmin(admin.ModelAdmin):
    list_display = ('rule_name', 'host', 'direction', 'action', 'protocol',
                    'remote_address', 'remote_port', 'source', 'risk_level',
                    'status', 'hit_count', 'expire_at')
    list_filter = ('direction', 'action', 'source', 'risk_level', 'status', 'enabled')
    search_fields = ('rule_name', 'display_name', 'program', 'remote_address', 'fingerprint')


@admin.register(FirewallRuleRequest)
class FirewallRuleRequestAdmin(admin.ModelAdmin):
    list_display = ('application', 'host', 'direction', 'protocol', 'remote_address',
                    'remote_port', 'risk_level', 'status', 'applicant', 'reviewer',
                    'is_temporary', 'created_at')
    list_filter = ('status', 'risk_level', 'direction', 'is_temporary')
    search_fields = ('application', 'program', 'applicant', 'reviewer', 'remote_address')


@admin.register(AnsibleTaskRecord)
class AnsibleTaskRecordAdmin(admin.ModelAdmin):
    list_display = ('name', 'task_ref', 'playbook', 'status', 'initiated_by',
                    'created_at', 'finished_at')
    list_filter = ('status', 'playbook')
    search_fields = ('task_ref', 'name', 'playbook', 'target_hosts')


@admin.register(FirewallAuditLog)
class FirewallAuditLogAdmin(admin.ModelAdmin):
    list_display = ('username', 'host', 'action', 'object_repr', 'result', 'created_at')
    list_filter = ('action', 'result')
    search_fields = ('username', 'object_repr', 'ansible_task_ref', 'detail')
    date_hierarchy = 'created_at'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(CommunicationRelation)
class CommunicationRelationAdmin(admin.ModelAdmin):
    list_display = ('host', 'process_name', 'protocol', 'remote_ip', 'remote_port',
                    'direction', 'risk_level', 'hit_count', 'first_seen', 'last_seen')
    list_filter = ('protocol', 'direction', 'risk_level')
    search_fields = ('process_name', 'program', 'remote_ip')


@admin.register(DailyFirewallStat)
class DailyFirewallStatAdmin(admin.ModelAdmin):
    list_display = ('host', 'date', 'drop_count', 'allow_count')
    list_filter = ('date',)
    search_fields = ('host__hostname', 'host__ip')
    date_hierarchy = 'date'
