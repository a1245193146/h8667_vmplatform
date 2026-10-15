from django.contrib import admin

from .models import (AnalysisResult, AnalysisTask, ServiceRegistry,
                     TimelineEvent)


@admin.register(ServiceRegistry)
class ServiceRegistryAdmin(admin.ModelAdmin):
    list_display = ('canonical_name', 'os_type', 'port', 'supervisor_program',
                    'jenkins_job', 'status', 'source', 'updated_at')
    list_filter = ('status', 'source', 'os_type')
    search_fields = ('canonical_name', 'jenkins_job', 'git_project',
                     'supervisor_program')


@admin.register(AnalysisTask)
class AnalysisTaskAdmin(admin.ModelAdmin):
    list_display = ('kind', 'target', 'status', 'initiated_by',
                    'created_at', 'finished_at')
    list_filter = ('kind', 'status')
    search_fields = ('target', 'initiated_by')
    date_hierarchy = 'created_at'


@admin.register(AnalysisResult)
class AnalysisResultAdmin(admin.ModelAdmin):
    list_display = ('task', 'collected_at', 'created_at')
    search_fields = ('task__target',)


@admin.register(TimelineEvent)
class TimelineEventAdmin(admin.ModelAdmin):
    list_display = ('ts', 'task', 'source', 'event_type', 'kind', 'summary')
    list_filter = ('source', 'kind')
    search_fields = ('summary', 'event_type')
    date_hierarchy = 'ts'
