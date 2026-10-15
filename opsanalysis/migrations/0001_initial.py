# Generated for opsanalysis module (hand-written, mirrors antivirus/0001_initial style)

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('firewall', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ServiceRegistry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('canonical_name', models.CharField(max_length=128, unique=True, verbose_name='应用统一名')),
                ('aliases', models.JSONField(blank=True, default=list, verbose_name='各系统别名')),
                ('domains', models.JSONField(blank=True, default=list, verbose_name='对外域名')),
                ('server_ips', models.JSONField(blank=True, default=list, verbose_name='部署服务器IP')),
                ('os_type', models.CharField(choices=[('windows', 'Windows'), ('linux', 'Linux'), ('unknown', '未知')], default='unknown', max_length=16, verbose_name='操作系统类型')),
                ('port', models.IntegerField(blank=True, null=True, verbose_name='服务端口')),
                ('supervisor_program', models.CharField(blank=True, default='', max_length=255, verbose_name='Supervisor程序名')),
                ('jenkins_job', models.CharField(blank=True, default='', max_length=255, verbose_name='Jenkins Job')),
                ('git_project', models.CharField(blank=True, default='', max_length=255, verbose_name='Git项目')),
                ('app_log_path', models.CharField(blank=True, default='', max_length=500, verbose_name='应用日志路径')),
                ('nginx_access_log', models.CharField(blank=True, default='', max_length=500, verbose_name='Nginx访问日志')),
                ('nginx_error_log', models.CharField(blank=True, default='', max_length=500, verbose_name='Nginx错误日志')),
                ('status', models.CharField(choices=[('candidate', '待确认'), ('confirmed', '已确认')], default='candidate', max_length=16, verbose_name='关联状态')),
                ('source', models.CharField(choices=[('auto', '自动发现'), ('manual', '人工登记')], default='manual', max_length=16, verbose_name='来源')),
                ('confidence', models.TextField(blank=True, default='', verbose_name='匹配依据')),
                ('remark', models.TextField(blank=True, default='', verbose_name='备注')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': '服务关联登记',
                'verbose_name_plural': '服务关联登记',
            },
        ),
        migrations.CreateModel(
            name='AnalysisTask',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('kind', models.CharField(choices=[('impact', '服务器操作影响分析'), ('troubleshoot', '服务故障辅助排查')], default='impact', max_length=20, verbose_name='分析类型')),
                ('target', models.CharField(blank=True, default='', max_length=255, verbose_name='目标(IP或应用名)')),
                ('params', models.JSONField(blank=True, default=dict, verbose_name='任务参数')),
                ('status', models.CharField(choices=[('pending', '待执行'), ('running', '执行中'), ('success', '成功'), ('failed', '失败')], default='pending', max_length=20, verbose_name='任务状态')),
                ('initiated_by', models.CharField(blank=True, default='system', max_length=100, verbose_name='发起人')),
                ('error', models.TextField(blank=True, default='', verbose_name='错误信息')),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('finished_at', models.DateTimeField(null=True, blank=True)),
                ('host', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='ops_analysis_tasks', to='firewall.firewallhost', verbose_name='目标服务器')),
                ('service', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='analysis_tasks', to='opsanalysis.serviceregistry', verbose_name='目标服务')),
            ],
            options={
                'verbose_name': '运维分析任务',
                'verbose_name_plural': '运维分析任务',
                'ordering': ['-id'],
            },
        ),
        migrations.CreateModel(
            name='AnalysisResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('snapshot', models.JSONField(blank=True, default=dict, verbose_name='采集快照')),
                ('analysis', models.JSONField(blank=True, default=dict, verbose_name='分析结论')),
                ('collected_at', models.DateTimeField(null=True, blank=True, verbose_name='采集完成时间')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('task', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='result', to='opsanalysis.analysistask')),
            ],
            options={
                'verbose_name': '运维分析结果',
                'verbose_name_plural': '运维分析结果',
            },
        ),
        migrations.CreateModel(
            name='TimelineEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ts', models.DateTimeField(blank=True, db_index=True, null=True, verbose_name='事件时间')),
                ('source', models.CharField(blank=True, default='', max_length=30, verbose_name='来源系统')),
                ('event_type', models.CharField(blank=True, default='', max_length=50, verbose_name='事件类型')),
                ('summary', models.CharField(blank=True, default='', max_length=500, verbose_name='摘要')),
                ('evidence', models.JSONField(blank=True, default=dict, verbose_name='证据')),
                ('kind', models.CharField(choices=[('fact', '已确认事实'), ('correlation', '时间关联'), ('inference', '推测原因'), ('suggestion', '建议检查')], default='fact', max_length=16, verbose_name='结论类型')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('task', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='timeline_events', to='opsanalysis.analysistask')),
            ],
            options={
                'verbose_name': '分析时间线事件',
                'verbose_name_plural': '分析时间线事件',
                'ordering': ['ts'],
            },
        ),
        migrations.AddIndex(
            model_name='serviceregistry',
            index=models.Index(fields=['status'], name='opsanalysis_sr_status_idx'),
        ),
        migrations.AddIndex(
            model_name='analysistask',
            index=models.Index(fields=['kind', 'status'], name='opsanalysis_at_kind_idx'),
        ),
        migrations.AddIndex(
            model_name='timelineevent',
            index=models.Index(fields=['task', 'ts'], name='opsanalysis_te_task_idx'),
        ),
    ]
