# Generated for antivirus module (hand-written, mirrors firewall/0001_initial style)

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('firewall', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AvDetection',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('detected_at', models.DateTimeField(db_index=True, verbose_name='检测时间')),
                ('original_path', models.CharField(blank=True, default='', max_length=500, verbose_name='原始文件路径')),
                ('file_name', models.CharField(blank=True, default='', max_length=255, verbose_name='文件名')),
                ('file_size', models.BigIntegerField(blank=True, null=True, verbose_name='文件大小(字节)')),
                ('sha256', models.CharField(blank=True, db_index=True, default='', max_length=64, verbose_name='SHA256')),
                ('threat_name', models.CharField(blank=True, default='', max_length=255, verbose_name='Defender威胁名称')),
                ('threat_type', models.CharField(blank=True, default='', max_length=100, verbose_name='威胁类型')),
                ('severity', models.CharField(blank=True, default='', max_length=50, verbose_name='严重级别')),
                ('category', models.CharField(blank=True, default='', max_length=100, verbose_name='威胁分类')),
                ('action_taken', models.CharField(blank=True, default='', max_length=50, verbose_name='Defender处置结果')),
                ('process_name', models.CharField(blank=True, default='', max_length=500, verbose_name='触发进程')),
                ('defender_threat_id', models.CharField(blank=True, default='', max_length=64, verbose_name='Defender威胁ID')),
                ('detection_source', models.CharField(default='eventlog', max_length=30, verbose_name='数据来源')),
                ('defender_record_id', models.BigIntegerField(blank=True, null=True, verbose_name='Defender事件RecordId')),
                ('quarantine_path', models.CharField(blank=True, default='', max_length=500, verbose_name='隔离文件保存路径')),
                ('quarantine_status', models.CharField(choices=[('pending', '未留存'), ('preserved', '已留存'), ('unavailable', '原文件不可得'), ('restored', '已恢复'), ('cleaned', '已清理')], default='pending', max_length=20, verbose_name='隔离留存状态')),
                ('status', models.CharField(choices=[('pending_review', '待复核'), ('confirmed_malicious', '确认恶意'), ('false_positive', '误报'), ('restored', '已恢复'), ('cleaned', '已清理')], default='pending_review', max_length=20, verbose_name='当前状态')),
                ('reviewer', models.CharField(blank=True, default='', max_length=100, verbose_name='操作人员')),
                ('reviewed_at', models.DateTimeField(blank=True, null=True, verbose_name='操作时间')),
                ('remark', models.TextField(blank=True, default='', verbose_name='备注')),
                ('event_hash', models.CharField(max_length=64, verbose_name='事件指纹')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('host', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='av_detections', to='firewall.firewallhost')),
            ],
            options={
                'verbose_name': '病毒检测事件',
                'verbose_name_plural': '病毒检测事件',
            },
        ),
        migrations.CreateModel(
            name='AvCollectState',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_record_id', models.BigIntegerField(default=0, verbose_name='已采集RecordId水位')),
                ('last_collect_time', models.DateTimeField(blank=True, null=True, verbose_name='最近采集时间')),
                ('last_status', models.CharField(blank=True, default='', max_length=20, verbose_name='最近采集状态')),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('host', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='av_collect_state', to='firewall.firewallhost')),
            ],
            options={
                'verbose_name': '病毒采集水位',
                'verbose_name_plural': '病毒采集水位',
            },
        ),
        migrations.CreateModel(
            name='AvAuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=100)),
                ('action', models.CharField(max_length=50)),
                ('object_repr', models.CharField(blank=True, default='', max_length=255)),
                ('old_status', models.CharField(blank=True, default='', max_length=20)),
                ('new_status', models.CharField(blank=True, default='', max_length=20)),
                ('reason', models.TextField(blank=True, default='')),
                ('ansible_task_ref', models.CharField(blank=True, default='', max_length=64)),
                ('result', models.CharField(default='success', max_length=20)),
                ('detail', models.TextField(blank=True, default='')),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('detection', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='audit_logs', to='antivirus.avdetection')),
            ],
            options={
                'verbose_name': '病毒模块操作日志',
                'verbose_name_plural': '病毒模块操作日志',
            },
        ),
        migrations.AddIndex(
            model_name='avdetection',
            index=models.Index(fields=['detected_at'], name='antivirus_a_detecte_idx'),
        ),
        migrations.AddIndex(
            model_name='avdetection',
            index=models.Index(fields=['status'], name='antivirus_a_status_idx'),
        ),
        migrations.AddIndex(
            model_name='avdetection',
            index=models.Index(fields=['threat_name'], name='antivirus_a_threat_idx'),
        ),
        migrations.AddIndex(
            model_name='avdetection',
            index=models.Index(fields=['host', 'detected_at'], name='antivirus_a_host_dt_idx'),
        ),
        migrations.AddConstraint(
            model_name='avdetection',
            constraint=models.UniqueConstraint(fields=('host', 'event_hash'), name='uniq_av_host_eventhash'),
        ),
    ]
