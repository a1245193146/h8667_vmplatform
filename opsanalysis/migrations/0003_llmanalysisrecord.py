# 新增 LlmAnalysisRecord：大模型辅助分析的完整留痕（hand-written）
#
# 为什么单独建表：analysis['llm'] 每次重跑会被整体覆盖，历史结论无法回溯；
# 且证据正文上万字，留在 JSONField 里会被结果页轮询接口反复传输。
# 内网 prod 部署后需执行：python manage.py migrate opsanalysis

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('opsanalysis', '0002_serviceregistry_last_online_at'),
    ]

    operations = [
        migrations.CreateModel(
            name='LlmAnalysisRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name='ID')),
                ('scope', models.CharField(
                    choices=[('impact', '服务器操作影响分析'),
                             ('troubleshoot', '服务故障辅助排查')],
                    default='troubleshoot', max_length=20, verbose_name='场景')),
                ('status', models.CharField(
                    choices=[('running', '进行中'), ('success', '成功'),
                             ('failed', '失败'), ('disabled', '未启用')],
                    default='running', max_length=20, verbose_name='状态')),
                ('model', models.CharField(blank=True, default='', max_length=128,
                                           verbose_name='模型名')),
                ('temperature', models.FloatField(blank=True, null=True, verbose_name='温度')),
                ('prompt_version', models.CharField(blank=True, default='', max_length=32,
                                                    verbose_name='提示词版本')),
                ('base_url', models.CharField(blank=True, default='', max_length=255,
                                              verbose_name='模型接口地址')),
                ('evidence', models.TextField(blank=True, default='',
                                              verbose_name='证据全文（多批以分隔线拼接）')),
                ('batches', models.JSONField(blank=True, default=list,
                                             verbose_name='分批明细（段落/字数/输出/耗时）')),
                ('output', models.TextField(blank=True, default='',
                                            verbose_name='模型最终意见（多批时为汇总稿）')),
                ('error', models.TextField(blank=True, default='', verbose_name='错误/警告信息')),
                ('prompt_chars', models.IntegerField(default=0, verbose_name='提示词总字数')),
                ('evidence_chars', models.IntegerField(default=0, verbose_name='证据字数')),
                ('batch_count', models.IntegerField(default=0, verbose_name='批次数')),
                ('latency_ms', models.IntegerField(default=0, verbose_name='总耗时(毫秒)')),
                ('requested_by', models.CharField(blank=True, default='', max_length=100,
                                                  verbose_name='发起人')),
                ('requested_at', models.DateTimeField(blank=True, null=True,
                                                      verbose_name='发起时间')),
                ('finished_at', models.DateTimeField(blank=True, null=True,
                                                     verbose_name='完成时间')),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('task', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='llm_records', to='opsanalysis.analysistask',
                    verbose_name='分析任务')),
            ],
            options={
                'verbose_name': '大模型辅助分析记录',
                'verbose_name_plural': '大模型辅助分析记录',
                'ordering': ['-id'],
            },
        ),
        migrations.AddIndex(
            model_name='llmanalysisrecord',
            index=models.Index(fields=['task', 'scope'], name='opsanalysis_llm_task_idx'),
        ),
    ]
