# Generated manually for domain management module

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='DomainTask',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('applicant', models.CharField(max_length=100, verbose_name='申请人')),
                ('domain', models.CharField(max_length=200, verbose_name='域名')),
                ('target_ip', models.GenericIPAddressField(verbose_name='目标IP')),
                ('target_port', models.IntegerField(verbose_name='目标端口')),
                ('reason', models.TextField(blank=True, default='', verbose_name='申请原因')),
                ('approval_status', models.CharField(choices=[('pending', '待审批'), ('approved', '管理员批准'), ('rejected', '已驳回')], default='pending', max_length=20, verbose_name='审批状态')),
                ('approved_by', models.CharField(blank=True, max_length=100, null=True, verbose_name='审批人')),
                ('approved_at', models.DateTimeField(blank=True, null=True, verbose_name='审批时间')),
                ('reject_reason', models.TextField(blank=True, null=True, verbose_name='驳回原因')),
                ('status', models.CharField(choices=[('pending_approval', '待审批'), ('approved', '已批准'), ('rejected', '已驳回'), ('pending', '待执行'), ('running', '执行中'), ('success', '成功'), ('partial_success', '部分成功'), ('failed', '失败')], default='pending_approval', max_length=20, verbose_name='任务状态')),
                ('result', models.TextField(blank=True, null=True, verbose_name='执行结果')),
                ('dns_status', models.BooleanField(default=False, verbose_name='DNS配置')),
                ('ssl_status', models.BooleanField(default=False, verbose_name='SSL证书')),
                ('nginx_proxy_status', models.BooleanField(default=False, verbose_name='反向代理')),
                ('nginx_upstream_status', models.BooleanField(default=False, verbose_name='负载均衡')),
                ('create_time', models.DateTimeField(auto_now_add=True, verbose_name='创建时间')),
                ('finish_time', models.DateTimeField(blank=True, null=True, verbose_name='完成时间')),
            ],
            options={
                'verbose_name': '域名配置任务',
                'verbose_name_plural': '域名配置任务',
                'ordering': ['-id'],
            },
        ),
    ]
