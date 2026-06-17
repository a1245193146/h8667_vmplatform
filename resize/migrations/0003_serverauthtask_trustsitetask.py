# Generated for server authorization login & trusted site submodules

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('resize', '0002_domaintask'),
    ]

    operations = [
        migrations.CreateModel(
            name='ServerAuthTask',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('applicant', models.CharField(max_length=100, verbose_name='申请人')),
                ('login_account', models.CharField(help_text='需要授权登录的 AD 域账号 (sAMAccountName)', max_length=100, verbose_name='授权域账号')),
                ('hostname_ip', models.CharField(help_text='目标服务器，多个用英文逗号分隔', max_length=500, verbose_name='服务器IP/主机名')),
                ('reason', models.TextField(verbose_name='申请原因')),
                ('approval_status', models.CharField(choices=[('auto_approved', '自动批准')], default='auto_approved', max_length=20, verbose_name='审批状态')),
                ('approved_by', models.CharField(blank=True, max_length=100, null=True, verbose_name='审批人')),
                ('approved_at', models.DateTimeField(blank=True, null=True, verbose_name='审批时间')),
                ('status', models.CharField(choices=[('pending', '待执行'), ('running', '执行中'), ('success', '成功'), ('failed', '失败')], default='pending', max_length=20, verbose_name='任务状态')),
                ('result', models.TextField(blank=True, null=True, verbose_name='执行结果')),
                ('create_time', models.DateTimeField(auto_now_add=True, verbose_name='创建时间')),
                ('finish_time', models.DateTimeField(blank=True, null=True, verbose_name='完成时间')),
            ],
            options={
                'verbose_name': '服务器授权登录任务',
                'verbose_name_plural': '服务器授权登录任务',
                'ordering': ['-id'],
            },
        ),
        migrations.CreateModel(
            name='TrustSiteTask',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('applicant', models.CharField(max_length=100, verbose_name='申请人')),
                ('domain', models.CharField(help_text='要加入受信任站点的域名，例如: myapp.4307.com', max_length=255, verbose_name='受信任域名')),
                ('reason', models.TextField(verbose_name='申请原因')),
                ('approval_status', models.CharField(choices=[('auto_approved', '自动批准')], default='auto_approved', max_length=20, verbose_name='审批状态')),
                ('approved_by', models.CharField(blank=True, max_length=100, null=True, verbose_name='审批人')),
                ('approved_at', models.DateTimeField(blank=True, null=True, verbose_name='审批时间')),
                ('status', models.CharField(choices=[('pending', '待执行'), ('running', '执行中'), ('success', '成功'), ('failed', '失败')], default='pending', max_length=20, verbose_name='任务状态')),
                ('result', models.TextField(blank=True, null=True, verbose_name='执行结果')),
                ('create_time', models.DateTimeField(auto_now_add=True, verbose_name='创建时间')),
                ('finish_time', models.DateTimeField(blank=True, null=True, verbose_name='完成时间')),
            ],
            options={
                'verbose_name': '受信任站点任务',
                'verbose_name_plural': '受信任站点任务',
                'ordering': ['-id'],
            },
        ),
    ]
