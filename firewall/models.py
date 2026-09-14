# 由 SPEC-firewall.md §1 冻结定义实现
from django.db import models


class FirewallHost(models.Model):
    hostname = models.CharField(max_length=128, verbose_name='主机名')
    ip = models.GenericIPAddressField(unique=True, verbose_name='IP')
    os_version = models.CharField(max_length=128, blank=True, default='', verbose_name='操作系统')
    department = models.CharField(max_length=128, blank=True, default='', verbose_name='部门')
    ansible_group = models.CharField(max_length=128, default='windows', verbose_name='Ansible分组')
    firewall_status = models.CharField(max_length=20, default='unknown',
        choices=(('on','已开启'),('off','已关闭'),('partial','部分开启'),('unknown','未知')), verbose_name='防火墙状态')
    profiles_detail = models.JSONField(default=dict, blank=True, verbose_name='Profile详情')
    is_online = models.BooleanField(default=True, verbose_name='在线')
    last_collection_time = models.DateTimeField(null=True, blank=True, verbose_name='最近采集时间')
    last_ansible_status = models.CharField(max_length=20, blank=True, default='', verbose_name='Ansible状态')
    enabled = models.BooleanField(default=True, verbose_name='纳入管理')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '防火墙主机'
        verbose_name_plural = '防火墙主机'
        indexes = [models.Index(fields=['firewall_status']), models.Index(fields=['department'])]

    def __str__(self):
        return f'{self.hostname}({self.ip})'


class FirewallEvent(models.Model):
    host = models.ForeignKey(FirewallHost, on_delete=models.CASCADE, related_name='events')
    timestamp = models.DateTimeField(verbose_name='事件时间')
    action = models.CharField(max_length=10, choices=(('DROP','DROP'),('ALLOW','ALLOW')))
    protocol = models.CharField(max_length=10, default='TCP')
    direction = models.CharField(max_length=10, blank=True, default='')  # inbound/outbound
    src_ip = models.CharField(max_length=64, blank=True, default='')
    src_port = models.IntegerField(null=True, blank=True)
    dst_ip = models.CharField(max_length=64, blank=True, default='')
    dst_port = models.IntegerField(null=True, blank=True)
    process_name = models.CharField(max_length=255, blank=True, default='')
    process_path = models.CharField(max_length=500, blank=True, default='')
    pid = models.IntegerField(null=True, blank=True)
    service_name = models.CharField(max_length=255, blank=True, default='')
    event_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = '防火墙事件'
        verbose_name_plural = '防火墙事件'
        constraints = [models.UniqueConstraint(fields=['host','event_hash'], name='uniq_host_eventhash')]
        indexes = [models.Index(fields=['host','timestamp']), models.Index(fields=['action','timestamp']),
                   models.Index(fields=['dst_port']), models.Index(fields=['dst_ip']), models.Index(fields=['timestamp'])]

    def __str__(self):
        return f'{self.host_id} {self.timestamp} {self.action}'


class FirewallRule(models.Model):
    host = models.ForeignKey(FirewallHost, on_delete=models.CASCADE, related_name='rules')
    rule_name = models.CharField(max_length=255, verbose_name='规则名')
    display_name = models.CharField(max_length=255, blank=True, default='')
    direction = models.CharField(max_length=10, default='Outbound')   # Inbound/Outbound
    action = models.CharField(max_length=10, default='Allow')         # Allow/Block
    protocol = models.CharField(max_length=10, default='TCP')
    program = models.CharField(max_length=500, blank=True, default='')
    service_name = models.CharField(max_length=255, blank=True, default='')
    local_address = models.CharField(max_length=255, default='Any')
    local_port = models.CharField(max_length=100, blank=True, default='')
    remote_address = models.CharField(max_length=255, default='Any')
    remote_port = models.CharField(max_length=100, blank=True, default='')
    profile = models.CharField(max_length=50, default='Any')
    enabled = models.BooleanField(default=True)
    source = models.CharField(max_length=20, default='imported',
        choices=(('auto','自动生成'),('request','申请审批'),('manual','人工创建'),('imported','采集同步')))
    risk_level = models.CharField(max_length=10, default='medium',
        choices=(('low','低风险'),('medium','中风险'),('high','高风险')))
    status = models.CharField(max_length=20, default='active',
        choices=(('active','生效中'),('pending_deploy','待下发'),('deploy_failed','下发失败'),
                 ('recycle_candidate','待回收'),('recycled','已回收'),('deleted','已删除')))
    fingerprint = models.CharField(max_length=64, db_index=True)
    hit_count = models.IntegerField(default=0)
    last_hit_time = models.DateTimeField(null=True, blank=True)
    expire_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '防火墙规则'
        verbose_name_plural = '防火墙规则'
        constraints = [models.UniqueConstraint(fields=['host','rule_name'], name='uniq_host_rulename')]
        indexes = [models.Index(fields=['host','fingerprint']), models.Index(fields=['status']), models.Index(fields=['expire_at'])]

    def __str__(self):
        return self.rule_name


class FirewallRuleRequest(models.Model):
    host = models.ForeignKey(FirewallHost, on_delete=models.CASCADE, related_name='rule_requests')
    application = models.CharField(max_length=255, verbose_name='应用名称')
    program = models.CharField(max_length=500, blank=True, default='')
    direction = models.CharField(max_length=10, default='Outbound')
    protocol = models.CharField(max_length=10, default='TCP')
    remote_address = models.CharField(max_length=255, default='Any')
    remote_port = models.CharField(max_length=100, blank=True, default='')
    reason = models.TextField(verbose_name='申请原因')
    risk_level = models.CharField(max_length=10, default='medium',
        choices=(('low','低风险'),('medium','中风险'),('high','高风险')))
    status = models.CharField(max_length=20, default='pending',
        choices=(('pending','待审核'),('approved','已批准'),('rejected','已驳回'),
                 ('deployed','已下发'),('deploy_failed','下发失败')))
    applicant = models.CharField(max_length=100)
    reviewer = models.CharField(max_length=100, blank=True, default='')
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reject_reason = models.TextField(blank=True, default='')
    is_temporary = models.BooleanField(default=False)
    expire_days = models.IntegerField(default=30)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '规则申请'
        verbose_name_plural = '规则申请'

    def __str__(self):
        return f'{self.application}({self.applicant})'


class AnsibleTaskRecord(models.Model):
    task_ref = models.CharField(max_length=64, unique=True)   # uuid4 hex
    name = models.CharField(max_length=128)
    playbook = models.CharField(max_length=255)
    target_hosts = models.TextField(blank=True, default='')
    status = models.CharField(max_length=20, default='pending',
        choices=(('pending','待执行'),('running','执行中'),('success','成功'),('failed','失败'),('timeout','超时')))
    initiated_by = models.CharField(max_length=100, blank=True, default='system')
    output = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = 'Ansible任务记录'
        verbose_name_plural = 'Ansible任务记录'

    def __str__(self):
        return f'{self.name}({self.task_ref})'


class FirewallAuditLog(models.Model):
    username = models.CharField(max_length=100)
    host = models.ForeignKey(FirewallHost, null=True, blank=True, on_delete=models.SET_NULL)
    action = models.CharField(max_length=50)   # enable_firewall/disable_firewall/create_rule/delete_rule/approve/reject/collect/recycle/sync_hosts
    object_repr = models.CharField(max_length=255, blank=True, default='')
    old_value = models.JSONField(null=True, blank=True)
    new_value = models.JSONField(null=True, blank=True)
    ansible_task_ref = models.CharField(max_length=64, blank=True, default='')
    result = models.CharField(max_length=20, default='success')   # success/failed
    detail = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = '审计日志'
        verbose_name_plural = '审计日志'

    def __str__(self):
        return f'{self.username} {self.action}'


class CommunicationRelation(models.Model):
    host = models.ForeignKey(FirewallHost, on_delete=models.CASCADE, related_name='communications')
    program = models.CharField(max_length=500, blank=True, default='')
    process_name = models.CharField(max_length=255, blank=True, default='')
    protocol = models.CharField(max_length=10, default='TCP')
    remote_ip = models.CharField(max_length=64, blank=True, default='')
    remote_port = models.IntegerField(null=True, blank=True)
    direction = models.CharField(max_length=10, default='outbound')
    risk_level = models.CharField(max_length=10, default='medium')
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    hit_count = models.IntegerField(default=1)

    class Meta:
        verbose_name = '通信关系'
        verbose_name_plural = '通信关系'
        constraints = [models.UniqueConstraint(
            fields=['host','program','protocol','remote_ip','remote_port','direction'],
            name='uniq_comm_relation')]
        indexes = [models.Index(fields=['remote_ip']), models.Index(fields=['remote_port'])]

    def __str__(self):
        return f'{self.host_id} {self.process_name}->{self.remote_ip}:{self.remote_port}'


class DailyFirewallStat(models.Model):
    host = models.ForeignKey(FirewallHost, on_delete=models.CASCADE, related_name='daily_stats')
    date = models.DateField()
    drop_count = models.IntegerField(default=0)
    allow_count = models.IntegerField(default=0)

    class Meta:
        verbose_name = '每日防火墙统计'
        verbose_name_plural = '每日防火墙统计'
        constraints = [models.UniqueConstraint(fields=['host','date'], name='uniq_host_date')]
        indexes = [models.Index(fields=['date'])]

    def __str__(self):
        return f'{self.host_id} {self.date}'
