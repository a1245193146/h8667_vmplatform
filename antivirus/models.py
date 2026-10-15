"""Windows Defender 病毒检测与隔离模块数据模型。

设计原则（与需求一致）：
- Defender 负责检测与隔离，本模块只读取其结果、记录留痕、管理人工复核；
- 不直接操作 Defender 内部隔离目录，"恢复/清理"仅针对本系统留存到 UNC 的副本；
- 断点续采：AvCollectState 记录每台主机已处理的 Defender 事件 RecordId 水位，
  服务器/采集程序重启后从水位继续，避免遗漏事件；
- 去重红线：unique(host, event_hash) + bulk_create(ignore_conflicts)，重试幂等。

主机清单复用 firewall.FirewallHost（已由 inventory 同步全部 Windows 主机），
避免重复建表与同步逻辑漂移。
"""
from django.db import models

from antivirus.defender_resources import resolve_resource
from firewall.models import FirewallHost


class AvCollectState(models.Model):
    """每台主机的 Defender 事件采集水位（断点续采，重启不丢）。"""
    host = models.OneToOneField(
        FirewallHost, on_delete=models.CASCADE, related_name='av_collect_state')
    # 已成功入库的最大 Event Log RecordId；下次只采 RecordId > 该值的事件
    last_record_id = models.BigIntegerField(default=0, verbose_name='已采集RecordId水位')
    last_collect_time = models.DateTimeField(null=True, blank=True, verbose_name='最近采集时间')
    last_status = models.CharField(max_length=20, blank=True, default='', verbose_name='最近采集状态')
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '病毒采集水位'
        verbose_name_plural = '病毒采集水位'

    def __str__(self):
        return f'{self.host_id} record_id={self.last_record_id}'


class AvDetection(models.Model):
    """一条病毒检测事件（Defender 检出 → 本系统统一记录）。"""
    host = models.ForeignKey(
        FirewallHost, on_delete=models.CASCADE, related_name='av_detections')

    # ---- 检测信息 ----
    detected_at = models.DateTimeField(verbose_name='检测时间', db_index=True)
    original_path = models.CharField(max_length=500, blank=True, default='', verbose_name='原始文件路径')
    # Defender 原始资源链（压缩包嵌套感染时为 "<容器>;file:_<容器>->内层->...->感染文件"）；
    # original_path 只存最外层磁盘容器（默认展示 + 留存复制源），此处完整留档供取证。
    resource_path = models.TextField(blank=True, default='', verbose_name='Defender原始资源链')
    file_name = models.CharField(max_length=255, blank=True, default='', verbose_name='文件名')
    file_size = models.BigIntegerField(null=True, blank=True, verbose_name='文件大小(字节)')
    sha256 = models.CharField(max_length=64, blank=True, default='', db_index=True, verbose_name='SHA256')
    threat_name = models.CharField(max_length=255, blank=True, default='', verbose_name='Defender威胁名称')
    threat_type = models.CharField(max_length=100, blank=True, default='', verbose_name='威胁类型')
    severity = models.CharField(max_length=50, blank=True, default='', verbose_name='严重级别')
    category = models.CharField(max_length=100, blank=True, default='', verbose_name='威胁分类')
    action_taken = models.CharField(max_length=50, blank=True, default='', verbose_name='Defender处置结果')
    process_name = models.CharField(max_length=500, blank=True, default='', verbose_name='触发进程')
    defender_threat_id = models.CharField(max_length=64, blank=True, default='', verbose_name='Defender威胁ID')
    detection_source = models.CharField(max_length=30, default='eventlog', verbose_name='数据来源')
    defender_record_id = models.BigIntegerField(null=True, blank=True, verbose_name='Defender事件RecordId')

    # ---- 隔离留存（本系统 UNC 副本，非 Defender 内部目录）----
    quarantine_path = models.CharField(max_length=500, blank=True, default='', verbose_name='隔离文件保存路径')
    quarantine_status = models.CharField(
        max_length=20, default='pending',
        choices=(('pending', '未留存'), ('preserved', '已留存'),
                 ('unavailable', '原文件不可得'), ('restored', '已恢复'),
                 ('cleaned', '已清理')),
        verbose_name='隔离留存状态')

    # ---- 人工复核流程 ----
    status = models.CharField(
        max_length=20, default='pending_review',
        choices=(('pending_review', '待复核'), ('confirmed_malicious', '确认恶意'),
                 ('false_positive', '误报'), ('restored', '已恢复'),
                 ('cleaned', '已清理')),
        verbose_name='当前状态')
    reviewer = models.CharField(max_length=100, blank=True, default='', verbose_name='操作人员')
    reviewed_at = models.DateTimeField(null=True, blank=True, verbose_name='操作时间')
    remark = models.TextField(blank=True, default='', verbose_name='备注')

    # ---- 去重 / 时间戳 ----
    event_hash = models.CharField(max_length=64, verbose_name='事件指纹')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '病毒检测事件'
        verbose_name_plural = '病毒检测事件'
        constraints = [
            models.UniqueConstraint(
                fields=['host', 'event_hash'], name='uniq_av_host_eventhash'),
        ]
        indexes = [
            models.Index(fields=['detected_at'], name='antivirus_a_detecte_idx'),
            models.Index(fields=['status'], name='antivirus_a_status_idx'),
            models.Index(fields=['threat_name'], name='antivirus_a_threat_idx'),
            models.Index(fields=['host', 'detected_at'], name='antivirus_a_host_dt_idx'),
        ]

    def __str__(self):
        return f'{self.host_id} {self.threat_name} {self.file_name}'

    # 展示用：把可能残留的 %%NNN 资源引用还原成可读文本。
    # 新数据入库时已还原；这里的属性兜底早期已入库、按 RecordId 水位不会被重采的旧行
    # （如 action_taken='%%809' → 'Quarantine'）。忠实还原，未收录编号原样返回。
    @property
    def action_taken_display(self):
        return resolve_resource(self.action_taken) or ''

    @property
    def severity_display(self):
        return resolve_resource(self.severity) or ''

    @property
    def category_display(self):
        return resolve_resource(self.category) or ''

    @property
    def threat_type_display(self):
        return resolve_resource(self.threat_type) or ''


class AvAuditLog(models.Model):
    """病毒模块操作留痕：采集/留存/确认恶意/误报/恢复/清理 全部记录。"""
    username = models.CharField(max_length=100)
    detection = models.ForeignKey(
        AvDetection, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='audit_logs')
    action = models.CharField(max_length=50)  # collect/preserve/confirm/false_positive/restore/cleanup
    object_repr = models.CharField(max_length=255, blank=True, default='')
    old_status = models.CharField(max_length=20, blank=True, default='')
    new_status = models.CharField(max_length=20, blank=True, default='')
    reason = models.TextField(blank=True, default='')
    ansible_task_ref = models.CharField(max_length=64, blank=True, default='')
    result = models.CharField(max_length=20, default='success')  # success/failed
    detail = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = '病毒模块操作日志'
        verbose_name_plural = '病毒模块操作日志'

    def __str__(self):
        return f'{self.username} {self.action}'
