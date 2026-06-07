from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models


class DiskResizeTask(models.Model):

    STATUS_CHOICES = (
        ('pending_approval', '待审批'),
        ('approved', '已批准'),
        ('rejected', '已驳回'),
        ('pending', '待执行'),
        ('running', '执行中'),
        ('success', '成功'),
        ('failed', '失败'),
    )

    applicant = models.CharField(
        max_length=100, verbose_name='申请人'
    )

    vm_ip = models.GenericIPAddressField(
        verbose_name='虚拟机IP'
    )

    # disk_key: vCenter 磁盘唯一标识
    # 格式: "scsi{controllerKey}:{unitNumber}"
    # 例如: "scsi1000:0", "scsi1000:1"
    disk_key = models.CharField(
        max_length=50,
        verbose_name='磁盘标识',
        help_text='vCenter SCSI 磁盘标识',
        default=''
    )

    disk_label = models.CharField(
        max_length=100,
        verbose_name='磁盘标签',
        help_text='vCenter 磁盘显示名称',
        default=''
    )

    drive_letter = models.CharField(
        max_length=1, verbose_name='盘符',
        blank=True, default=''
    )

    current_size = models.IntegerField(
        verbose_name='当前大小(GB)'
    )

    add_size = models.IntegerField(
        verbose_name='扩容大小(GB)'
    )

    reason = models.TextField(
        verbose_name='申请原因'
    )

    # 审批相关字段
    approval_status = models.CharField(
        max_length=20,
        choices=(
            ('pending', '待审批'),
            ('auto_approved', '自动批准'),
            ('approved', '管理员批准'),
            ('rejected', '已驳回'),
        ),
        default='pending',
        verbose_name='审批状态'
    )

    approved_by = models.CharField(
        max_length=100,
        null=True, blank=True,
        verbose_name='审批人'
    )

    approved_at = models.DateTimeField(
        null=True, blank=True,
        verbose_name='审批时间'
    )

    reject_reason = models.TextField(
        null=True, blank=True,
        verbose_name='驳回原因'
    )

    # 执行状态
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending_approval',
        verbose_name='任务状态'
    )

    result = models.TextField(
        null=True, blank=True,
        verbose_name='执行结果'
    )

    create_time = models.DateTimeField(
        auto_now_add=True,
        verbose_name='创建时间'
    )

    finish_time = models.DateTimeField(
        null=True, blank=True,
        verbose_name='完成时间'
    )

    class Meta:
        verbose_name = '磁盘扩容任务'
        verbose_name_plural = '磁盘扩容任务'
        ordering = ['-id']

    def __str__(self):
        return f'{self.vm_ip} - {self.disk_label or self.drive_letter}'

    @property
    def needs_approval(self):
        """判断是否需要人工审批: 虚拟机磁盘>200GB 需要审批，<=200GB 自动批准"""
        return self.current_size > 200


class DomainTask(models.Model):

    applicant = models.CharField(
        max_length=100, verbose_name='申请人'
    )

    domain = models.CharField(
        max_length=255, unique=True, verbose_name='域名'
    )

    backend_ip = models.GenericIPAddressField(
        verbose_name='后端IP地址'
    )

    port = models.IntegerField(
        verbose_name='后端端口',
        validators=[MinValueValidator(1), MaxValueValidator(65535)]
    )

    reason = models.TextField(
        verbose_name='申请原因'
    )

    # 审批字段
    approval_status = models.CharField(
        max_length=20,
        choices=(
            ('pending', '待审批'),
            ('approved', '已批准'),
            ('rejected', '已驳回'),
        ),
        default='pending',
        verbose_name='审批状态'
    )

    approved_by = models.CharField(
        max_length=100, null=True, blank=True, verbose_name='审批人'
    )

    approved_at = models.DateTimeField(
        null=True, blank=True, verbose_name='审批时间'
    )

    reject_reason = models.TextField(
        null=True, blank=True, verbose_name='驳回原因'
    )

    # 执行状态
    STATUS_CHOICES = (
        ('pending_approval', '待审批'),
        ('approved', '已批准'),
        ('rejected', '已驳回'),
        ('pending', '待执行'),
        ('running', '执行中'),
        ('success', '成功'),
        ('failed', '失败'),
    )

    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='pending_approval', verbose_name='任务状态'
    )

    result = models.TextField(
        null=True, blank=True, verbose_name='执行结果'
    )

    create_time = models.DateTimeField(
        auto_now_add=True, verbose_name='创建时间'
    )

    finish_time = models.DateTimeField(
        null=True, blank=True, verbose_name='完成时间'
    )

    class Meta:
        verbose_name = '域名配置任务'
        verbose_name_plural = '域名配置任务'
        ordering = ['-id']

    def __str__(self):
        return f'{self.domain} - {self.applicant}'
