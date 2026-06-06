from django.db import models


class DomainTask(models.Model):
    STATUS_CHOICES = (
        ('pending_approval', '待审批'),
        ('approved', '已批准'),
        ('rejected', '已驳回'),
        ('pending', '待执行'),
        ('running', '执行中'),
        ('success', '成功'),
        ('partial_success', '部分成功'),
        ('failed', '失败'),
    )

    applicant = models.CharField(max_length=100, verbose_name='申请人')
    domain = models.CharField(max_length=200, verbose_name='域名')
    target_ip = models.GenericIPAddressField(verbose_name='目标IP')
    target_port = models.IntegerField(verbose_name='目标端口')
    reason = models.TextField(verbose_name='申请原因', blank=True, default='')

    # Approval fields (same pattern as resize)
    approval_status = models.CharField(max_length=20, choices=(
        ('pending', '待审批'),
        ('approved', '管理员批准'),
        ('rejected', '已驳回'),
    ), default='pending', verbose_name='审批状态')
    approved_by = models.CharField(max_length=100, null=True, blank=True, verbose_name='审批人')
    approved_at = models.DateTimeField(null=True, blank=True, verbose_name='审批时间')
    reject_reason = models.TextField(null=True, blank=True, verbose_name='驳回原因')

    # Execution status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending_approval', verbose_name='任务状态')
    result = models.TextField(null=True, blank=True, verbose_name='执行结果')

    # Detailed execution results
    dns_status = models.BooleanField(default=False, verbose_name='DNS配置')
    ssl_status = models.BooleanField(default=False, verbose_name='SSL证书')
    nginx_proxy_status = models.BooleanField(default=False, verbose_name='反向代理')
    nginx_upstream_status = models.BooleanField(default=False, verbose_name='负载均衡')

    create_time = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')
    finish_time = models.DateTimeField(null=True, blank=True, verbose_name='完成时间')

    class Meta:
        verbose_name = '域名配置任务'
        verbose_name_plural = '域名配置任务'
        ordering = ['-id']

    def __str__(self):
        return f'{self.domain} -> {self.target_ip}:{self.target_port}'
