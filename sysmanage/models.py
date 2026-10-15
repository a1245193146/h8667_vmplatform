"""系统管理模块数据模型：执行留痕 + 可前端编辑的配置 + 配置变更审计。

为什么单独建一个 app：这三张表服务的对象是"整个平台"而不是某个业务模块，
firewall/antivirus/opsanalysis 都要往里写。挂在任一业务 app 下都会造成
反向依赖（业务模块 import 另一个业务模块的 models），故独立成 sysmanage。

两条设计红线：
- 留痕绝不能拖垮主流程：写日志失败只 warning，不向上抛（见 services/execlog.py）。
- 凭据类配置只写不读：is_secret=True 的值永不出现在页面/接口/日志里，
  列表只显示掩码。隔离内网允许服务端持有明文凭据，但不允许它经前端外泄。
"""
from django.db import models


class ExecLog(models.Model):
    """远程执行留痕：凡经 ssh_exec / run_playbook 下发的命令都落一条。

    与 firewall.AnsibleTaskRecord 的分工：AnsibleTaskRecord 是"一次 playbook
    任务"的业务记录（含状态机与全量 output），本表是"一条命令"的技术留痕，
    覆盖面更广（含 ping 探活、inventory 读取、SFTP 同步这些不走 playbook 的动作），
    用 task_ref 与前者关联。两者不合并：业务记录要长期保留且被多处查询，
    技术留痕量大、需要独立的保留期与清理策略。
    """

    KINDS = (
        ('playbook', 'Ansible Playbook'),
        ('ansible', 'Ansible 临时命令'),
        ('probe', '探活/探测'),
        ('shell', '控制机命令'),
        ('sync', '脚本同步(SFTP)'),
    )
    STATUSES = (
        ('success', '成功'),
        ('failed', '失败'),
        ('timeout', '超时'),
        ('error', '异常'),
    )

    module = models.CharField(
        max_length=32, default='system', db_index=True,
        verbose_name='来源模块')
    kind = models.CharField(max_length=16, default='shell', choices=KINDS,
                            verbose_name='命令类型')
    target = models.CharField(max_length=255, blank=True, default='',
                              verbose_name='目标主机/清单')
    command = models.TextField(verbose_name='命令原文')
    rc = models.IntegerField(null=True, blank=True, verbose_name='退出码')
    status = models.CharField(max_length=16, default='success', choices=STATUSES,
                              db_index=True, verbose_name='结果')
    stdout = models.TextField(blank=True, default='', verbose_name='输出(头尾留存)')
    stderr_tail = models.TextField(blank=True, default='', verbose_name='错误输出尾部')
    stdout_bytes = models.IntegerField(default=0, verbose_name='输出总字符数')
    truncated = models.BooleanField(default=False, verbose_name='输出是否被截断')
    duration_ms = models.IntegerField(default=0, verbose_name='耗时(毫秒)')
    task_ref = models.CharField(max_length=64, blank=True, default='', db_index=True,
                                verbose_name='关联Ansible任务')
    initiated_by = models.CharField(max_length=100, blank=True, default='system',
                                    verbose_name='发起人')
    note = models.CharField(max_length=255, blank=True, default='', verbose_name='备注')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True,
                                      verbose_name='执行时间')

    class Meta:
        verbose_name = '执行留痕'
        verbose_name_plural = '执行留痕'
        ordering = ['-id']
        indexes = [
            models.Index(fields=['module', '-created_at']),
            models.Index(fields=['kind', '-created_at']),
        ]

    def __str__(self):
        return f'{self.module}/{self.kind} {self.command[:40]}'


class SysConfig(models.Model):
    """前端可编辑的配置项：key 形如 OPS_LLM.TEMPERATURE，点号对应 settings 里的层级。

    读取口径见 services/config.py：先查本表，查不到回退 settings。
    这样现有的 settings.XXX 写法一处都不用改，可逐键迁移。
    """

    GROUPS = (
        ('llm', '大模型'),
        ('ops', '运维分析'),
        ('ansible', 'Ansible/控制机'),
        ('av', '病毒检测'),
        ('fw', '防火墙'),
        ('report', '报表'),
        ('system', '平台'),
    )

    key = models.CharField(max_length=128, unique=True, verbose_name='配置键')
    value = models.JSONField(null=True, blank=True, verbose_name='配置值')
    group = models.CharField(max_length=32, default='system', choices=GROUPS,
                             db_index=True, verbose_name='分组')
    desc = models.TextField(blank=True, default='', verbose_name='说明')
    value_type = models.CharField(
        max_length=16, default='str',
        choices=(('str', '文本'), ('int', '整数'), ('float', '小数'),
                 ('bool', '开关'), ('list', '列表'), ('intlist', '整数列表'),
                 ('json', 'JSON')),
        verbose_name='值类型')
    is_secret = models.BooleanField(default=False, verbose_name='凭据(只写不读)')
    updated_by = models.CharField(max_length=100, blank=True, default='',
                                  verbose_name='最后修改人')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='最后修改时间')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='创建时间')

    class Meta:
        verbose_name = '系统配置'
        verbose_name_plural = '系统配置'
        ordering = ['group', 'key']

    def __str__(self):
        return self.key


class ConfigAuditLog(models.Model):
    """配置变更审计：长期保留，只记"值的摘要"不记明文（凭据尤其不能落审计）。"""

    username = models.CharField(max_length=100, verbose_name='操作人')
    key = models.CharField(max_length=128, db_index=True, verbose_name='配置键')
    action = models.CharField(
        max_length=16, default='update',
        choices=(('create', '新增'), ('update', '修改'),
                 ('delete', '删除'), ('reset', '恢复默认')),
        verbose_name='动作')
    old_display = models.CharField(max_length=255, blank=True, default='',
                                   verbose_name='原值摘要')
    new_display = models.CharField(max_length=255, blank=True, default='',
                                   verbose_name='新值摘要')
    result = models.CharField(max_length=20, default='success', verbose_name='结果')
    detail = models.TextField(blank=True, default='', verbose_name='说明')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True,
                                      verbose_name='时间')

    class Meta:
        verbose_name = '配置审计'
        verbose_name_plural = '配置审计'
        ordering = ['-id']

    def __str__(self):
        return f'{self.username} {self.action} {self.key}'
