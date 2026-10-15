"""服务器运维模块数据模型：批量远程执行的任务、每台机器的结果、问答留痕。

为什么单独建 app 而不是塞进 opsanalysis：opsanalysis 的红线是"全程只读，绝不
关机/重启/停服务/改配置"，本模块的定位恰恰相反——它就是用来下发变更命令的。
两者混在一个 app 里，"只读"这句承诺就没有边界可言了。分开之后 opsanalysis
不 import serverops 的任何东西，它的只读保证不被本模块削弱；本模块则复用
平台既有的两个执行收口（ssh_exec / execlog），不另起一套通道。

三张表的分工：
  ServerOpsJob        一次批量执行：谁发的、为什么发、发给哪些机器、判成几级风险、
                      以及【实际下发到控制机的完整命令串】（resolved_command）。
                      只存用户原文是不够的——出事时要能回答"ansible 到底收到了什么"。
  ServerOpsHostResult 每台机器的 rc/stdout/stderr。批量执行必须能逐台交代，
                      "60 台里有 3 台失败"这种结论不能只有一个汇总数字。
  ChatMessage         运维问答窗的一问一答。模型没有执行能力，只产出命令文本；
                      落库是为了能回看、能追问，也为了审计"谁问过什么"。
"""
from django.db import models


class ServerOpsJob(models.Model):
    """一次批量远程执行。状态机仿 firewall.AnsibleTaskRecord / opsanalysis.AnalysisTask。"""

    OS_TYPES = (('linux', 'Linux'), ('windows', 'Windows'))
    # shell=Linux bash；powershell=Windows 且强制走 -EncodedCommand（见 services/runner.py）；
    # win_cmd=Windows 原文直送 cmd.exe，给坚持要用 netsh/wmic 原生命令的人
    MODES = (('shell', 'Linux Shell'),
             ('powershell', 'Windows PowerShell'),
             ('win_cmd', 'Windows CMD'))
    TIERS = (('L1', 'L1 只读'), ('L2', 'L2 变更'), ('L3', 'L3 危险'))
    STATUSES = (('pending', '待执行'), ('running', '执行中'),
                ('success', '全部成功'), ('partial', '部分成功'),
                ('failed', '全部失败'), ('aborted', '已中止'))

    os_type = models.CharField(max_length=16, choices=OS_TYPES, default='linux',
                               verbose_name='目标系统')
    mode = models.CharField(max_length=16, choices=MODES, default='shell',
                            verbose_name='执行方式')
    command = models.TextField(verbose_name='命令原文(用户输入)')
    resolved_command = models.TextField(
        blank=True, default='',
        verbose_name='实际下发的完整命令')

    tier = models.CharField(max_length=4, choices=TIERS, default='L2',
                            db_index=True, verbose_name='风险等级')
    # 判级依据（命中了哪些危险模式、哪些段落、有哪些告警）。判级是交互边界不是
    # 安全边界，故把依据整包存下来：将来有人质疑"这条为什么被判成 L1"时能还原现场。
    tier_detail = models.JSONField(default=dict, blank=True, verbose_name='判级依据')

    targets = models.JSONField(default=list, verbose_name='目标主机')
    inventory = models.CharField(max_length=255, blank=True, default='',
                                 verbose_name='所用inventory')
    become = models.BooleanField(default=False, verbose_name='提权(sudo/become)')
    canary = models.CharField(
        max_length=64, blank=True, default='',
        verbose_name='灰度主机')
    # 整批的墙钟上限。批量下发几十台 Windows（WinRM 握手很慢）时 120s 不够，
    # 但也不能无限等——Celery -P solo 只有一个 worker，卡住就整个平台不动了。
    timeout_sec = models.IntegerField(default=300, verbose_name='超时(秒)')

    status = models.CharField(max_length=16, choices=STATUSES, default='pending',
                              db_index=True, verbose_name='任务状态')
    created_by = models.CharField(max_length=100, default='system', db_index=True,
                                  verbose_name='发起人')
    reason = models.TextField(blank=True, default='', verbose_name='执行原因')

    # 历史列：L3 曾要求手输确认口令，现已取消（见 views.py 约定 2）。
    # 列与 verbose_name 原样保留是为了不产生迁移；新任务一律留空，不再有写入方。
    confirm_token = models.CharField(max_length=16, blank=True, default='',
                                     verbose_name='要求的确认口令')

    ok_count = models.IntegerField(default=0, verbose_name='成功台数')
    failed_count = models.IntegerField(default=0, verbose_name='失败台数')
    unreachable_count = models.IntegerField(default=0, verbose_name='不可达台数')
    skipped_count = models.IntegerField(default=0, verbose_name='跳过台数')

    # ansible 原始输出。JSON callback 解析失败时这是唯一的证据，故必须留存；
    # 解析成功时也留一份，因为"我们解析出来的"和"ansible 说的"不是一回事。
    raw_output = models.TextField(blank=True, default='', verbose_name='ansible原始输出')
    raw_truncated = models.BooleanField(default=False, verbose_name='原始输出是否被截断')
    parsed = models.BooleanField(default=False, verbose_name='是否成功解析出每主机结果')
    error = models.TextField(blank=True, default='', verbose_name='错误信息')

    duration_ms = models.IntegerField(default=0, verbose_name='耗时(毫秒)')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True,
                                      verbose_name='创建时间')
    started_at = models.DateTimeField(null=True, blank=True, verbose_name='开始时间')
    finished_at = models.DateTimeField(null=True, blank=True, verbose_name='结束时间')

    class Meta:
        verbose_name = '服务器运维任务'
        verbose_name_plural = '服务器运维任务'
        ordering = ['-id']
        indexes = [
            models.Index(fields=['tier', 'status'], name='serverops_job_tier_idx'),
            models.Index(fields=['created_by', 'created_at'], name='serverops_job_by_idx'),
        ]

    def __str__(self):
        return '#%s %s %s(%s)' % (self.pk, self.os_type,
                                  (self.command or '')[:40], self.status)

    @property
    def target_count(self):
        return len(self.targets or [])

    @property
    def finished(self):
        return self.status in ('success', 'partial', 'failed', 'aborted')

    @property
    def exec_ref(self):
        """与 sysmanage.ExecLog 的关联键：runner 下发命令时把 task_ref 设成这个值。"""
        return 'serverops:%s' % self.pk

    def exec_logs(self):
        """本次任务在控制机上的执行留痕（含失败的 SSH 连接尝试）。"""
        from sysmanage.models import ExecLog
        return ExecLog.objects.filter(task_ref=self.exec_ref).order_by('id')


class ServerOpsHostResult(models.Model):
    """单台机器的执行结果。

    ordering=['id'] 而不是 ['-id']：灰度(canary)那一台必须先出现在全量结果之前，
    看的人才能按"先试一台、再铺开"的真实顺序读下去。
    """

    PHASES = (('canary', '灰度'), ('full', '全量'))
    # 不设 'changed'：shell / win_shell 模块对任何执行成功的命令都报 changed=true，
    # 拿它当状态只会让每台机器都显示"已变更"，是噪声不是信息。
    STATUSES = (('ok', '成功'), ('failed', '失败'),
                ('unreachable', '不可达'), ('skipped', '已跳过'))

    job = models.ForeignKey(ServerOpsJob, on_delete=models.CASCADE,
                            related_name='host_results', verbose_name='所属任务')
    host = models.CharField(max_length=128, verbose_name='主机')
    phase = models.CharField(max_length=8, choices=PHASES, default='full',
                             verbose_name='执行阶段')
    status = models.CharField(max_length=16, choices=STATUSES, default='failed',
                              db_index=True, verbose_name='结果')
    rc = models.IntegerField(null=True, blank=True, verbose_name='退出码')
    stdout = models.TextField(blank=True, default='', verbose_name='标准输出')
    stdout_bytes = models.IntegerField(default=0, verbose_name='输出总字符数')
    truncated = models.BooleanField(default=False, verbose_name='输出是否被截断')
    stderr = models.TextField(blank=True, default='', verbose_name='错误输出')
    # ansible 的 msg：unreachable（WinRM 连不上）和模块级失败时，真正的原因在这里，
    # 而不在 stdout/stderr。少了这一栏，"不可达"就只剩一个词、无从下手。
    msg = models.TextField(blank=True, default='', verbose_name='ansible消息')
    duration_ms = models.IntegerField(default=0, verbose_name='耗时(毫秒)')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='记录时间')

    class Meta:
        verbose_name = '服务器运维单机结果'
        verbose_name_plural = '服务器运维单机结果'
        ordering = ['id']
        indexes = [
            models.Index(fields=['job', 'status'], name='serverops_hr_job_idx'),
        ]

    def __str__(self):
        return '%s@%s(%s)' % (self.host, self.job_id, self.status)


class ChatMessage(models.Model):
    """运维问答窗的一问一答。

    模型没有执行能力——它给出的命令只是文本，要落到机器上必须回到命令控制台，
    照常走判级/必填原因/留痕。这条边界写死在提示词里（services/chat.py），
    也写在这里：content 永远只是文本，不存在"模型触发了执行"这条路径。
    """

    ROLES = (('user', '提问'), ('assistant', '回答'))
    STATUSES = (('pending', '生成中'), ('done', '完成'), ('failed', '失败'))

    session = models.CharField(max_length=64, db_index=True, verbose_name='会话标识')
    role = models.CharField(max_length=12, choices=ROLES, default='user',
                            verbose_name='角色')
    content = models.TextField(blank=True, default='', verbose_name='内容')
    status = models.CharField(max_length=12, choices=STATUSES, default='done',
                              verbose_name='状态')
    os_type = models.CharField(max_length=16, blank=True, default='',
                               verbose_name='目标系统(提问上下文)')
    host = models.CharField(max_length=128, blank=True, default='',
                            verbose_name='目标主机(提问上下文)')
    ok = models.BooleanField(default=True, verbose_name='是否成功')
    error = models.TextField(blank=True, default='', verbose_name='错误信息')
    model = models.CharField(max_length=128, blank=True, default='', verbose_name='模型')
    latency_ms = models.IntegerField(default=0, verbose_name='耗时(毫秒)')
    created_by = models.CharField(max_length=100, blank=True, default='system',
                                  db_index=True, verbose_name='发起人')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True,
                                      verbose_name='时间')

    class Meta:
        verbose_name = '运维问答记录'
        verbose_name_plural = '运维问答记录'
        ordering = ['id']

    def __str__(self):
        return '%s:%s(%s)' % (self.session, self.role, (self.content or '')[:30])
