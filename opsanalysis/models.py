"""运维分析模块数据模型。

设计原则（与需求一致）：
- 第一阶段一切只读：只做"采集 + 关联 + 分析 + 时间线"，绝不触发关机/重启等危险操作；
  "模拟操作"只产出分析结论，与任何执行动作严格分离。
- 复用 firewall.FirewallHost 作为服务器资产（Windows/Linux 均纳入，用 os_version /
  ansible_group 区分），不另建 Server 表，避免与既有主机同步逻辑漂移。
- 采集到的进程/端口/连接等明细不逐一建表，统一存进 AnalysisResult.snapshot 的 JSON，
  按任务天然留历史；只把"服务关联登记"这一命门单独建表（ServiceRegistry）。
- 大模型辅助分析另建 LlmAnalysisRecord 存全量留痕（证据+各批输出+最终意见），
  analysis['llm'] 只留精简摘要与 record_id，便于结果页轮询与历史复用。
- 时间线严格区分：已确认事实(fact) / 时间关联(correlation) / 推测(inference) /
  建议(suggestion)，绝不把"同时发生"当成"因果关系"。
"""
from django.conf import settings
from django.db import models

from firewall.models import FirewallHost


class ServiceRegistry(models.Model):
    """服务关联登记表：把"同一应用在各系统里的不同名字"收敛成一条统一记录。

    关联线索以 ip:port 为主键：nginx upstream 的 ip:port ↔ supervisor 配置里的
    监听端口 ↔ Jenkins job config.xml 的部署目标+command。自动发现产出 candidate，
    人工确认后转 confirmed。此表只读采集服务器信息，不改动任何服务器。
    """
    canonical_name = models.CharField(max_length=128, unique=True, verbose_name='应用统一名')
    aliases = models.JSONField(default=list, blank=True, verbose_name='各系统别名')
    domains = models.JSONField(default=list, blank=True, verbose_name='对外域名')
    server_ips = models.JSONField(default=list, blank=True, verbose_name='部署服务器IP')
    os_type = models.CharField(
        max_length=16, default='unknown',
        choices=(('windows', 'Windows'), ('linux', 'Linux'), ('unknown', '未知')),
        verbose_name='操作系统类型')
    port = models.IntegerField(null=True, blank=True, verbose_name='服务端口')
    supervisor_program = models.CharField(max_length=255, blank=True, default='', verbose_name='Supervisor程序名')
    jenkins_job = models.CharField(max_length=255, blank=True, default='', verbose_name='Jenkins Job')
    git_project = models.CharField(max_length=255, blank=True, default='', verbose_name='Git项目')
    app_log_path = models.CharField(max_length=500, blank=True, default='', verbose_name='应用日志路径')
    nginx_access_log = models.CharField(max_length=500, blank=True, default='', verbose_name='Nginx访问日志')
    nginx_error_log = models.CharField(max_length=500, blank=True, default='', verbose_name='Nginx错误日志')

    status = models.CharField(
        max_length=16, default='candidate',
        choices=(('candidate', '待确认'), ('confirmed', '已确认')),
        verbose_name='关联状态')
    source = models.CharField(
        max_length=16, default='manual',
        choices=(('auto', '自动发现'), ('manual', '人工登记')),
        verbose_name='来源')
    confidence = models.TextField(blank=True, default='', verbose_name='匹配依据')
    remark = models.TextField(blank=True, default='', verbose_name='备注')

    # 最近一次"自动发现"确认其部署服务器在线的时间（仅按主机可达性判定，见
    # discovery.mark_services_online）。长期停用的应用不会被刷新，从而在列表里
    # 自然显示"很久没在线"。为空表示从未探测到在线。
    last_online_at = models.DateTimeField(null=True, blank=True, verbose_name='最近在线时间')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '服务关联登记'
        verbose_name_plural = '服务关联登记'
        indexes = [
            models.Index(fields=['status'], name='opsanalysis_sr_status_idx'),
        ]

    def __str__(self):
        return self.canonical_name

    @property
    def supervisor_web_urls(self):
        """每台部署服务器(server_ips)上都跑着 supervisor Web(:9999)，各自监控本机服务。
        故按 IP 逐台生成面板/日志地址，返回列表：
            [{'ip': '10.2.20.211', 'home': 'http://10.2.20.211:9999',
              'log': 'http://10.2.20.211:9999/logtail/<程序名>'}, ...]
        无 supervisor 程序名时 log 为空串（只保留 home）。面板用 HTTP Basic Auth，
        浏览器首次访问自行弹登录框，故 URL 内不含凭据。scheme/端口可在
        settings.OPS_DISCOVERY_CONFIG 用 SUPERVISOR_WEB_SCHEME / SUPERVISOR_WEB_PORT 覆盖。"""
        cfg = getattr(settings, 'OPS_DISCOVERY_CONFIG', {}) or {}
        scheme = (cfg.get('SUPERVISOR_WEB_SCHEME') or 'http').split('://')[0].rstrip(':')
        port = cfg.get('SUPERVISOR_WEB_PORT') or 9999
        out = []
        for ip in (self.server_ips or []):
            ip = str(ip).strip()
            if not ip:
                continue
            home = '%s://%s:%s' % (scheme, ip, port)
            log = ('%s/logtail/%s' % (home, self.supervisor_program)
                   if self.supervisor_program else '')
            out.append({'ip': ip, 'home': home, 'log': log})
        return out

    @property
    def supervisor_log_url(self):
        """兼容单值用法：返回第一台部署服务器的 logtail 地址；无程序名/无 IP 时空串。
        多机部署请改用 supervisor_web_urls 逐台渲染。"""
        for e in self.supervisor_web_urls:
            if e['log']:
                return e['log']
        return ''

    @property
    def supervisor_web_url(self):
        """兼容单值用法：返回第一台部署服务器的 supervisor 面板首页；无 IP 时空串。"""
        for e in self.supervisor_web_urls:
            return e['home']
        return ''

    @property
    def online_ago_text(self):
        """距最近一次被发现在线多久（人类可读）；从未探测到返回'未知'。"""
        if not self.last_online_at:
            return '未知'
        from django.utils import timezone
        secs = int((timezone.now() - self.last_online_at).total_seconds())
        if secs < 0:
            secs = 0
        if secs < 60:
            return '刚刚'
        if secs < 3600:
            return '%d分钟前' % (secs // 60)
        if secs < 86400:
            return '%d小时前' % (secs // 3600)
        return '%d天前' % (secs // 86400)

    @property
    def online_recent(self):
        """最近在线是否在 15 分钟内（列表着色用）。从未探测到 → False。"""
        if not self.last_online_at:
            return False
        from django.utils import timezone
        return (timezone.now() - self.last_online_at).total_seconds() <= 900


class AnalysisTask(models.Model):
    """一次分析任务（影响分析 / 服务排查）。仿 firewall.AnsibleTaskRecord 的状态机。"""
    kind = models.CharField(
        max_length=20, default='impact',
        choices=(('impact', '服务器操作影响分析'), ('troubleshoot', '服务故障辅助排查')),
        verbose_name='分析类型')
    target = models.CharField(max_length=255, blank=True, default='', verbose_name='目标(IP或应用名)')
    host = models.ForeignKey(
        FirewallHost, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='ops_analysis_tasks', verbose_name='目标服务器')
    service = models.ForeignKey(
        ServiceRegistry, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='analysis_tasks', verbose_name='目标服务')

    params = models.JSONField(default=dict, blank=True, verbose_name='任务参数')
    status = models.CharField(
        max_length=20, default='pending',
        choices=(('pending', '待执行'), ('running', '执行中'),
                 ('success', '成功'), ('failed', '失败')),
        verbose_name='任务状态')
    initiated_by = models.CharField(max_length=100, blank=True, default='system', verbose_name='发起人')
    error = models.TextField(blank=True, default='', verbose_name='错误信息')

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = '运维分析任务'
        verbose_name_plural = '运维分析任务'
        ordering = ['-id']
        indexes = [
            models.Index(fields=['kind', 'status'], name='opsanalysis_at_kind_idx'),
        ]

    def __str__(self):
        return f'{self.kind}:{self.target}({self.status})'


class AnalysisResult(models.Model):
    """一次任务的采集快照 + 分析结论（均以 JSON 存，不拆细表）。"""
    task = models.OneToOneField(
        AnalysisTask, on_delete=models.CASCADE, related_name='result')
    snapshot = models.JSONField(default=dict, blank=True, verbose_name='采集快照')
    analysis = models.JSONField(default=dict, blank=True, verbose_name='分析结论')
    collected_at = models.DateTimeField(null=True, blank=True, verbose_name='采集完成时间')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = '运维分析结果'
        verbose_name_plural = '运维分析结果'

    def __str__(self):
        return f'result of task#{self.task_id}'


class TimelineEvent(models.Model):
    """服务排查时间线：把各子系统信息统一成时间轴，并标注证据类型。"""
    task = models.ForeignKey(
        AnalysisTask, on_delete=models.CASCADE, related_name='timeline_events')
    ts = models.DateTimeField(null=True, blank=True, db_index=True, verbose_name='事件时间')
    source = models.CharField(max_length=30, blank=True, default='', verbose_name='来源系统')
    event_type = models.CharField(max_length=50, blank=True, default='', verbose_name='事件类型')
    summary = models.CharField(max_length=500, blank=True, default='', verbose_name='摘要')
    evidence = models.JSONField(default=dict, blank=True, verbose_name='证据')
    kind = models.CharField(
        max_length=16, default='fact',
        choices=(('fact', '已确认事实'), ('correlation', '时间关联'),
                 ('inference', '推测原因'), ('suggestion', '建议检查')),
        verbose_name='结论类型')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = '分析时间线事件'
        verbose_name_plural = '分析时间线事件'
        ordering = ['ts']
        indexes = [
            models.Index(fields=['task', 'ts'], name='opsanalysis_te_task_idx'),
        ]

    def __str__(self):
        return f'{self.ts} {self.source} {self.event_type}'


class LlmAnalysisRecord(models.Model):
    """一次大模型辅助分析的完整留痕：送进去的证据 + 每批输出 + 最终意见。

    为什么单独建表，而不是只塞 analysis['llm']：
    - analysis 是 JSONField，重跑一次就整体覆盖，历史结论无法回溯对比；
    - 证据正文动辄上万字，留在 analysis 里会被结果页 3 秒轮询接口反复传输；
    - 后续要做"同一服务多次分析横向对比""同类故障经验沉淀"，需要能按任务/时间
      检索的结构化行，而不是埋在 JSON 深处。

    红线：本表只存"模型的意见 + 当时送给它的证据副本"，属参考资料；
    绝不覆盖 snapshot/analysis 里的真实采集数据（facts/timeline 原样保留），
    也不得被当成结论直接展示——页面始终标注"非结论，需人工核实"。
    """
    task = models.ForeignKey(
        AnalysisTask, on_delete=models.CASCADE, related_name='llm_records',
        verbose_name='分析任务')
    scope = models.CharField(
        max_length=20, default='troubleshoot',
        choices=(('impact', '服务器操作影响分析'), ('troubleshoot', '服务故障辅助排查')),
        verbose_name='场景')
    status = models.CharField(
        max_length=20, default='running',
        choices=(('running', '进行中'), ('success', '成功'),
                 ('failed', '失败'), ('disabled', '未启用')),
        verbose_name='状态')

    model = models.CharField(max_length=128, blank=True, default='', verbose_name='模型名')
    temperature = models.FloatField(null=True, blank=True, verbose_name='温度')
    prompt_version = models.CharField(max_length=32, blank=True, default='', verbose_name='提示词版本')
    base_url = models.CharField(max_length=255, blank=True, default='', verbose_name='模型接口地址')

    evidence = models.TextField(blank=True, default='', verbose_name='证据全文（多批以分隔线拼接）')
    batches = models.JSONField(default=list, blank=True, verbose_name='分批明细（段落/字数/输出/耗时）')
    output = models.TextField(blank=True, default='', verbose_name='模型最终意见（多批时为汇总稿）')
    error = models.TextField(blank=True, default='', verbose_name='错误/警告信息')

    prompt_chars = models.IntegerField(default=0, verbose_name='提示词总字数')
    evidence_chars = models.IntegerField(default=0, verbose_name='证据字数')
    batch_count = models.IntegerField(default=0, verbose_name='批次数')
    latency_ms = models.IntegerField(default=0, verbose_name='总耗时(毫秒)')

    requested_by = models.CharField(max_length=100, blank=True, default='', verbose_name='发起人')
    requested_at = models.DateTimeField(null=True, blank=True, verbose_name='发起时间')
    finished_at = models.DateTimeField(null=True, blank=True, verbose_name='完成时间')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = '大模型辅助分析记录'
        verbose_name_plural = '大模型辅助分析记录'
        ordering = ['-id']
        indexes = [
            models.Index(fields=['task', 'scope'], name='opsanalysis_llm_task_idx'),
        ]

    def __str__(self):
        return f'llm#{self.id} {self.scope}:{self.task_id}({self.status})'

    @property
    def output_chars(self):
        return len(self.output or '')
