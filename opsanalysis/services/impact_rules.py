"""运维分析——影响分析规则引擎。

输入：采集快照(snapshot) + 模拟操作类型(op_type) + 目标IP。
输出：结构化 analysis，严格区分"技术影响范围"与"业务用户影响范围"，
并对每条结论标注性质。红线：只做只读分析，绝不触发任何执行；
无认证/业务日志时明确声明"无法评估业务用户影响"，不臆断用户数、不下因果断言。

snapshot 结构对 Windows / Linux 采集器保持一致（见 collectors），故规则与 OS 无关。
"""
import logging

from opsanalysis.services import oslogs

logger = logging.getLogger(__name__)

# 模拟操作类型 → 风险级别与文案（全部仅分析，不执行）
OP_META = {
    'shutdown': ('高危', '关机'),
    'restart': ('高危', '重启'),
    'stop_service': ('中危', '停止服务'),
}

# 页面/证据里最多展开多少个服务。取 300 是为了"实际等于不截断"（普通服务器几百个服务），
# 只作为极端情况的保险阀；一旦真的截断，必须把丢弃条数写进 analysis 并在页面披露。
SERVICES_SHOWN = 300


def _as_int(v, default=0):
    """取整；取不到就退回 default（用于"采集端没回报总数"的老快照）。"""
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _reverse_services(ip: str):
    """反查 ServiceRegistry：server_ips 含该 IP 的应用（承载的对外服务/域名）。"""
    from opsanalysis.models import ServiceRegistry
    hits = []
    for s in ServiceRegistry.objects.all():
        ips = s.server_ips or []
        if isinstance(ips, list) and ip in [str(x) for x in ips]:
            hits.append({
                'name': s.canonical_name,
                'domains': s.domains or [],
                'port': s.port,
                'supervisor_program': s.supervisor_program,
                'status': s.status,
            })
    return hits


def analyze_impact(snapshot: dict, op_type: str, ip: str) -> dict:
    snapshot = snapshot or {}
    basic = snapshot.get('basic') or {}
    users = snapshot.get('users') or {}
    conns = snapshot.get('connections') or {}
    listeners = snapshot.get('listeners') or []
    services = snapshot.get('services') or []
    supervisor = snapshot.get('supervisor') or {}

    level, op_label = OP_META.get(op_type, ('中危', op_type or '未知操作'))

    # ---- 采集到的可量化事实（技术影响范围）----
    established = conns.get('established') or []
    # established 只是样本（采集端上限 MaxConn=200 且不排序），真实连接数用采集端回报的
    # established_total / by_state['Established']，否则会把 200 当成"这台机只有 200 个连接"。
    est_count = _as_int(conns.get('established_total'),
                        _as_int((conns.get('by_state') or {}).get('Established'),
                                len(established)))
    by_state = conns.get('by_state') or {}
    remote_top = conns.get('remote_ip_top') or []
    session_count = users.get('session_count') or 0
    rdp_active = users.get('rdp_active') or 0
    logged_on = users.get('logged_on') or []

    listen_ports = sorted({int(x.get('local_port')) for x in listeners
                           if x.get('local_port') is not None})
    detected_apps = []
    for p in (supervisor.get('ini_programs') or []):
        detected_apps.append({'name': p.get('name'), 'port': p.get('port'),
                              'stdout_logfile': p.get('stdout_logfile')})
    for p in (supervisor.get('programs') or []):
        if p.get('port'):
            detected_apps.append({'name': f"pid:{p.get('pid')}", 'port': p.get('port'),
                                  'stdout_logfile': ''})

    # ---- 间接影响：本机承载的对外应用/域名（来自关联登记表）----
    related_services = _reverse_services(ip)
    affected_domains = sorted({d for s in related_services for d in (s.get('domains') or [])})

    # 服务列表绝不能按采集顺序硬切：WMI 大致按名字字母序返回，U*/UFIDA* 一类用友服务
    # 正好排在尾部，曾被 services[:60] 整片切掉——页面写"运行 60 个服务"、大模型也只看到
    # 60 个，于是双双得出"这台机没有 U8"的错误结论。
    # 现在先按"是否与本机已登记应用相关"排序再截断，且把真实总数与丢弃条数如实报出去。
    svc_tokens = {str(t).lower() for s in related_services
                  for t in ([s.get('name'), s.get('supervisor_program')]
                            + list(s.get('domains') or []))
                  if t and len(str(t)) > 2}

    def _svc_rank(sv):
        low = ('%s %s' % (sv.get('name') or '', sv.get('display_name') or '')).lower()
        return 0 if any(t in low for t in svc_tokens) else 1

    ordered_services = sorted(services, key=_svc_rank)   # 稳定排序：组内保持采集原序
    shown_services = ordered_services[:SERVICES_SHOWN]
    services_dropped = len(services) - len(shown_services)

    direct = []
    if listen_ports:
        direct.append(f'本机监听 {len(listen_ports)} 个端口：{_fmt_ports(listen_ports)}，'
                      f'{op_label}后这些端口将不可用')
    if services:
        direct.append(f'本机运行 {len(services)} 个服务，{op_label}将全部中断')
    if detected_apps:
        apps_desc = _join_limited(
            detected_apps,
            fmt=lambda a: (f"{a.get('name')}(:{a.get('port')})"
                           if a.get('port') else str(a.get('name'))))
        direct.append(f'检测到应用进程：{apps_desc}')
    if est_count:
        direct.append(f'当前有 {est_count} 个 ESTABLISHED 活动连接，{_op_verb(op_type)}将强制断开')
    if session_count or rdp_active:
        direct.append(f'当前有 {session_count} 个活跃会话（其中 RDP {rdp_active} 个）、'
                      f'登录用户 {len(logged_on)} 个，将受到影响')

    indirect = []
    if related_services:
        names = _join_limited(related_services, fmt=lambda s: s['name'])
        indirect.append(f'本机承载已登记应用：{names}')
    if affected_domains:
        indirect.append(f'以下对外域名指向本机，{op_label}后将无法访问：'
                        f'{_join_limited(affected_domains)}')
    if not indirect:
        indirect.append('未在关联登记表中找到指向本机的对外应用（可能尚未登记，见服务关联登记）')

    # ---- 风险提示 ----
    risks = []
    risks.append({'level': level,
                  'text': f'"{op_label}"为{level}操作。本系统第一阶段仅提供模拟分析，不会执行任何实际操作。'})
    if session_count or rdp_active:
        risks.append({'level': '高', 'text': f'存在 {session_count} 个活跃会话，直接{op_label}会中断在线用户。'})
    if est_count >= 1:
        risks.append({'level': '中', 'text': f'存在 {est_count} 个活动连接，来源 IP {len(remote_top)} 个。'})
    if affected_domains:
        risks.append({'level': '高', 'text': f'本机承载 {len(affected_domains)} 个对外域名，{op_label}将造成业务不可访问。'})
    for d in (basic.get('disks') or []):
        if d.get('percent') is not None and float(d['percent']) >= 90:
            risks.append({'level': '中', 'text': f"磁盘 {d.get('device')} 使用率 {d.get('percent')}%，需关注。"})

    # ---- 近 N 日操作系统事件（只读采集；Windows/Linux 的 data.os_logs 结构一致）----
    os_log = oslogs.summarize(snapshot.get('os_logs'))
    risks.extend(oslogs.impact_risks(os_log, op_label))

    # ---- 业务用户影响：无认证/业务日志时明确不可评估 ----
    business = {
        'assessable': False,
        'note': '系统未接入业务认证/访问日志，无法评估真实业务用户数与影响面；'
                '以上仅为技术影响范围（连接数/会话/端口/进程/域名映射）。',
        'affected_domains': affected_domains,
        'active_connections': est_count,
        'active_sessions': session_count,
        'logged_on_users': logged_on,
        'top_remote_ips': [{'ip': r.get('ip'), 'count': r.get('count')} for r in remote_top[:15]],
    }

    return {
        'op_type': op_type,
        'op_label': op_label,
        'target_ip': ip,
        'basic': {
            'hostname': basic.get('hostname'),
            'os': basic.get('os'),
            'cpu_percent': basic.get('cpu_percent'),
            'mem_percent': basic.get('mem_percent'),
            'mem_total_mb': basic.get('mem_total_mb'),
            'uptime_seconds': basic.get('uptime_seconds'),
            'boot_time': basic.get('boot_time'),
            'disks': basic.get('disks') or [],
        },
        'technical_impact': {
            'direct': direct,
            'indirect': indirect,
            'listen_ports': listen_ports,
            'running_services': [
                {'name': s.get('name'), 'display_name': s.get('display_name'),
                 'status': s.get('status'), 'start_mode': s.get('start_mode'),
                 'related': _svc_rank(s) == 0}
                for s in shown_services
            ],
            'running_services_total': len(services),
            'running_services_dropped': services_dropped,
            # 非运行状态的服务（采集端已全量回报）：一台机上"自动启动却处于停止"的服务
            # 往往就是故障本身，以前只采 Running，这类线索完全不可见。
            'stopped_services': [
                {'name': s.get('name'), 'display_name': s.get('display_name'),
                 'status': s.get('status'), 'start_mode': s.get('start_mode')}
                for s in (snapshot.get('services_other') or [])[:SERVICES_SHOWN]
            ],
            'stopped_services_total': _as_int(snapshot.get('services_other_total'),
                                              len(snapshot.get('services_other') or [])),
            'stopped_services_dropped': _as_int(snapshot.get('services_other_dropped')),
            'processes_total': _as_int(snapshot.get('processes_total'),
                                       len(snapshot.get('processes') or [])),
            'processes_truncated': bool(snapshot.get('processes_truncated')),
            'related_apps': detected_apps,
            'related_services': related_services,
            'active_connections': {
                'total_tcp': conns.get('tcp_total'),
                'established_count': est_count,
                'established_sample_truncated': bool(conns.get('established_truncated')),
                'by_state': by_state,
                'udp_total': conns.get('udp_total'),
                'established_sample': established[:100],
                'remote_ip_top': [{'ip': r.get('ip'), 'count': r.get('count')} for r in remote_top[:20]],
            },
            'active_sessions': {
                'session_count': session_count,
                'rdp_active': rdp_active,
                'logged_on': logged_on,
                'sessions': users.get('sessions') or [],
            },
        },
        'business_impact': business,
        'risks': risks,
        'os_logs': {
            'available': os_log['available'],
            'os_type': os_log['os_type'],
            'days': os_log['days'],
            'since': os_log['since'],
            'total_matched': os_log['total_matched'],
            'returned': os_log['returned'],
            'truncated': os_log['truncated'],
            'dropped': os_log.get('dropped') or 0,
            'logs_scanned': os_log.get('logs_scanned') or [],
            'level_filter': os_log['level_filter'],
            'counts': os_log['counts'],
            'count_labels': os_log['count_labels'],
            'notes': os_log['notes'],
            'errors': os_log['errors'],
            'highlights': os_log['highlights'],
            # 聚合视图：全量按级别采集后事件可能上千条，逐条展示既看不过来也喂不进模型。
            # groups 一行 = 一种错误 + 次数 + 首末时间，groups_dropped 是被截掉的种类数。
            'groups': os_log.get('groups') or [],
            'groups_total': os_log.get('groups_total') or 0,
            'groups_dropped': os_log.get('groups_dropped') or 0,
        },
    }


def _op_verb(op_type: str) -> str:
    return {'shutdown': '关机', 'restart': '重启', 'stop_service': '停服务'}.get(op_type, '操作')


def _fmt_ports(ports, limit=30) -> str:
    """端口列表格式化。超过 limit 必须把总数写进结果：
    上游文案是"本机监听 N 个端口：<这里>"，N 与列出的个数对不上时，
    读的人会以为采集漏了，其实是这里截断的——那属于静默截断，不允许。"""
    return _join_limited(ports, limit=limit, sep=', ')


def _join_limited(items, limit=20, fmt=str, sep='、') -> str:
    """拼接列表，超出上限就在末尾写明"共 N 个，仅列前 M"。"""
    items = list(items)
    shown = items[:limit]
    s = sep.join(fmt(x) for x in shown)
    if len(items) > len(shown):
        s += f' …（共 {len(items)} 个，仅列前 {limit}）'
    return s
