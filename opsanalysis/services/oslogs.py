# -*- coding: utf-8 -*-
"""运维分析——操作系统事件日志归一化（只读分析用）。

Windows(Collect-OpsImpact.ps1) 与 Linux(collect_ops_impact.py) 都输出 data.os_logs，
kind 已对齐，本模块把两者统一成分析层可直接使用的形态：
  summarize()  分类计数 + 高影响事件清单 + 纯描述性 notes（影响分析页用）
  select()     只挑"值得进时间线"的事件（故障排查用），可按服务标识过滤
  group()      按 (日志/ID/来源/消息签名) 聚合重复事件，供大模型证据与页面明细使用
  impact_risks() 由 OS 事件推导的风险提示（供影响分析 risks 列表）

红线：本模块只描述"采集到了什么"，绝不下因果结论。调用方若把 OS 事件与故障
窗口并列展示，必须标为 correlation（仅时间关联），不得写成因果。

采集范围有差别：Windows 采 System/Application 两本日志里全部 Critical/Error/Warning
事件（不按事件 ID 白名单挑，Information/Verbose 不采），Linux 不筛级别。
采集器把范围写进 os_logs.level_filter，本模块将其转成 notes 里的一条如实说明——
范围一定要披露，否则"0 条"会被读成"没发生过"。
"""
import logging
import re

logger = logging.getLogger(__name__)

# kind → 中文标签（Windows 与 Linux 采集器共用）
KIND_LABEL = {
    'reboot': '重启/关机',
    'oom': '内存耗尽(OOM)',
    'kernel': '内核错误',
    'service': '服务启停/失败',
    'service_state': '服务状态变更',
    'syslog_err': '系统日志错误',
    'crash': '程序崩溃/挂起',
    'update': '补丁/更新',
    'log_cleared': '日志被清除',
    'auth': '登录/提权',
    'cron': '定时任务',
    'pkg': '软件包变更',
    # 全量按级别采集后新增：ID/provider 都归不进上面任何一类的告警/错误。
    # "归类不出"绝不等于"不重要"，必须有自己的标签，否则页面上会显示成空。
    'other': '其它告警/错误',
}

# 展示优先级：数字越小越靠前（越可能与"服务为什么挂了"相关）
KIND_PRIORITY = {
    'log_cleared': 0, 'oom': 1, 'crash': 2, 'reboot': 3, 'kernel': 4,
    'service': 5, 'syslog_err': 6, 'service_state': 7, 'update': 8,
    'pkg': 9, 'auth': 10, 'cron': 11, 'other': 12,
}

# 无需匹配服务标识也必须上报的 kind（整机级异常，任何服务都可能受影响）
ALWAYS_KINDS = ('log_cleared', 'oom', 'crash', 'reboot', 'kernel')
ALARM_LEVELS = ('Critical', 'Error', 'Warning')

# 失败/异常语义（用来从"服务启停"这类噪声 kind 里挑出真正异常的那几条）
FAIL_HINT = re.compile(
    r'fail|error|crash|terminat|unexpected|timeout|refused|denied|killed'
    r'|异常|失败|错误|拒绝|超时|被终止', re.I)
# 纯数字（端口）与 IP 用边界匹配，避免 80 命中 8080、10.2.20.5 命中 10.2.20.55
_IPISH = re.compile(r'^[\d.]+$')
# 过于宽泛的标识：拿它去匹配等于不过滤，直接忽略
_NOISE_TOKENS = frozenset((
    'system', 'service', 'services', 'server', 'windows', 'linux', 'http', 'https',
    'tcp', 'udp', 'log', 'logs', 'root', 'admin', 'www', 'exe', 'dll', 'com', 'cn',
))
# 聚合签名用：把数字串（PID/端口/句柄/计数）统一成 #，好让"同一类错误"合并成一条
_SIG_NUM = re.compile(r'\d+')
_SIG_WS = re.compile(r'\s+')


def label(kind):
    return KIND_LABEL.get(kind or '', kind or '其它')


def _msg(e):
    return str((e or {}).get('message') or '')


def _kind(e):
    return str((e or {}).get('kind') or '')


def _level(e):
    return str((e or {}).get('level') or '')


def _ts(e):
    return str((e or {}).get('ts') or '')


def clean_tokens(tokens):
    """过滤掉过短/过宽泛的标识，返回小写去重列表。

    纯数字短标识（端口 22/80）保留，靠边界匹配使用；其它标识至少 3 字符，
    否则"命中"等于不过滤，只会把整机噪声当成本服务相关事件。
    """
    out = []
    for t in (tokens or []):
        tl = str(t or '').strip().lower()
        if not tl or tl in _NOISE_TOKENS:
            continue
        if len(tl) < 3 and not tl.isdigit():
            continue
        if tl not in out:
            out.append(tl)
    return out


def _token_hit(message, tokens):
    """返回命中的标识（用于在结论里说明"为什么这条事件与本服务相关"），无命中返回 ''。"""
    if not tokens:
        return ''
    ml = message.lower()
    for tl in tokens:
        if len(tl) < 3 and not (tl.isdigit() or _IPISH.match(tl)):
            continue
        if tl.isdigit() or _IPISH.match(tl):
            if re.search(r'(?<![\d.])%s(?![\d.])' % re.escape(tl), ml):
                return tl
        elif tl in ml:
            return tl
    return ''


def _decorate(e):
    """补上模板直接可用的展示字段（中文分类名 + 归一化时间文本），不修改原字典。

    Windows 的 ts 是 '2026-10-12T16:24:26.3194707+08:00'，Linux 是 '2026-10-12 03:11:22'，
    统一裁到秒并把 T 换成空格，前端无需再处理两种格式。
    """
    item = dict(e)
    item['kind_label'] = label(_kind(e))
    ts = _ts(e)
    item['ts_text'] = ts[:19].replace('T', ' ') if ts else ''
    return item


def sort_events(events):
    """按 kind 重要度升序、同级按时间倒序（稳定排序两步完成），并补展示字段。"""
    evs = [_decorate(e) for e in (events or []) if isinstance(e, dict)]
    evs.sort(key=_ts, reverse=True)
    evs.sort(key=lambda e: KIND_PRIORITY.get(_kind(e), 50))
    return evs


def _counts(os_logs):
    out = {}
    for k, v in ((os_logs or {}).get('counts') or {}).items():
        try:
            out[str(k)] = int(v)
        except (TypeError, ValueError):
            continue
    return out


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def summarize(os_logs, highlight_limit=40, group_limit=60):
    """归一化成展示/分析用的摘要。字段缺失一律给安全默认值，绝不抛出。"""
    o = os_logs if isinstance(os_logs, dict) else {}
    events = [e for e in (o.get('events') or []) if isinstance(e, dict)]
    counts = _counts(o)
    if not counts and events:
        # 采集器没给 counts 时自行统计，保证上层展示不空
        for e in events:
            k = _kind(e)
            counts[k] = counts.get(k, 0) + 1
    try:
        total = int(o.get('total_matched') or 0)
    except (TypeError, ValueError):
        total = 0
    try:
        days = int(o.get('days') or 0)
    except (TypeError, ValueError):
        days = 0
    ordered = sort_events(events)
    s = {
        'available': bool(events or counts),
        'os_type': str(o.get('os_type') or ''),
        'days': days,
        'since': str(o.get('since') or ''),
        'total_matched': total or len(events),
        'returned': len(events),
        'truncated': bool(o.get('truncated')),
        'dropped': _as_int(o.get('dropped')),
        'logs_scanned': [str(x) for x in (o.get('logs_scanned') or [])],
        'level_filter': str(o.get('level_filter') or ''),
        'counts': counts,
        'count_labels': [{'kind': k, 'label': label(k), 'count': v}
                         for k, v in sorted(counts.items(),
                                            key=lambda kv: KIND_PRIORITY.get(kv[0], 50))
                         if v],
        'highlights': ordered[:highlight_limit],
        'errors': [str(x) for x in (o.get('errors') or [])],
        'notes': [],
    }
    rows, _gtotal, gdropped = group(ordered, limit=group_limit)
    s['groups'] = rows
    s['groups_total'] = len(rows) + gdropped
    s['groups_dropped'] = gdropped
    s['notes'] = _notes(s)
    return s


def brief(s):
    """去掉 highlights 的摘要：highlights 体积大，落库(JSONField)时只留计数与 notes。"""
    return {k: v for k, v in (s or {}).items() if k != 'highlights'}


def _notes(s):
    """纯描述性摘要：只说"采到了什么"，不解释"因此怎样"。"""
    n = []
    d = s['days'] or 1
    if s.get('level_filter'):
        # 采集侧筛过范围（Windows 按级别、Linux 按日志源），必须如实说明：
        # 否则"0 条重启/0 条服务状态变更"会被当成"没发生过"，也会把模型带向同一错误结论。
        n.append('采集范围：%s；范围外的事件未采集，未出现不代表未发生。'
                 % s['level_filter'])
    if not s['available']:
        if s['errors']:
            n.append('未采集到近 %d 日操作系统事件日志（原因见下方"采集受限说明"）。' % d)
        else:
            # Windows 只采 Warning+ 后，"安静的机器"会走到这里：不能一律说成采集受限
            n.append('近 %d 日没有采集到符合采集条件的事件'
                     '（可能确实没有，也可能是采集受限，两者无法区分）。' % d)
        return n
    for kind in ('log_cleared', 'oom', 'crash', 'reboot', 'kernel', 'service',
                 'syslog_err', 'update', 'auth', 'cron', 'pkg', 'service_state', 'other'):
        c = s['counts'].get(kind)
        if not c:
            continue
        last = ''
        for e in s['highlights']:
            if _kind(e) == kind and _ts(e):
                last = _ts(e)[:19].replace('T', ' ')
                break
        n.append('近 %d 日「%s」事件 %d 条%s。' % (
            d, label(kind), c, ('，最近一条 %s' % last) if last else ''))
    if s['truncated']:
        n.append('匹配到 %d 条、本次返回 %d 条（已达上限截断%s）；'
                 '如需完整数据请缩小天数或提高采集上限。'
                 % (s['total_matched'], s['returned'],
                    ('，丢弃 %d 条' % s['dropped']) if s.get('dropped') else ''))
    return n


def select(os_logs, tokens=(), limit=20):
    """挑出值得进入故障排查时间线的 OS 事件。返回 (events, dropped)。

    收录规则（宁缺勿滥，避免把整机噪声当成某个服务的故障原因）：
      1) 整机级异常 kind（日志清除/OOM/崩溃/重启/内核错误）——一律收录；
      2) 级别为 Warning 及以上的；
      3) 服务启停类里带失败语义的；
      4) 消息里出现本服务标识（程序名/端口/域名/部署 IP）的——例如
         sudo COMMAND=/bin/systemctl restart <程序名> 这类"人为操作"线索；
      5) 近一日的补丁/更新（变更线索），排在最后，超限时优先被丢弃。
    每条都带 matched 字段说明命中原因，供前端解释"为什么这条与本服务有关"。
    """
    o = os_logs if isinstance(os_logs, dict) else {}
    events = [e for e in (o.get('events') or []) if isinstance(e, dict)]
    toks = clean_tokens(tokens)
    picked = []
    for e in events:
        k, msg, lv = _kind(e), _msg(e), _level(e)
        hit = _token_hit(msg, toks)
        why = ''
        if k in ALWAYS_KINDS:
            why = '整机级异常(%s)' % label(k)
        elif hit:
            why = '命中本服务标识 %s' % hit
        elif lv in ALARM_LEVELS:
            # Windows 侧只采 Warning 及以上，这一条等于"全收"——正是需求：
            # 近一天所有警告/错误都要能进时间线、能喂给大模型。
            # Linux 侧大量事件是合成的 Information 级，仍要靠上面的标识命中才收，
            # "宁缺勿滥"对 Linux 噪声依旧成立。
            why = '%s（级别 %s）' % (label(k), lv)
        elif k in ('service', 'service_state') and FAIL_HINT.search(msg):
            why = '%s 含失败语义' % label(k)
        elif k in ('update', 'pkg'):
            why = '近一日变更(%s)' % label(k)
        if not why:
            continue
        item = dict(e)
        item['matched'] = why
        picked.append(item)
    ordered = sort_events(picked)
    dropped = len(ordered) - limit if limit and len(ordered) > limit else 0
    if limit:
        ordered = ordered[:limit]
    return ordered, max(0, dropped)


_LEVEL_SEVERITY = {'Critical': 0, 'Error': 1, 'Warning': 2}


def _signature(e, width=120):
    """聚合用的消息签名：数字统一成 #、空白压平、截前 width 字。"""
    m = _SIG_NUM.sub('#', _msg(e))
    return _SIG_WS.sub(' ', m).strip()[:width]


def group(events, limit=60, width=120):
    """把重复事件按 (日志, ID, 来源, 消息签名) 聚合。返回 (rows, total, dropped_rows)。

    为什么要聚合：改成"全量按级别采集"后，一天几百上千条告警里绝大多数是同一条在刷屏
    （Disk/4231、Schannel/36888、Time-Service/36 这类）。逐条塞给大模型会瞬间吃光字数
    预算、把真正独有的那条错误挤掉；页面上也没人翻得完。
    聚合后一行 = 一种错误 + 出现次数 + 首末时间 + 一条原文样例，信息密度反而更高，
    而且次数本身就是最有价值的信号（刷 500 次的警告和只出现 1 次的错误，处置优先级不同）。

    排序：先按级别严重度（Critical > Error > Warning），再按次数降序，最后按最近时间降序。
    limit 截断时把丢弃的"种类数"如实返回，调用方必须披露——聚合本身也是一次取舍。
    """
    buckets = {}
    total = 0
    for e in (events or []):
        if not isinstance(e, dict):
            continue
        total += 1
        key = (str(e.get('log') or ''), str(e.get('id') or ''),
               str(e.get('source') or ''), _signature(e, width))
        b = buckets.get(key)
        ts = _ts(e)
        if b is None:
            buckets[key] = b = {
                'log': key[0], 'id': key[1], 'source': key[2], 'signature': key[3],
                'kind': _kind(e), 'level': _level(e), 'count': 0,
                'first_ts': ts, 'last_ts': ts,
                'sample': _msg(e)[:300], 'matched': str(e.get('matched') or ''),
            }
            # 展示层（模板）不做逻辑，中文分类名与可读时间在这里就算好，
            # 免得每个模板各自写过滤器、写漏了就退化成显示英文 kind。
            b['kind_label'] = label(b['kind'])
        b['count'] += 1
        if ts:
            # ts 是 ISO 字符串，同格式下字典序即时间序
            if not b['first_ts'] or ts < b['first_ts']:
                b['first_ts'] = ts
            if not b['last_ts'] or ts > b['last_ts']:
                b['last_ts'] = ts
        if not b['level']:
            b['level'] = _level(e)
        if not b['matched'] and e.get('matched'):
            b['matched'] = str(e.get('matched'))

    # 两次稳定排序实现"级别严重度升序 → 次数降序 → 最近时间降序"。
    # 不用负号反转时间戳字符串：空时间戳在那种写法下会被排到最前，等于假装它最新。
    rows = sorted(buckets.values(), key=lambda r: r['last_ts'], reverse=True)
    rows = sorted(rows, key=lambda r: (_LEVEL_SEVERITY.get(r['level'], 9), -r['count']))
    for r in rows:
        r['first_text'] = r['first_ts'][:19].replace('T', ' ') if r['first_ts'] else '时间不详'
        r['last_text'] = r['last_ts'][:19].replace('T', ' ') if r['last_ts'] else '时间不详'
    dropped_rows = max(0, len(rows) - limit) if limit else 0
    if limit:
        rows = rows[:limit]
    return rows, total, dropped_rows


def impact_risks(s, op_label='操作'):
    """由近 N 日 OS 事件推导影响分析风险提示。

    措辞红线：只陈述"采集到的事实 + 需要注意什么"，绝不把时间先后说成因果。
    """
    risks = []
    if not s.get('available'):
        return risks
    c = s.get('counts') or {}
    d = s.get('days') or 1

    def last_ts(kind):
        for e in s.get('highlights') or []:
            if _kind(e) == kind and _ts(e):
                return _ts(e)[:19].replace('T', ' ')
        return ''

    if c.get('log_cleared'):
        risks.append({'level': '高', 'text':
                      '近 %d 日有 %d 条"事件日志被清除"记录，事后追溯依据可能不完整，'
                      '需确认是否为计划内维护。' % (d, c['log_cleared'])})
    if c.get('oom'):
        risks.append({'level': '高', 'text':
                      '近 %d 日发生 %d 次内存耗尽(OOM)，最近 %s；本机内存已有压力，'
                      '%s会进一步放大服务不可用风险。'
                      % (d, c['oom'], last_ts('oom') or '时间不详', op_label)})
    if c.get('crash'):
        risks.append({'level': '中', 'text':
                      '近 %d 日有 %d 条程序崩溃/挂起记录，最近 %s。'
                      % (d, c['crash'], last_ts('crash') or '时间不详')})
    if c.get('reboot'):
        risks.append({'level': '中', 'text':
                      '近 %d 日已有 %d 条重启/关机记录，最近 %s；请先确认是否处于计划内维护窗口。'
                      % (d, c['reboot'], last_ts('reboot') or '时间不详')})
    if c.get('service'):
        risks.append({'level': '中', 'text':
                      '近 %d 日有 %d 条服务启停/失败记录，%s前建议先核对这些服务当前状态。'
                      % (d, c['service'], op_label)})
    if c.get('kernel'):
        risks.append({'level': '中', 'text':
                      '近 %d 日有 %d 条内核级错误（含 I/O 错误等），%s可能加剧底层异常。'
                      % (d, c['kernel'], op_label)})
    if c.get('update') or c.get('pkg'):
        n = (c.get('update') or 0) + (c.get('pkg') or 0)
        # 不说"安装过"：Windows 只采 Warning 及以上，这里的记录其实是安装失败
        risks.append({'level': '低', 'text':
                      '近 %d 日有 %d 条更新/软件包变更记录；若同期出现异常，可纳入时间线核对'
                      '（仅时间先后，不构成因果结论）。' % (d, n)})
    if s.get('truncated'):
        risks.append({'level': '低', 'text':
                      'OS 事件已达采集上限（匹配 %d 条、返回 %d 条），本结论基于部分数据。'
                      % (s.get('total_matched') or 0, s.get('returned') or 0)})
    if s.get('errors'):
        risks.append({'level': '低', 'text':
                      '部分日志源未能读取（%d 项），存在盲区：%s'
                      % (len(s['errors']), '；'.join(s['errors'][:3]))})
    return risks
