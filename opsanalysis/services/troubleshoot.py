"""运维分析——服务故障辅助排查（只读）。

输入一个已登记服务（ServiceRegistry）或域名/IP，只读关联：
  应用服务器状态(端口/进程/uptime) + supervisor 状态 + Nginx access/error 日志窗口
  + DNS 解析 + Jenkins 最近构建，汇聚成统一时间线。

红线（务必遵守）：
- 全程只读，绝不重启/停止/部署任何东西；
- 时间线严格区分四类，绝不把"同时发生"当成"因果关系"：
    fact        已确认事实（直接观测到的）
    correlation 时间关联（仅"时间上接近/同时段"，显式声明非因果）
    inference   推测原因（措辞用"推测/可能/需确认"）
    suggestion  建议检查（可执行的下一步排查动作）
"""
import base64
import html
import logging
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta

from django.conf import settings
from django.utils import timezone

from opsanalysis.services.collectors import (
    collect_impact_snapshot, detect_os_type,
)
from opsanalysis.services.discovery import _run, collect_supervisor
from opsanalysis.services import oslogs

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_MIN = 30
LOGTAIL_TAIL_LINES = 3
# 每台部署机进入时间线的 OS 事件"逐条明细"上限。
# 采集侧已改为全量收 Warning 及以上，一天几百条是常态；时间线是给人看的，
# 逐条铺开没人翻得完，所以这里只保留最相关的若干条，其余用 os_logs.groups
# （一类错误 + 次数 + 首末时间）补全，两者都进大模型证据——条数上限不等于信息丢失。
OS_EVENT_LIMIT = 60


# -------------------------------------------------- supervisor logtail 服务端抓取

def _fetch_logtail_lines(ip, program, cfg, tail_n=LOGTAIL_TAIL_LINES):
    """服务端直接抓 supervisor 面板的 logtail 页面，取日志最后 tail_n 行。

    为什么走服务端而不是登录目标机 tail 文件：logtail 由 supervisor 按其**当前**配置
    解析真实日志路径，不受 ServiceRegistry 里可能过期的登记路径影响；面板账号已在
    settings 配置（隔离内网允许硬编码），故这里带 HTTP Basic Auth 直接 GET。

    返回 dict：{'lines': [...], 'url': ..., 'ok': bool, 'note': str}。任何异常都吞掉，
    只记 note——logtail 是"锦上添花"的展示，绝不能因为它失败而中断整个排查采集。
    """
    scheme = cfg.get('SUPERVISOR_WEB_SCHEME') or 'http'
    port = cfg.get('SUPERVISOR_WEB_PORT') or 9999
    user = cfg.get('SUPERVISOR_WEB_USER') or ''
    pwd = cfg.get('SUPERVISOR_WEB_PASS') or ''
    url = '%s://%s:%s/logtail/%s' % (scheme, ip, port, program)
    res = {'lines': [], 'url': url, 'ok': False, 'note': ''}
    if not program:
        res['note'] = '无 supervisor 程序名，跳过 logtail 抓取'
        return res
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'vmp-ops/1.0'})
        if user:
            token = base64.b64encode(
                ('%s:%s' % (user, pwd)).encode('utf-8')).decode('ascii')
            req.add_header('Authorization', 'Basic %s' % token)
        with urllib.request.urlopen(req, timeout=8) as resp:
            ctype = (resp.headers.get('Content-Type') or '').lower()
            raw = resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        res['note'] = 'logtail HTTP %s（%s）' % (e.code, url)
        return res
    except Exception as e:
        res['note'] = 'logtail 抓取失败：%s（%s）' % (e.__class__.__name__, url)
        return res

    # supervisor /logtail/ 返回 HTML（日志正文在 <pre> 里）；某些版本/直连返回纯文本。
    text = raw
    if 'html' in ctype or '<pre' in raw.lower():
        m = re.search(r'<pre[^>]*>(.*?)</pre>', raw, re.DOTALL | re.IGNORECASE)
        if m:
            text = html.unescape(m.group(1))
        else:
            text = html.unescape(re.sub(r'<[^>]+>', '', raw))
    lines = [ln.rstrip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln.strip()][-tail_n:]
    res['lines'] = lines
    res['ok'] = True
    res['note'] = ('已抓取（%d 行）' % len(lines)) if lines else '页面为空（无日志内容）'
    return res



# ------------------------------------------------------------------ 时间处理

def _aware(dt):
    if dt is None:
        return None
    if timezone.is_naive(dt):
        try:
            return timezone.make_aware(dt, timezone.get_current_timezone())
        except Exception:
            return dt
    return dt


def _parse_ts(s):
    if not s:
        return None
    sv = str(s).strip()
    # 先按整串试，再按前 19 字符试：nginx access 的 dd/Mon/yyyy:HH:MM:SS 恰好 20 字符，
    # 只截 19 位会把秒截断导致解析失败。
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%d/%b/%Y:%H:%M:%S'):
        for cand in (sv, sv[:19]):
            try:
                return datetime.strptime(cand, fmt)
            except (ValueError, TypeError):
                continue
    # 带毫秒/时区的 ISO
    try:
        return datetime.fromisoformat(sv.replace('Z', ''))
    except Exception:
        return None


def _ev(ts, source, event_type, summary, evidence, kind):
    return {'ts': _aware(ts) if isinstance(ts, datetime) else _aware(_parse_ts(ts)),
            'source': source, 'event_type': event_type,
            'summary': summary[:500], 'evidence': evidence or {}, 'kind': kind}


def _iso(dt):
    """datetime → ISO 字符串（含时区偏移），供 JSONField 存储；其它值原样返回。"""
    if isinstance(dt, datetime):
        return dt.isoformat()
    return dt


def _jsonable(ev):
    """把事件里的 ts 转成 JSON 可序列化字符串（内部排序仍用 datetime，落库前才转）。
    TimelineEvent.ts 是 DateTimeField，Django 能把 ISO 字符串 to_python 回 datetime。"""
    out = dict(ev)
    out['ts'] = _iso(ev.get('ts'))
    return out


# ------------------------------------------------------------------ 采集

def gather(svc, window_min=DEFAULT_WINDOW_MIN, initiated_by='system'):
    """只读采集一个服务的所有排查信号。svc 可为 ServiceRegistry 或 None(仅域名/IP)。"""
    cfg = getattr(settings, 'OPS_DISCOVERY_CONFIG', {}) or {}
    server_ips = list(svc.server_ips or []) if svc else []
    domains = list(svc.domains or []) if svc else []
    port = svc.port if svc else None
    program = (svc.supervisor_program if svc else '') or ''
    jenkins_job = (svc.jenkins_job if svc else '') or ''
    app_log_path = (svc.app_log_path if svc else '') or ''
    # supervisor 的 stdout_logfile 常写成 /opt/logs/%(program_name)s_deubg.log，
    # 由 supervisor 启动时展开；Linux 发现脚本登记的是未展开原文，导致该路径在磁盘
    # 上"不存在"、误报应用日志缺失。这里用已知 program 就地展开，修复存量登记行。
    app_log_path_configured = app_log_path
    if program and '%(program_name)s' in app_log_path:
        app_log_path = app_log_path.replace('%(program_name)s', program)

    # OS 事件按"本服务标识"过滤：程序名/服务名/端口/域名/jenkins job（每机再叠加其 IP）。
    # 目的：整机一天上千条日志里，只把与本服务相关的挑进时间线，避免噪声淹没结论。
    os_tokens = oslogs.clean_tokens(
        [program, svc.canonical_name if svc else '', port, jenkins_job] + domains)

    g = {
        'service': {
            'canonical_name': svc.canonical_name if svc else '',
            'domains': domains, 'server_ips': server_ips, 'port': port,
            'supervisor_program': program, 'jenkins_job': jenkins_job,
            'app_log_path': app_log_path,
            'app_log_path_configured': app_log_path_configured,
            # 每台部署机的 supervisor 面板/logtail 地址（http://ip:9999/logtail/<程序名>），
            # 供排查页直接点开看应用日志——比探测日志文件更省事。URL 不含凭据，
            # 面板用 HTTP Basic Auth，浏览器首次访问自弹登录框。纯内存计算，可 JSON 序列化。
            'supervisor_web_urls': (svc.supervisor_web_urls if svc else []),
            'nginx_access_log': (svc.nginx_access_log if svc else '') or '',
            'nginx_error_log': (svc.nginx_error_log if svc else '') or '',
            'os_type': svc.os_type if svc else 'unknown',
        },
        'window_min': window_min,
        'nginx_host': cfg.get('NGINX_HOST') or '',
        'servers': [],
        'nginx_logs': None,
        'dns': [],
        'jenkins': None,
        'errors': [],
    }

    # ---- 应用服务器状态 ----
    for ip in server_ips:
        entry = {'ip': ip, 'os_type': detect_os_type(ip), 'port_listening': None,
                 'listen_ports': [], 'app_process': False, 'uptime_seconds': None,
                 'boot_time': '', 'cpu_percent': None, 'mem_percent': None,
                 'supervisor_status': '', 'collected_at': None, 'reachable': False,
                 'app_log': {}, 'logtail': {},
                 'os_logs': {}, 'os_events': [], 'os_events_dropped': 0}
        try:
            snap = collect_impact_snapshot(ip, initiated_by=initiated_by,
                                           app_log_path=app_log_path)
            if snap.get('ok'):
                entry['reachable'] = True
                data = snap.get('data') or {}
                entry['collected_at'] = data.get('collected_at')
                entry['app_log'] = data.get('app_log') or {}
                # 近 N 日操作系统事件（重启/OOM/崩溃/服务失败/补丁/sudo 等，只读采集）
                raw_os = data.get('os_logs') or {}
                entry['os_logs'] = oslogs.brief(oslogs.summarize(raw_os))
                entry['os_events'], entry['os_events_dropped'] = oslogs.select(
                    raw_os, tokens=os_tokens + [ip], limit=OS_EVENT_LIMIT)
                listeners = data.get('listeners') or []
                entry['listen_ports'] = sorted({int(x['local_port']) for x in listeners
                                                if x.get('local_port') is not None})
                if port:
                    if entry['listen_ports']:
                        entry['port_listening'] = int(port) in entry['listen_ports']
                    else:
                        # 采集到的监听端口为空——正常在线主机总会有若干监听端口
                        # (Windows 135/445/5985、Linux 22 等)，全空几乎必然是采集不完整，
                        # 不能据此断定"未监听"，标记为未知(None)，避免把采集缺失误报成故障。
                        entry['port_listening'] = None
                        g['errors'].append(
                            '%s 未采集到任何监听端口，端口 %s 状态未知'
                            '（采集可能不完整，非"未监听"结论；可在该机 netstat -ano 复核）'
                            % (ip, port))
                basic = data.get('basic') or {}
                entry['uptime_seconds'] = basic.get('uptime_seconds')
                entry['boot_time'] = basic.get('boot_time')
                entry['cpu_percent'] = basic.get('cpu_percent')
                entry['mem_percent'] = basic.get('mem_percent')
                # 应用进程存在性（启发式：命令行含 program 名或 :port）
                needle = program or (str(port) if port else '')
                for p in (data.get('processes') or []):
                    blob = '%s %s' % (p.get('name', ''), p.get('command_line', ''))
                    if needle and needle.lower() in blob.lower():
                        entry['app_process'] = True
                        break
                # supervisor 运行状态：Linux 走 supervisorctl 权威状态
                if entry['os_type'] == 'linux':
                    progs = collect_supervisor(ip, initiated_by=initiated_by)
                    for p in progs:
                        if program and p.get('name') == program:
                            entry['supervisor_status'] = (p.get('status') or '').upper()
                            break
                    if not entry['supervisor_status'] and progs:
                        # program 名没匹配上，但记录一下有无 RUNNING 的候选
                        entry['supervisor_status'] = ''
                else:
                    sup = (snap.get('data') or {}).get('supervisor') or {}
                    names = [x.get('name') for x in (sup.get('ini_programs') or [])]
                    if program and program in names:
                        entry['supervisor_status'] = 'CONFIGURED'  # Windows 仅确认已配置
            else:
                g['errors'].append('采集 %s 失败: %s' % (ip, snap.get('error')))
        except Exception as e:
            g['errors'].append('采集 %s 异常: %s' % (ip, e))
        # 服务端抓 supervisor logtail（带面板账号）——不受登记路径过期影响，
        # 供"已确认事实"展示程序当前日志末行；失败只记 note，绝不影响主采集。
        if program:
            entry['logtail'] = _fetch_logtail_lines(ip, program, cfg)
        g['servers'].append(entry)

    # ---- Nginx 日志窗口 ----
    nginx_host = cfg.get('NGINX_HOST')
    acc = g['service']['nginx_access_log']
    err = g['service']['nginx_error_log']
    if nginx_host and (acc or err):
        # nginx error_log 通常是全局共享的（所有服务写同一份），直接统计
        # connection refused / connect() failed 会把"别的服务"的报错也算进来，
        # 对单服务排障失去意义。用本服务的「后端 IP:端口 + 域名」做归属过滤，
        # 只统计 upstream/server/host 命中本服务标识的错误行；同时脚本仍返回
        # total_all_services 作全局对照。
        match_tokens = set()
        for ip in server_ips:
            match_tokens.add('%s:%s' % (ip, port) if port else ip)
        for d in domains:
            if d:
                match_tokens.add(d)
        try:
            g['nginx_logs'] = _run('ops_probe_nginx_logs.yml', nginx_host, extra={
                'access_logs': acc, 'error_logs': err, 'window_min': window_min,
                'match_tokens': ','.join(sorted(match_tokens)),
            }, initiated_by=initiated_by, timeout=120)
        except Exception as e:
            g['errors'].append('nginx 日志探测异常: %s' % e)

    # ---- DNS 解析（探测机复用 nginx 主机；未配置则跳过）----
    probe_host = cfg.get('PROBE_HOST') or nginx_host
    if probe_host and domains:
        dns_servers = cfg.get('DNS_SERVERS') or ''
        for d in domains:
            try:
                r = _run('ops_probe_dns.yml', probe_host,
                         extra={'domain': d, 'dns_servers': dns_servers},
                         initiated_by=initiated_by, timeout=60)
                if r:
                    g['dns'].append(r)
            except Exception as e:
                g['errors'].append('DNS 探测异常 %s: %s' % (d, e))

    # ---- Jenkins 最近构建 ----
    jenkins_host = cfg.get('JENKINS_HOST')
    if jenkins_host and jenkins_job:
        try:
            g['jenkins'] = _run('ops_probe_jenkins_builds.yml', jenkins_host, extra={
                'jenkins_job': jenkins_job,
                'jenkins_jobs_dir': cfg.get('JENKINS_JOBS_DIR') or '',
            }, initiated_by=initiated_by, timeout=90)
        except Exception as e:
            g['errors'].append('jenkins 构建探测异常: %s' % e)

    return g


# ------------------------------------------------------------------ 时间线

def _fmt_dur(sec):
    try:
        sec = int(float(sec))
    except (ValueError, TypeError):
        return '?'
    if sec < 60:
        return '%d秒' % sec
    if sec < 3600:
        return '%d分钟' % (sec // 60)
    if sec < 86400:
        return '%d小时' % (sec // 3600)
    return '%d天' % (sec // 86400)


def build_timeline(g):
    """把采集结果转成时间线事件（严格四类）。返回 (events, signals)。
    signals 是给 summary 用的布尔/计数汇总。"""
    events = []
    sig = {
        'any_unreachable': False, 'port_missing': [], 'port_ok': [],
        'supervisor_bad': [], 'recent_reboot': [], 'app_process_missing': [],
        'port_unknown': [],
        'nginx_5xx': 0, 'nginx_upstream_errors': {}, 'dns_mismatch': [], 'dns_fail': [],
        'jenkins_last_failure': None, 'jenkins_last_success': None,
        'nginx_last_ok_access': None,
        'app_log_recent': [], 'app_log_missing': [],
        'app_log_path': (g['service'].get('app_log_path') or ''),
        # 近 N 日 OS 事件：os_events 全量(ip,kind,ts,msg)，os_notable 只留整机级异常/告警级
        'os_events': [], 'os_notable': [], 'os_notes': [], 'os_missing': [],
    }
    svc = g['service']
    port = svc.get('port')
    program = svc.get('supervisor_program')

    # ---- 服务器事实 ----
    for s in g['servers']:
        ip = s['ip']
        ts = _parse_ts(s.get('collected_at')) or timezone.now()
        if not s.get('reachable'):
            sig['any_unreachable'] = True
            events.append(_ev(ts, 'server:%s' % ip, 'unreachable',
                              '服务器 %s 采集不可达（可能关机/网络不通/WinRM-SSH 异常）' % ip,
                              {'ip': ip}, 'fact'))
            continue
        # 端口监听
        if port:
            if s.get('port_listening') is True:
                sig['port_ok'].append(ip)
                events.append(_ev(ts, 'server:%s' % ip, 'port_listen',
                                  '端口 %s 在 %s 正常监听' % (port, ip),
                                  {'ip': ip, 'port': port}, 'fact'))
            elif s.get('port_listening') is False:
                sig['port_missing'].append(ip)
                events.append(_ev(ts, 'server:%s' % ip, 'port_missing',
                                  '端口 %s 在 %s 未监听（应用可能未启动）' % (port, ip),
                                  {'ip': ip, 'port': port, 'listen_ports': s.get('listen_ports')}, 'fact'))
            elif s.get('port_listening') is None:
                # 采集到的监听端口为空 → 端口状态未知，绝不当作"未监听"
                sig['port_unknown'].append(ip)
                events.append(_ev(ts, 'server:%s' % ip, 'port_unknown',
                                  '端口 %s 在 %s 状态未知（本次未采集到监听端口列表，非"未监听"结论；'
                                  '建议在该机执行 netstat -ano 复核）' % (port, ip),
                                  {'ip': ip, 'port': port}, 'fact'))
        # supervisor 状态
        st = s.get('supervisor_status') or ''
        if st and st not in ('RUNNING', 'CONFIGURED'):
            sig['supervisor_bad'].append((ip, program, st))
            events.append(_ev(ts, 'supervisor:%s' % ip, 'program_state',
                              'supervisor 程序 %s 在 %s 状态为 %s（非 RUNNING）' % (program or '?', ip, st),
                              {'ip': ip, 'program': program, 'status': st}, 'fact'))
        elif st == 'RUNNING':
            events.append(_ev(ts, 'supervisor:%s' % ip, 'program_state',
                              'supervisor 程序 %s 在 %s 状态 RUNNING' % (program or '?', ip),
                              {'ip': ip, 'program': program, 'status': st}, 'fact'))
        # 应用进程
        if not s.get('app_process') and (program or port):
            sig['app_process_missing'].append(ip)
        # 应用/Supervisor 日志新鲜度（旁证："日志近期有写入 → 应用大概率在跑"）
        al = s.get('app_log') or {}
        al_path = al.get('path') or ''
        # 登记路径含 %(program_name)s 占位符时，gather() 已按程序名展开；此处提示一下，
        # 免得用户看到"展开后的真实路径"与登记原文不一致而困惑。
        cfg_al_path = g['service'].get('app_log_path_configured') or ''
        al_expand_note = ''
        if cfg_al_path and cfg_al_path != al_path:
            al_expand_note = '；注：登记路径 %s 含 supervisor 占位符，已按程序名展开为实际文件' % cfg_al_path
        # 服务端抓的 supervisor logtail（不受登记路径影响，反映程序当前真实日志）
        lt = s.get('logtail') or {}
        lt_lines = lt.get('lines') or []
        lt_url = lt.get('url') or ''
        if al_path and al.get('exists'):
            age = al.get('mtime_ago_sec')
            try:
                age_i = int(age) if age is not None else None
            except (ValueError, TypeError):
                age_i = None
            recent = age_i is not None and age_i <= 1800
            if recent:
                sig['app_log_recent'].append(ip)
            lines = al.get('last_lines') or []
            # 优先用 logtail 抓到的末行（来源权威、路径不会错），否则退回文件末尾
            if lt_lines:
                tail, tail_src = lt_lines, 'supervisor logtail'
            else:
                tail = [str(x).rstrip() for x in lines[-3:] if str(x).strip()]
                tail_src = '日志文件末尾'
            ago_txt = _fmt_dur(age_i) if age_i is not None else '未知'
            summary = '应用/Supervisor 日志(%s) 在 %s 最近写入于 %s（%s前）%s' % (
                al_path, ip, al.get('mtime') or '?', ago_txt,
                '，日志近期有写入，应用大概率仍在运行' if recent else '，距今较久')
            if tail:
                # 直接把日志最后几行贴进"已确认事实"，省得再去翻文件/点 logtail
                summary += '；最后 %d 行（来源：%s）：\n%s' % (
                    len(tail), tail_src, '\n'.join('  | ' + t[:200] for t in tail))
            summary += al_expand_note
            events.append(_ev(_parse_ts(al.get('mtime')) or ts, 'applog:%s' % ip,
                              'app_log_state', summary,
                              {'ip': ip, 'path': al_path, 'mtime': al.get('mtime'),
                               'mtime_ago_sec': age_i, 'recent': recent,
                               'size': al.get('size'),
                               'last_lines': (lt_lines or lines[-3:])}, 'fact'))
        elif lt_lines:
            # 登记路径不存在（或未登记），但 logtail 抓到了程序日志——说明真实路径与
            # 登记不符，且程序确实在输出日志（视为"应用在运行"的证据），不再误报缺失。
            sig['app_log_recent'].append(ip)
            head = ('登记的应用日志路径(%s) 在 %s 上不存在，但 supervisor logtail 显示'
                    '程序 %s 仍在输出日志——真实日志路径与登记不一致，登记路径需更新'
                    % (al_path, ip, program or '?')) if al_path else (
                    '未登记应用日志路径，但 supervisor logtail 显示程序 %s 在 %s 上有日志输出'
                    % (program or '?', ip))
            summary = '%s；最后 %d 行（来源：supervisor logtail %s）：\n%s' % (
                head, len(lt_lines), lt_url,
                '\n'.join('  | ' + t[:200] for t in lt_lines))
            events.append(_ev(ts, 'applog:%s' % ip, 'app_log_state', summary,
                              {'ip': ip, 'path': al_path, 'logtail_url': lt_url,
                               'last_lines': lt_lines}, 'fact'))
        elif al_path and not al.get('exists'):
            sig['app_log_missing'].append(ip)
            miss = ('登记的应用日志(%s) 在 %s 上不存在（%s）——可能路径已变更/日志被清理/'
                    '或应用并非在此机运行，需人工核对%s' % (
                        al_path, ip, al.get('error') or '文件不存在', al_expand_note))
            if program:
                miss += ('；提示：可点本页上方 supervisor logtail 链接直接看程序 %s 的实时日志'
                         '（logtail 由 supervisor 按当前配置解析真实路径，不受登记路径影响）' % program)
                if lt.get('note'):
                    miss += '；服务端 logtail 抓取：%s' % lt.get('note')
            events.append(_ev(ts, 'applog:%s' % ip, 'app_log_state', miss,
                              {'ip': ip, 'path': al_path, 'error': al.get('error')}, 'fact'))
        # uptime / 疑似重启
        up = s.get('uptime_seconds')
        if up is not None:
            try:
                up_i = int(float(up))
            except (ValueError, TypeError):
                up_i = None
            if up_i is not None and up_i < 900:
                sig['recent_reboot'].append((ip, up_i))
                events.append(_ev(_parse_ts(s.get('boot_time')) or ts, 'server:%s' % ip,
                                  'recent_boot',
                                  '服务器 %s 运行时长仅 %s，疑似近期重启/开机' % (ip, _fmt_dur(up_i)),
                                  {'ip': ip, 'uptime_seconds': up_i, 'boot_time': s.get('boot_time')}, 'fact'))

        # ---- 近 N 日操作系统事件（重启/OOM/崩溃/服务失败/补丁/sudo 等）----
        # 全部记为 fact：它们是采集到的原始记录本身，不含任何因果判断。
        ols = s.get('os_logs') or {}
        if ols.get('notes'):
            sig['os_notes'].extend('%s：%s' % (ip, x) for x in ols['notes'])
            events.append(_ev(
                ts, 'os:%s' % ip, 'os_summary',
                '%s 近%s日操作系统事件概览：%s' % (ip, ols.get('days') or '?',
                                                '；'.join(ols['notes'])),
                {'ip': ip, 'counts': ols.get('counts'), 'days': ols.get('days'),
                 'since': ols.get('since'), 'truncated': ols.get('truncated'),
                 'errors': ols.get('errors')}, 'fact'))
        elif ols.get('errors'):
            sig['os_missing'].append(ip)
            events.append(_ev(ts, 'os:%s' % ip, 'os_unavailable',
                              '%s 未能采集到操作系统事件日志（采集受限，非"无异常"结论）：%s'
                              % (ip, '；'.join(ols['errors'][:3])),
                              {'ip': ip, 'errors': ols.get('errors')}, 'fact'))
        else:
            sig['os_missing'].append(ip)
        for e in (s.get('os_events') or []):
            k = e.get('kind') or 'event'
            msg = e.get('message') or ''
            summary = '%s [%s] %s' % (ip, e.get('kind_label') or oslogs.label(k), msg)
            if e.get('matched'):
                summary += '（与本服务相关依据：%s）' % e['matched']
            events.append(_ev(_parse_ts(e.get('ts')) or ts, 'os:%s' % ip, 'os_%s' % k,
                              summary,
                              {'ip': ip, 'kind': k, 'level': e.get('level'),
                               'source': e.get('source'), 'log': e.get('log'),
                               'ts_raw': e.get('ts'), 'message': msg[:300],
                               'matched': e.get('matched')}, 'fact'))
            sig['os_events'].append((ip, k, e.get('ts') or '', msg[:200]))
            if k in oslogs.ALWAYS_KINDS or (e.get('level') in oslogs.ALARM_LEVELS):
                sig['os_notable'].append((ip, k, e.get('ts') or ''))
        if s.get('os_events_dropped'):
            events.append(_ev(ts, 'os:%s' % ip, 'os_truncated',
                              '%s 另有 %d 条相关 OS 事件未展开（已按重要度取前 %d 条）'
                              % (ip, s['os_events_dropped'], OS_EVENT_LIMIT),
                              {'ip': ip, 'dropped': s['os_events_dropped']}, 'fact'))

    # ---- Nginx 日志事实 ----
    nl = g.get('nginx_logs') or {}
    access_seen = False
    for a in (nl.get('access_logs') or []):
        sc = a.get('status_counts') or {}
        fivexx = sum(v for k, v in sc.items() if str(k).startswith('5'))
        if fivexx:
            sig['nginx_5xx'] += fivexx
            detail = ', '.join('%s:%s' % (k, v) for k, v in sorted(sc.items()) if str(k).startswith('5'))
            events.append(_ev(_parse_ts(a.get('last_ts')) or timezone.now(), 'nginx:access',
                              'http_5xx',
                              '近%s分钟 access 日志(%s) 出现 5xx 共 %d 次（%s）' % (
                                  nl.get('window_min'), a.get('path'), fivexx, detail),
                              {'path': a.get('path'), 'status_counts': sc,
                               'per_minute_5xx': a.get('per_minute_5xx')}, 'fact'))
        # 最近一次"正常访问"(2xx/3xx)——跨窗口取尾部最近一条，回答"这应用最近啥时候还被正常访问"
        last_ok = a.get('last_ok_ts') or ''
        last_any = a.get('last_any_ts') or ''
        if last_ok or last_any:
            access_seen = True
            ts_ok = _parse_ts(last_ok) if last_ok else None
            if ts_ok and (sig.get('nginx_last_ok_access') is None
                          or ts_ok > sig['nginx_last_ok_access']):
                sig['nginx_last_ok_access'] = ts_ok
            summary = 'access 日志(%s) 最近一次正常访问(2xx/3xx)：%s' % (
                a.get('path'), last_ok or '（尾部未见 2xx/3xx）')
            if last_any and last_any != last_ok:
                summary += '；最近一条任意请求：%s' % last_any
            if a.get('ok_in_window') is not None:
                summary += '（近%s分钟正常访问 %s 次 / 共 %s 次）' % (
                    nl.get('window_min'), a.get('ok_in_window'), a.get('total_in_window'))
            if a.get('path_resolved'):
                summary += '；注：登记路径 %s 含 nginx 变量，已解析为当前真实文件' % a.get('configured_path')
            events.append(_ev(ts_ok or _parse_ts(last_any) or timezone.now(),
                              'nginx:access', 'last_ok_access', summary,
                              {'path': a.get('path'), 'last_ok_ts': last_ok,
                               'last_any_ts': last_any,
                               'ok_in_window': a.get('ok_in_window'),
                               'total_in_window': a.get('total_in_window')}, 'fact'))
        elif a.get('exists') and not a.get('error'):
            access_seen = True
            scanned = a.get('lines_scanned') or 0
            matched = a.get('lines_matched') or 0
            if scanned and not matched:
                # 尾部有行但一条都没解析出时间戳/状态码 → 多半是日志格式不在识别范围
                # ($time_local / $time_iso8601 之外)，据实说明并附样本行，绝不谎称"长期无访问"。
                summary = ('access 日志(%s) 尾部有 %d 行，但未能识别其时间戳格式'
                           '（已兼容 $time_local 与 $time_iso8601）；样本行：%s' % (
                               a.get('path'), scanned, (a.get('sample_tail') or '')[:160]))
                detail = {'path': a.get('path'), 'lines_scanned': scanned,
                          'lines_matched': matched, 'sample_tail': a.get('sample_tail')}
            else:
                summary = ('access 日志(%s) 尾部未见任何请求记录（该文件确无有效请求行，'
                           '可能长期无访问或日志已轮转）' % a.get('path'))
                detail = {'path': a.get('path'), 'lines_scanned': scanned,
                          'lines_matched': matched}
            events.append(_ev(timezone.now(), 'nginx:access', 'last_ok_access',
                              summary, detail, 'fact'))
    # 兜底：没能给出"最近一次被访问"结论时，明确说明原因，绝不静默省略
    if not access_seen:
        acc_list = nl.get('access_logs') or []
        if not nl:
            reason = ('本次未探测 nginx 日志（未配置 NGINX_HOST，或本服务未登记 '
                      'nginx access/error 日志路径），无法判断最近一次被访问时间')
        elif not acc_list:
            reason = ('本服务未登记「Nginx 访问日志」路径，无法判断最近一次被访问时间；'
                      '请在服务关联登记里补全「Nginx 访问日志」后重试')
        else:
            miss = [a.get('path') for a in acc_list if a.get('path') and not a.get('exists')]
            reason = ('登记的 access 日志在 nginx 主机上读取不到(%s)，无法判断最近访问；'
                      '请核对路径/权限' % ('、'.join(miss) or '见采集详情'))
        events.append(_ev(timezone.now(), 'nginx:access', 'last_ok_access',
                          '未能判断本服务最近一次被访问时间：%s' % reason,
                          {'reason': reason}, 'fact'))
    for e in (nl.get('error_logs') or []):
        sigs = e.get('signatures') or {}
        scoped = bool(e.get('service_scoped'))
        total = e.get('total_in_window')            # 归属到本服务的行数
        total_all = e.get('total_all_services')     # 全局(所有服务)行数
        first_ts = e.get('first_ts') or ''
        last_ts = e.get('last_ts') or ''
        span = ''
        if first_ts and last_ts and first_ts != last_ts:
            span = '，发生于 %s ~ %s' % (first_ts, last_ts)
        elif last_ts:
            span = '，发生于 %s' % last_ts
        if sigs:
            for k, v in sigs.items():
                sig['nginx_upstream_errors'][k] = sig['nginx_upstream_errors'].get(k, 0) + v
            detail = ', '.join('%s:%s' % (k, v) for k, v in sorted(sigs.items()))
            # 归属说明：脚本已按「本服务 后端IP:端口 + 域名」过滤 error 行，
            # 全局 error_log 里别的服务的 connection refused 不再计入本服务。
            if scoped:
                scope_note = '（已按本服务标识 %s 过滤归属；全局同窗口 upstream 错误共 %s 行，其中属于本服务 %s 行）' % (
                    '、'.join(e.get('match_tokens') or []) or '本服务',
                    total_all if total_all is not None else '?',
                    total if total is not None else '?')
            else:
                scope_note = '（未提供本服务过滤标识，以下为 error 日志全局统计，可能混入其它服务的报错）'
            events.append(_ev(_parse_ts(last_ts) or timezone.now(), 'nginx:error',
                              'upstream_error',
                              '近%s分钟 error 日志(%s) 命中 upstream 相关错误 %s 行（签名 %s）%s。%s '
                              '注意：这些是窗口内已发生的历史事件，实时 tail -f 只显示此后新增的行，'
                              '当前 tail 无输出不代表误报' % (
                                  nl.get('window_min'), e.get('path'),
                                  total if total is not None else '?', detail, span, scope_note),
                              {'path': e.get('path'), 'signatures': sigs,
                               'service_scoped': scoped,
                               'match_tokens': e.get('match_tokens'),
                               'total_in_window': total, 'total_all_services': total_all,
                               'first_ts': first_ts,
                               'last_ts': last_ts, 'per_minute': e.get('per_minute'),
                               'samples': (e.get('samples') or [])[:3]}, 'fact'))
        elif scoped and total_all:
            # 全局有 upstream 错误，但没有一行属于本服务——明确说明，避免误当本服务故障
            events.append(_ev(_parse_ts(last_ts) or timezone.now(), 'nginx:error',
                              'upstream_error',
                              '近%s分钟 error 日志(%s) 全局命中 upstream 错误 %s 行，'
                              '但按本服务标识(%s)过滤后为 0 行——这些报错属于其它服务，与本服务无关' % (
                                  nl.get('window_min'), e.get('path'), total_all,
                                  '、'.join(e.get('match_tokens') or [])),
                              {'path': e.get('path'), 'service_scoped': True,
                               'match_tokens': e.get('match_tokens'),
                               'total_in_window': 0, 'total_all_services': total_all}, 'fact'))

    # ---- DNS 事实 ----
    # 反向代理识别：域名常解析到 nginx(反代)而非后端应用机，这是正常架构，
    # 不能因为"解析IP≠登记后端IP"就判为 DNS 异常。故把 nginx 主机视为合法解析目标。
    proxy_ips = set()
    for k in ('nginx_host',):
        v = (g.get(k) or '').strip()
        if v:
            proxy_ips.add(v)
    for d in (g.get('dns') or []):
        dom = d.get('domain')
        per_srv = d.get('servers') or []
        resolved = set()
        fails = []
        for s in per_srv:
            if s.get('addresses'):
                resolved.update(s['addresses'])
            elif s.get('error'):
                fails.append('%s(%s)' % (s.get('server'), s.get('error')))
        expected = set(str(x) for x in (svc.get('server_ips') or []))
        if not resolved and fails:
            sig['dns_fail'].append(dom)
            events.append(_ev(timezone.now(), 'dns', 'resolve_fail',
                              '域名 %s 解析失败：%s' % (dom, '; '.join(fails)),
                              {'domain': dom, 'servers': per_srv}, 'fact'))
        elif resolved:
            hit_backend = bool(resolved & expected)
            hit_proxy = bool(resolved & proxy_ips)
            # 只有"既不指向登记后端、也不指向 nginx 反代"时，才算真正的解析不一致
            mismatch = bool(expected) and not hit_backend and not hit_proxy
            if hit_proxy and not hit_backend:
                note = '（指向 Nginx 反向代理 %s，再由其转发到后端 %s，属正常架构）' % (
                    ','.join(sorted(resolved & proxy_ips)),
                    ','.join(sorted(expected)) or '?')
            elif mismatch:
                note = '（与登记后端 %s 不一致，且非已知 Nginx 反代）' % ','.join(sorted(expected))
            else:
                note = ''
            events.append(_ev(timezone.now(), 'dns', 'resolve_ok',
                              '域名 %s 解析到 %s%s' % (dom, ','.join(sorted(resolved)), note),
                              {'domain': dom, 'resolved': sorted(resolved),
                               'expected': sorted(expected),
                               'is_reverse_proxy': hit_proxy and not hit_backend}, 'fact'))
            if mismatch:
                sig['dns_mismatch'].append((dom, sorted(resolved), sorted(expected)))

    # ---- Jenkins 事实 ----
    jk = g.get('jenkins') or {}
    lb = jk.get('last_build')
    ls = jk.get('last_success')
    if lb:
        sig['jenkins_last_failure'] = lb if (lb.get('result') or '').upper() not in ('SUCCESS', '') else None
        events.append(_ev(_parse_ts(lb.get('iso_time')) or timezone.now(), 'jenkins',
                          'last_build',
                          'Jenkins job %s 最近构建 #%s 于 %s 结果 %s' % (
                              jk.get('job'), lb.get('number'), lb.get('iso_time') or '?',
                              lb.get('result') or '?'),
                          {'job': jk.get('job'), 'build': lb}, 'fact'))
    if ls:
        sig['jenkins_last_success'] = ls
        events.append(_ev(_parse_ts(ls.get('iso_time')) or timezone.now(), 'jenkins',
                          'last_success',
                          'Jenkins job %s 最近成功构建 #%s 于 %s' % (
                              jk.get('job'), ls.get('number'), ls.get('iso_time') or '?'),
                          {'job': jk.get('job'), 'build': ls}, 'fact'))

    events.sort(key=lambda x: (x['ts'] is None, x['ts'] or timezone.now()))
    return events, sig


def build_correlations_and_inferences(g, sig):
    """基于事实信号生成"时间关联(correlation)"与"推测(inference)"，措辞严格非因果。"""
    corr = []
    infer = []
    svc = g['service']
    port = svc.get('port')
    program = svc.get('supervisor_program')

    refused = sig['nginx_upstream_errors'].get('connect() failed', 0) + \
        sig['nginx_upstream_errors'].get('connection refused', 0)
    timed_out = sig['nginx_upstream_errors'].get('upstream timed out', 0)

    # 关联：端口未监听 与 nginx 拒绝连接 同时出现
    if sig['port_missing'] and refused:
        corr.append(_ev(timezone.now(), 'correlation', 'time_relation',
                        'nginx 出现 upstream "connection refused" 与 后端端口(%s)在 %s 未监听 同时出现'
                        '（仅时间/现象关联，非因果结论）' % (port, ','.join(sig['port_missing'])),
                        {'port_missing': sig['port_missing'], 'refused': refused}, 'correlation'))
    # 关联：近期重启 与 5xx/拒绝连接 时间段接近
    if sig['recent_reboot'] and (sig['nginx_5xx'] or refused):
        corr.append(_ev(timezone.now(), 'correlation', 'time_relation',
                        '后端服务器近期重启(%s) 与 nginx 5xx/upstream 错误 在时间上接近'
                        '（仅时间关联，非因果结论）' % ','.join('%s:%s' % (ip, _fmt_dur(u)) for ip, u in sig['recent_reboot']),
                        {'recent_reboot': sig['recent_reboot']}, 'correlation'))
    # 关联：jenkins 最近构建失败 与 nginx 错误 时间接近
    jfail = sig.get('jenkins_last_failure')
    if jfail and (sig['nginx_5xx'] or refused or sig['port_missing']):
        corr.append(_ev(_parse_ts(jfail.get('iso_time')) or timezone.now(), 'correlation', 'time_relation',
                        'Jenkins 最近构建 #%s(%s) 于 %s 与 当前异常现象 时间上接近（仅时间关联，非因果结论）' % (
                            jfail.get('number'), jfail.get('result'), jfail.get('iso_time')),
                        {'build': jfail}, 'correlation'))

    # 关联：近 N 日操作系统级异常事件 与 当前异常现象 处于同一时段
    os_days = 0
    for s in g['servers']:
        try:
            os_days = max(os_days, int((s.get('os_logs') or {}).get('days') or 0))
        except (TypeError, ValueError):
            pass
    fault_now = bool(sig['any_unreachable'] or sig['port_missing'] or sig['supervisor_bad']
                     or sig['app_process_missing'] or sig['nginx_5xx'] or refused or timed_out)
    if sig['os_notable'] and fault_now:
        desc = '；'.join(
            '%s %s(%s)' % (ip, oslogs.label(k), (t or '时间不详')[:19].replace('T', ' '))
            for ip, k, t in sig['os_notable'][:6])
        corr.append(_ev(timezone.now(), 'correlation', 'time_relation',
                        '部署机近%s日存在操作系统级异常事件（%s），与本服务当前异常处于同一时段'
                        '（仅时间关联，非因果结论；请人工核对具体时刻与业务影响范围）'
                        % (os_days or '?', desc),
                        {'os_notable': [list(x) for x in sig['os_notable'][:20]]}, 'correlation'))
    # 关联：近一日有针对本服务的人为操作记录（sudo/服务重启/新装服务）
    human_ops = [(ip, k, t, m) for ip, k, t, m in sig['os_events']
                 if k in ('auth', 'service_state') and
                 re.search(r'sudo|supervisorctl|systemctl|restart|installed a service', m, re.I)]
    if human_ops:
        ip, k, t, m = human_ops[0]
        corr.append(_ev(_parse_ts(t) or timezone.now(), 'correlation', 'time_relation',
                        '近%s日在 %s 采到与本服务相关的人为操作记录（%s），时间与当前异常需人工比对'
                        '（仅时间关联，非因果结论）：%s'
                        % (os_days or '?', ip, oslogs.label(k), m[:200]),
                        {'human_ops': [list(x) for x in human_ops[:10]]}, 'correlation'))

    # 推测：应用进程不可用（仅在确有观测事实支撑时给出，避免弱启发式误报）
    if sig['supervisor_bad']:
        # supervisor 权威状态异常(Linux supervisorctl 报 STOPPED/EXITED 等) → 较强证据
        reason = ['supervisor 状态异常(%s)' % ','.join('%s=%s' % (p, s) for _, p, s in sig['supervisor_bad'])]
        if sig['port_missing']:
            reason.append('端口未监听(%s)' % ','.join(sig['port_missing']))
        infer.append(_ev(timezone.now(), 'inference', 'guess',
                         '推测：应用进程可能未正常运行（%s），导致 nginx upstream 无法连通；需查应用日志确认，不作因果定论' % '；'.join(reason),
                         {'signals': ['supervisor_bad', 'port_missing']}, 'inference'))
    elif sig['port_missing']:
        # 仅"端口未监听"一条证据时，用应用/supervisor 日志新鲜度做反证：
        # 若这些机器日志近期仍在写入 → 应用大概率在跑，"端口未监听"更可能是采集漏采。
        contra = [ip for ip in sig['port_missing'] if ip in sig['app_log_recent']]
        if contra:
            infer.append(_ev(timezone.now(), 'inference', 'guess',
                             '推测：采集显示端口(%s)在 %s 未监听，但这些机器的应用/supervisor 日志近期仍在写入，'
                             '应用大概率仍在运行——"端口未监听"更可能是采集漏采(监听端口来源不全)而非应用未启动；'
                             '请在该机 netstat -ano 复核端口，勿据此断定应用没起（不作因果定论）'
                             % (port, ','.join(contra)),
                             {'signals': ['port_missing', 'app_log_recent']}, 'inference'))
        else:
            infer.append(_ev(timezone.now(), 'inference', 'guess',
                             '推测：应用进程可能未正常运行（端口未监听(%s)），可能导致 nginx upstream 无法连通；'
                             '需查应用日志确认，不作因果定论' % ','.join(sig['port_missing']),
                             {'signals': ['port_missing']}, 'inference'))
    elif sig['app_process_missing'] and not sig['port_ok'] and not sig['port_unknown']:
        # 仅在端口状态"已明确"时才用进程启发式；措辞更弱，说明其局限。
        # port_unknown(采集不到监听端口)时绝不触发，避免把采集缺失误判成"应用没起"。
        infer.append(_ev(timezone.now(), 'inference', 'guess',
                         '推测：进程列表中未匹配到应用进程(%s)，但这是弱启发式'
                         '（进程明细按内存取前若干条，可能漏采），端口是否监听未直接确认；需人工核对，不作定论'
                         % (program or port or '?'),
                         {'signals': ['app_process_missing']}, 'inference'))
    elif sig['port_unknown']:
        extra = ''
        if sig['app_log_recent']:
            extra = '；且应用/supervisor 日志近期仍在写入(%s)，应用大概率在运行' % ','.join(sig['app_log_recent'])
        infer.append(_ev(timezone.now(), 'inference', 'guess',
                         '说明：本次未能采集到 %s 的监听端口列表，端口 %s 是否在监听无法从采集数据判定；'
                         '这通常是采集不完整(WinRM/脚本受限)而非应用故障，请在该机 netstat -ano 复核后再下结论%s'
                         % (','.join(sig['port_unknown']), port or '?', extra),
                         {'signals': ['port_unknown']}, 'inference'))
    # 推测：部署失败导致
    if jfail:
        infer.append(_ev(timezone.now(), 'inference', 'guess',
                         '推测：最近一次 Jenkins 构建 #%s 结果为 %s，可能部署未成功/未正确拉起应用；需查该构建日志确认' % (
                             jfail.get('number'), jfail.get('result')),
                         {'build_number': jfail.get('number')}, 'inference'))
    # 推测：DNS 异常
    if sig['dns_fail']:
        infer.append(_ev(timezone.now(), 'inference', 'guess',
                         '推测：域名 %s 解析失败，客户端可能根本无法到达后端；需确认 DNS 记录' % ','.join(sig['dns_fail']),
                         {'dns_fail': sig['dns_fail']}, 'inference'))
    if sig['dns_mismatch']:
        infer.append(_ev(timezone.now(), 'inference', 'guess',
                         '推测：域名解析到的 IP 与登记后端不一致（%s），可能解析指向错误；需人工核对' % (
                             '; '.join('%s→%s(期望%s)' % (d, ','.join(r), ','.join(e)) for d, r, e in sig['dns_mismatch'])),
                         {'dns_mismatch': sig['dns_mismatch']}, 'inference'))
    # 推测：应用存活但处理异常
    if (sig['nginx_5xx'] or timed_out) and sig['port_ok'] and not sig['port_missing']:
        infer.append(_ev(timezone.now(), 'inference', 'guess',
                         '推测：端口正常监听但仍有 5xx/upstream 超时，应用可能存活但处理异常（依赖/超时/500）；需查应用日志',
                         {'timed_out': timed_out}, 'inference'))
    # 推测：不可达
    if sig['any_unreachable']:
        infer.append(_ev(timezone.now(), 'inference', 'guess',
                         '推测：部分后端服务器采集不可达，可能关机或网络中断；需确认主机状态',
                         {}, 'inference'))
    # 推测：OS 层证据（OOM/崩溃）与"应用进程不在"同时出现
    oom_hits = [(ip, t) for ip, k, t in sig['os_notable'] if k == 'oom']
    crash_hits = [(ip, t) for ip, k, t in sig['os_notable'] if k == 'crash']
    app_gone = bool(sig['port_missing'] or sig['app_process_missing'] or sig['supervisor_bad'])
    if oom_hits and app_gone:
        infer.append(_ev(timezone.now(), 'inference', 'guess',
                         '推测：部署机 %s 近%s日内核曾以 OOM 杀进程（%s），应用进程可能被一并杀掉；'
                         '需在该机 dmesg -T | grep -i "killed process" 核对被杀进程名与时刻，'
                         '不作因果定论' % (
                             ','.join(sorted({ip for ip, _ in oom_hits})),
                             os_days or '?',
                             '；'.join((t or '时间不详')[:19].replace('T', ' ') for _, t in oom_hits[:3])),
                         {'oom': [list(x) for x in oom_hits[:10]]}, 'inference'))
    elif crash_hits and app_gone:
        infer.append(_ev(timezone.now(), 'inference', 'guess',
                         '推测：部署机 %s 近%s日有程序崩溃/挂起记录（%s），可能涉及本服务进程；'
                         '需核对崩溃报告中的进程名，不作因果定论' % (
                             ','.join(sorted({ip for ip, _ in crash_hits})), os_days or '?',
                             '；'.join((t or '时间不详')[:19].replace('T', ' ') for _, t in crash_hits[:3])),
                         {'crash': [list(x) for x in crash_hits[:10]]}, 'inference'))

    if not infer and not corr:
        infer.append(_ev(timezone.now(), 'inference', 'guess',
                         '未在只读探测中发现明显异常信号；若故障仍存在，建议扩大时间窗口或人工核对应用日志/上游依赖',
                         {}, 'inference'))
    return corr, infer


def build_suggestions(g, sig):
    sug = []
    svc = g['service']
    program = svc.get('supervisor_program')
    app_log = svc.get('app_log_path')
    port = svc.get('port')
    for ip in sig.get('port_unknown') or []:
        sug.append('在 %s 上执行 netstat -ano 复核端口 %s 是否在监听'
                   '（本次未采集到监听端口列表，端口状态未知，不能据此判定应用未启动）' % (ip, port or '?'))
    for ip in sig.get('port_missing') or []:
        sug.append('在 %s 上复核端口 %s 是否真的未监听：Windows 用 netstat -ano | findstr %s，'
                   'Linux 用 ss -lntp | grep %s（端口采集可能漏采，人工确认后再判定应用是否启动）'
                   % (ip, port or '?', port or ':?', port or '?'))
    for ip in sig.get('app_log_missing') or []:
        sug.append('核对 %s 上登记的应用日志路径 %s 是否正确（本次在该机未找到此文件，可能路径已变更或应用不在此机）'
                   % (ip, app_log or '(未登记)'))
    for s in g['servers']:
        ip = s['ip']
        if s.get('supervisor_status') and s['supervisor_status'] not in ('RUNNING', 'CONFIGURED'):
            sug.append('在 %s 上查看 supervisor 程序 %s 状态与日志：supervisorctl status %s；tail %s' % (
                ip, program or '?', program or '?', app_log or '(登记的 stdout_logfile)'))
        if app_log:
            sug.append('查看 %s 的应用日志 %s 最近报错（只读）' % (ip, app_log))
    if sig['recent_reboot']:
        for ip, u in sig['recent_reboot']:
            sug.append('确认 %s 是否有人为重启/关机（当前 uptime≈%s）' % (ip, _fmt_dur(u)))
    # 近 N 日 OS 事件相关的下一步核对动作（全部只读）
    if sig.get('os_notable'):
        ips = sorted({ip for ip, _, _ in sig['os_notable']})
        kinds = '、'.join(sorted({oslogs.label(k) for _, k, _ in sig['os_notable']}))
        sug.append('按时刻核对 %s 的操作系统级异常（%s）与故障发生的先后顺序：Linux 用 '
                   'journalctl --since "-1d" -p err 与 dmesg -T | grep -iE "killed process|error"；'
                   'Windows 用 事件查看器→系统/应用程序 按时间筛选（只读，切勿清除日志）'
                   % (','.join(ips), kinds))
    if any(k in ('auth', 'service_state') for _, k, _, _ in sig.get('os_events') or []):
        sug.append('核对近一日是否有针对本服务的人为操作（sudo/supervisorctl restart/新装服务），'
                   '并与操作人确认操作时刻与内容')
    for ip in sig.get('os_missing') or []:
        sug.append('%s 未采集到操作系统事件日志（属采集受限，不等于"无异常"）：确认采集账号能否读取'
                   '事件源——Linux 需 root 或 systemd-journal/adm 组、Windows 需事件日志读取权限' % ip)
    jfail = sig.get('jenkins_last_failure')
    if jfail:
        commits = (jfail.get('commits') or [])[:3]
        sug.append('核对 Jenkins job %s 构建 #%s 的构建日志与提交(%s)，确认部署是否成功' % (
            svc.get('jenkins_job') or '?', jfail.get('number'),
            '; '.join(commits) if commits else '无 changelog'))
    for d in (g.get('dns') or []):
        dom = d.get('domain')
        if dom in sig['dns_fail'] or any(dom == m[0] for m in sig['dns_mismatch']):
            sug.append('用 nslookup %s <DNS> 复核解析结果是否与后端 %s 一致' % (
                dom, ','.join(str(x) for x in (svc.get('server_ips') or []))))
    if not sug:
        sug.append('扩大排查时间窗口重试；或人工核对 nginx upstream 配置与后端健康检查')
    # 去重保序
    out = []
    for x in sug:
        if x not in out:
            out.append(x)
    return [_ev(timezone.now(), 'suggestion', 'action', x, {}, 'suggestion') for x in out]


def build_headline(g, sig):
    """给一个"推测性"总体判断（明确标注为推测，不下因果定论）。"""
    if sig['dns_fail']:
        return {'level': '推测', 'text': '疑似 DNS 解析失败导致服务不可达（需确认 DNS 记录）'}
    if sig['any_unreachable']:
        return {'level': '推测', 'text': '疑似后端服务器不可达/关机（需确认主机状态）'}
    if sig['supervisor_bad']:
        return {'level': '推测', 'text': '疑似应用进程未运行（supervisor 状态异常），需查应用日志确认'}
    if sig['port_missing']:
        if [ip for ip in sig['port_missing'] if ip in sig['app_log_recent']]:
            return {'level': '推测', 'text': '采集显示端口未监听，但应用/supervisor 日志近期仍在写入，应用大概率在运行——端口判定疑为采集漏采，建议 netstat 复核'}
        return {'level': '推测', 'text': '疑似应用进程未运行（端口未监听），需查应用日志确认'}
    if sig.get('jenkins_last_failure'):
        return {'level': '推测', 'text': '疑似最近一次部署失败导致，需核对 Jenkins 构建'}
    if sig['dns_mismatch']:
        return {'level': '推测', 'text': '疑似 DNS 解析指向与后端不一致'}
    if sig['nginx_5xx']:
        return {'level': '推测', 'text': '后端端口存活但存在 5xx/超时，疑似应用处理异常'}
    if sig.get('port_unknown'):
        return {'level': '推测', 'text': '本次未采集到后端监听端口列表，端口状态未知（多为采集不完整，非应用故障定论），建议 netstat 复核'}
    return {'level': '推测', 'text': '只读探测未发现明显异常，若故障仍在建议扩大窗口或人工排查'}


def analyze(g):
    """把 gather 结果整理成最终 analysis（时间线四分类 + 概览）。"""
    facts, sig = build_timeline(g)
    corr, infer = build_correlations_and_inferences(g, sig)
    sugg = build_suggestions(g, sig)
    headline = build_headline(g, sig)
    timeline = facts + corr + infer + sugg
    timeline.sort(key=lambda x: (x['kind'] != 'fact', x['ts'] is None, x['ts'] or timezone.now()))
    # 内部排序用 datetime；落库(JSONField)前统一把 ts 转 ISO 字符串，避免 datetime 不可序列化
    return {
        'service': g['service'],
        'window_min': g.get('window_min'),
        # nginx 日志是在哪台机上读的（反代机），供前端/大模型证据标注"主机"用
        'nginx_host': g.get('nginx_host') or '',
        'headline': headline,
        'signals': {
            'any_unreachable': sig['any_unreachable'],
            'port_missing': sig['port_missing'], 'port_ok': sig['port_ok'],
            'port_unknown': sig['port_unknown'],
            'supervisor_bad': [list(x) for x in sig['supervisor_bad']],
            'recent_reboot': [list(x) for x in sig['recent_reboot']],
            'nginx_5xx': sig['nginx_5xx'],
            'nginx_upstream_errors': sig['nginx_upstream_errors'],
            'nginx_last_ok_access': _iso(sig.get('nginx_last_ok_access')),
            'app_log_recent': sig['app_log_recent'],
            'app_log_missing': sig['app_log_missing'],
            'app_log_path': sig['app_log_path'],
            'dns_fail': sig['dns_fail'],
            'dns_mismatch': [list(x) for x in sig['dns_mismatch']],
            'jenkins_last_build': (g.get('jenkins') or {}).get('last_build'),
            # 近 N 日 OS 事件（tuple 落 JSONField 会变数组，前端按数组读）
            'os_events': [list(x) for x in sig['os_events'][:60]],
            'os_notable': [list(x) for x in sig['os_notable'][:30]],
            'os_notes': sig['os_notes'],
            'os_missing': sig['os_missing'],
        },
        'facts': [_jsonable(e) for e in facts],
        'correlations': [_jsonable(e) for e in corr],
        'inferences': [_jsonable(e) for e in infer],
        'suggestions': [_jsonable(e) for e in sugg],
        'timeline': [_jsonable(e) for e in timeline],
        'servers': g['servers'],
        'nginx_logs': g.get('nginx_logs'),
        'dns': g.get('dns'),
        'jenkins': g.get('jenkins'),
        'errors': g.get('errors') or [],
    }
