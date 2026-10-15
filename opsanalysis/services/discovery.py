"""运维分析——服务关联自动发现（只读）。

三处只读发现源，以 ip:port 为连接键聚合成"逻辑应用"，写入 ServiceRegistry 候选：
  1) Nginx：upstream <域名> { server ip:port } + server{ server_name / access_log / proxy_pass }
  2) Jenkins：jobs/*/config.xml → job 名 / git 项目 / 部署 IP / command 里的 supervisor 程序与端口
  3) Supervisor：各应用机 [program:x] / command(端口) / stdout_logfile（Linux 走 discover_supervisor.py，
     Windows 复用 ops_impact_windows.yml 采集到的 supervisor 段）

红线：全程只读，绝不 reload nginx / 触发构建 / start-stop-restart supervisor。
发现结果只产出 candidate（待确认）与合并别名，绝不覆盖人工已 confirmed 的记录内容。
"""
import logging
import re
from datetime import datetime

from django.conf import settings

from firewall.services.ansible_executor import parse_host_json

from opsanalysis.services.collectors import (
    collect_impact_windows, detect_os_type,
)
from opsanalysis.services.sync import ops_run_playbook, host_alive

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ 采集

def _cfg():
    return getattr(settings, 'OPS_DISCOVERY_CONFIG', {}) or {}


def _run(playbook, target_host, extra=None, initiated_by='system', timeout=120):
    """下发只读发现 playbook，返回 parse_host_json 的 data（失败 None）。"""
    ev = {'target_host': target_host}
    if extra:
        ev.update(extra)
    res = ops_run_playbook(playbook, ev, timeout=timeout, initiated_by=initiated_by,
                           name=playbook.replace('.yml', ''))
    if not res.get('ok'):
        logger.warning('discovery %s@%s 执行失败: %s', playbook, target_host,
                       (res.get('error') or 'unknown'))
        return None
    data = parse_host_json(res.get('stdout', ''), target_host)
    if data is None:
        logger.warning('discovery %s@%s 输出解析失败', playbook, target_host)
    return data


def collect_nginx(initiated_by='system'):
    host = _cfg().get('NGINX_HOST')
    if not host:
        return None
    return _run('ops_discover_nginx.yml', host,
                extra={'nginx_conf': _cfg().get('NGINX_CONF') or ''},
                initiated_by=initiated_by)


def collect_jenkins(initiated_by='system'):
    host = _cfg().get('JENKINS_HOST')
    if not host:
        return None
    return _run('ops_discover_jenkins.yml', host,
                extra={'jenkins_jobs_dir': _cfg().get('JENKINS_JOBS_DIR') or ''},
                initiated_by=initiated_by)


def collect_supervisor(ip, initiated_by='system'):
    """采集单台应用机的 supervisor 程序；按 OS 路由。返回 [program dict] 或 []。"""
    ost = detect_os_type(ip)
    if ost == 'windows':
        # 复用影响采集里的 supervisor 段，避免为 Windows 再写一份发现脚本
        r = collect_impact_windows(ip, initiated_by=initiated_by)
        if not r.get('ok'):
            return []
        sup = (r.get('data') or {}).get('supervisor') or {}
        progs = []
        for p in (sup.get('ini_programs') or []):
            progs.append({'name': p.get('name'), 'port': p.get('port'),
                          'command': p.get('command', ''),
                          'stdout_logfile': p.get('stdout_logfile', ''),
                          'ini_file': p.get('ini_file', ''), 'status': ''})
        return progs
    data = _run('ops_discover_supervisor.yml', ip, initiated_by=initiated_by)
    if not data:
        return []
    return data.get('programs') or []


# ------------------------------------------------------------------ 关联

class _App(object):
    """一个逻辑应用的聚合中间态（用 set 去重，最后落库）。"""

    def __init__(self, identity):
        self.identity = identity
        self.names = set()          # 各系统里出现过的名字（域名/job/program/upstream）
        self.domains = set()
        self.server_ips = set()
        self.ports = set()
        self.supervisor_program = ''
        self.jenkins_job = ''
        self.git_project = ''
        self.git_name = ''
        self.app_log_path = ''
        self.nginx_access_log = ''
        self.nginx_error_log = ''
        self.evidence = []          # 匹配依据（写进 confidence）
        # 仅用于"合并同一应用的多条候选"的连接键（如 ip:port），不落库：
        self.extra_keys = set()
        # 合并后被本条吸收掉的其它候选 identity（清理陈旧拆分记录用）：
        self.absorbed = set()

    def add_ip(self, ip):
        if ip:
            self.server_ips.add(ip)

    def add_port(self, p):
        if p:
            try:
                self.ports.add(int(p))
            except (ValueError, TypeError):
                pass

    def add_ipport(self, ip, p):
        """登记一个 ip:port 连接键（不参与落库的 port 选择，只用于跨源合并）。"""
        if ip and p:
            try:
                self.extra_keys.add('ipport:%s:%d' % (ip, int(p)))
            except (ValueError, TypeError):
                pass


def _index_supervisor(sup_by_ip):
    """返回两个索引：{(ip, port): program} 精确匹配，{ip: [program]} 按主机兜底。"""
    by_ipport = {}
    by_ip = {}
    for ip, progs in sup_by_ip.items():
        for p in progs:
            by_ip.setdefault(ip, []).append(p)
            port = p.get('port')
            if port:
                by_ipport[(ip, int(port))] = p
    return by_ipport, by_ip


def _match_prog_on_host(cands, port, name_hints=()):
    """nginx upstream 成员 ip:port 没能按 (ip,port) 精确命中 supervisor 程序时的兜底匹配。

    Windows 应用的 command 里端口常写成 --port 8878 / -p 8878，采集端正则未提取到
    port 字段，导致 (ip,port) 索引里没有它——于是 nginx 侧只拿到 IP、拿不到程序名，
    supervisor 侧又独立成一条候选，一个服务被拆成两条(分别缺 nginx/jenkins 与 program)。
    这里按主机内的程序做无歧义兜底：
      1) 端口作为独立数字出现在某程序 command 里 → 命中它；
      2) 程序名核心词元与 upstream/域名首标签相同、或互为前缀(如 h5858.4307.com ↔
         h5858_ywops)，且同机内只有一个程序命中 → 命中它；
      3) 该机只有一个 supervisor 程序 → 直接归属(无歧义)。
    都不满足(多程序且无从判断)则返回 None，宁可不关联也不误关联。"""
    named = [c for c in (cands or []) if c.get('name')]
    if not named:
        return None
    if port:
        try:
            pat = re.compile(r'(?:[:=\s\-])%d(?!\d)' % int(port))
        except (ValueError, TypeError):
            pat = None
        if pat:
            for c in named:
                if pat.search(c.get('command') or ''):
                    return c
    hint_toks = {_core_token(h) for h in (name_hints or ())}
    hint_toks.discard('')
    if hint_toks:
        hit = [c for c in named if _core_token(c.get('name')) in hint_toks]
        if len(hit) == 1:
            return hit[0]
        # 域名首标签常是程序名的前缀（h5858.4307.com ↔ h5858_ywops）。同机内
        # 前缀关系唯一时才认，且要求公共前缀足够长，避免 h5 之类误配。
        pref = []
        for c in named:
            ct = _core_token(c.get('name'))
            for h in hint_toks:
                if len(h) >= 4 and (ct.startswith(h) or h.startswith(ct)) \
                        and min(len(ct), len(h)) >= 4:
                    pref.append(c)
                    break
        if len(pref) == 1:
            return pref[0]
    if len(named) == 1:
        return named[0]
    return None


# ------------------------------------------------------- 跨源合并（同一应用去重）

# command 里"服务监听端口"的写法（比 discovery_jenkins 的 PORT_RE 更严，避免把
# --redis-port 6379 之类的外部依赖端口当成本服务端口）
_CMD_PORT_RE = re.compile(
    r'(?:--port|--http[=-]?|--server\.port[=:]|-p\s|\b0\.0\.0\.0:'
    r'|\b127\.0\.0\.1:|\blocalhost:)\s*[:=]?\s*(\d{2,5})\b')

# 过于通用、不能作为合并依据的词元（否则所有 www.* / api.* 会被并成一条）
_GENERIC_TOKENS = {
    'www', 'web', 'api', 'app', 'apps', 'test', 'demo', 'dev', 'uat', 'prod',
    'mail', 'ftp', 'admin', 'localhost', 'nginx', 'jenkins', 'supervisor',
    'server', 'service', 'services', 'default', 'static', 'image', 'images',
}


def _cmd_ports(command):
    """从 supervisor/jenkins 的 command 文本里抽出候选监听端口（用于跨源合并键）。"""
    out = set()
    for m in _CMD_PORT_RE.finditer(command or ''):
        try:
            p = int(m.group(1))
        except (ValueError, TypeError):
            continue
        if 1 <= p <= 65535:
            out.add(p)
    return out


def _core_token(s):
    """把各系统里的名字规约成可跨源比较的"核心词元"。

    tasklist.4307.com → tasklist；https://git/x/h5858_ywops.git → h5858_ywops；
    h5858_ywops → h5858_ywops。取不到/太短/太通用返回 ''。"""
    if not s:
        return ''
    t = str(s).strip().lower()
    if not t or _looks_like_ip(t):
        return ''
    t = t.replace('\\', '/')
    # 候选 identity 形如 h5858_ywops@192.168.2.60，去掉 @IP 尾巴再取词元
    t = re.sub(r'@(?:\d{1,3}\.){3}\d{1,3}$', '', t)
    if '/' in t:                      # git URL → 取仓库短名
        t = t.rsplit('/', 1)[-1]
    if t.endswith('.git'):
        t = t[:-4]
    elif '.' in t:                    # 域名 → 取第一段标签
        t = t.split('.')[0]
    t = t.strip('._-:/ ')
    if len(t) < 3 or t in _GENERIC_TOKENS or not re.search(r'[a-z0-9]', t):
        return ''
    return t


def _strong_keys(a):
    """精确标识符键：只要两条候选共享其一，就无条件认定为同一应用。

    对应用户要求"nginx/supervisor/jenkins/git 四者有任意两个相同即全部关联"：
    id: 是跨源同名键（supervisor 程序名 == jenkins job 名 == git 短名），
    prog:/job:/dom: 是各源内部的精确键，ipport: 是同机同端口键。"""
    ks = set()
    if a.supervisor_program:
        pn = a.supervisor_program.strip().lower()
        if pn not in _GENERIC_TOKENS:
            ks.add('prog:%s' % pn)
    if a.jenkins_job:
        jn = a.jenkins_job.strip().lower()
        if jn not in _GENERIC_TOKENS:
            ks.add('job:%s' % jn)
    for g in (a.git_name, a.git_project):
        tok = _core_token(g)
        if tok:
            ks.add('git:%s' % tok)
    # 跨源同名：这四个源里任意两个用了同一个标识符，就是同一个应用
    for v in (a.supervisor_program, a.jenkins_job, a.git_name,
              _core_token(a.git_project)):
        vl = str(v or '').strip().lower()
        if len(vl) >= 3 and vl not in _GENERIC_TOKENS:
            ks.add('id:%s' % vl)
    for d in a.domains:
        dl = str(d).strip().lower()
        if dl:
            ks.add('dom:%s' % dl)
    ks |= set(a.extra_keys)           # ip:port（同一 ip:port 不可能是两个应用）
    return ks


def _fuzzy_keys(a):
    """核心词元键：跨源同名（如 supervisor 程序名 == git 短名 == jenkins job 名），
    但比精确键弱，需 IP 相容才合并，避免把不同机器上的同名应用误并。"""
    ks = set()
    for n in set(a.names) | {a.identity, a.supervisor_program, a.jenkins_job,
                             a.git_name, a.git_project}:
        tok = _core_token(n)
        if tok:
            ks.add('tok:%s' % tok)
    return ks


def _ip_compat(a, b):
    ai = set(str(x) for x in (a.server_ips or []))
    bi = set(str(x) for x in (b.server_ips or []))
    if not ai or not bi:              # 一方没采到 IP（如停用 job）→ 不做否决
        return True
    return bool(ai & bi)


def _richness(a):
    """合并时挑"信息最全"的那条作为基准，保证 nginx 域名/access_log 不丢。"""
    return (
        (4 if a.domains else 0) + (2 if a.supervisor_program else 0)
        + (1 if a.jenkins_job else 0) + (1 if a.nginx_access_log else 0)
        + len(a.server_ips)
    )


def _merge_into(dst, src):
    dst.names |= src.names
    dst.domains |= src.domains
    dst.server_ips |= src.server_ips
    dst.ports |= src.ports
    dst.extra_keys |= src.extra_keys
    dst.absorbed |= src.absorbed
    dst.absorbed.add(src.identity)
    for f in ('supervisor_program', 'jenkins_job', 'git_project', 'git_name',
              'app_log_path', 'nginx_access_log', 'nginx_error_log'):
        if not getattr(dst, f) and getattr(src, f):
            setattr(dst, f, getattr(src, f))
    dst.evidence.extend(src.evidence)


def _merge_apps(apps):
    """把"实际是同一个应用、却被拆成多条候选"的记录合并（并查集）。

    为什么需要：nginx↔supervisor 靠 ip:port 关联，而 Windows 的端口常没从 command
    里提取到；jenkins↔其它源过去只按"部署IP+程序名"关联，停用 job 或 job 名==程序名
    的情况就关联不上。结果一个应用被拆成 nginx+supervisor 一条、jenkins+git 一条，
    排查时各缺一半信息（如"未登记 Nginx 访问日志"）。这里按标识符相同做合并。"""
    items = list(apps.values())
    n = len(items)
    if n < 2:
        return items
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(i, j):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[max(ri, rj)] = min(ri, rj)

    for keyfn, need_ip in ((_strong_keys, False), (_fuzzy_keys, True)):
        bucket = {}
        for i, a in enumerate(items):
            for k in keyfn(a):
                bucket.setdefault(k, []).append(i)
        for group in bucket.values():
            if len(group) < 2:
                continue
            for i in group[1:]:
                if not need_ip or _ip_compat(items[group[0]], items[i]):
                    union(group[0], i)

    groups = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(items[i])
    merged = []
    for g in groups.values():
        g.sort(key=_richness, reverse=True)
        base = g[0]
        for other in g[1:]:
            _merge_into(base, other)
        if len(g) > 1:
            base.evidence.append('合并同一应用的 %d 条候选：%s（标识符相同）' % (
                len(g), ', '.join(x.identity for x in g[1:])))
        merged.append(base)
    return merged


def correlate(nginx_data, jenkins_data, sup_by_ip):
    """把三处发现源聚合成逻辑应用列表（[_App]）。"""
    apps = {}          # identity -> _App
    sup_index, sup_by_host = _index_supervisor(sup_by_ip)

    def get_app(identity):
        if identity not in apps:
            apps[identity] = _App(identity)
        return apps[identity]

    # ---- 1) Nginx：upstream 名即对外域名，天然把一个应用的多台后端聚成一组 ----
    upstream_to_app = {}
    if nginx_data:
        g_err = nginx_data.get('global_error_log') or ''
        # server 块：域名 → access_log / 它 proxy 到哪个 upstream
        srv_by_upstream = {}
        for s in (nginx_data.get('servers') or []):
            for up in (s.get('proxy_upstreams') or []):
                srv_by_upstream.setdefault(up, []).append(s)
        for u in (nginx_data.get('upstreams') or []):
            name = u.get('name')
            if not name:
                continue
            app = get_app(name)
            upstream_to_app[name] = app
            app.names.add(name)
            app.domains.add(name)
            members = u.get('servers') or []
            # 程序名兜底匹配用的"名字线索"：upstream 名 + 关联 server 块的 server_name
            srv_blocks = srv_by_upstream.get(name, [])
            name_hints = [name]
            for s in srv_blocks:
                name_hints.extend(s.get('server_name') or [])
            for m in members:
                ip = m.get('ip'); port = m.get('port')
                # upstream 成员可能是域名（如指向另一台 nginx），只收 IP
                if ip and _looks_like_ip(ip):
                    app.add_ip(ip)
                    app.add_port(port)
                    app.add_ipport(ip, port)
                    prog = sup_index.get((ip, int(port))) if port else None
                    if not prog:
                        # (ip,port) 没精确命中(常见于 Windows：端口没从 command 提取到)，
                        # 按主机内程序做无歧义兜底，避免同一服务被拆成两条候选。
                        prog = _match_prog_on_host(sup_by_host.get(ip), port, name_hints)
                    if prog and prog.get('name'):
                        app.supervisor_program = prog['name']
                        app.names.add(prog['name'])
                        if prog.get('stdout_logfile'):
                            app.app_log_path = prog['stdout_logfile']
                        for cp in _cmd_ports(prog.get('command')):
                            app.add_ipport(ip, cp)
            # 关联到该 upstream 的 server 块（域名 + access_log）
            for s in srv_by_upstream.get(name, []):
                for sn in (s.get('server_name') or []):
                    app.domains.add(sn); app.names.add(sn)
                if s.get('access_log'):
                    app.nginx_access_log = s['access_log']
                if s.get('error_log'):
                    app.nginx_error_log = s['error_log']
            if not app.nginx_error_log and g_err:
                app.nginx_error_log = g_err
            if members:
                app.evidence.append(
                    'nginx upstream %s → %s' % (
                        name, ','.join('%s:%s' % (m.get('ip'), m.get('port')) for m in members)))
            if app.supervisor_program:
                app.evidence.append('supervisor program %s 命中 ip:port' % app.supervisor_program)
            if app.nginx_access_log:
                app.evidence.append('nginx access_log %s' % app.nginx_access_log)

    # ---- 2) Jenkins：按 部署IP + supervisor程序/端口 关联到已有应用，否则独立成候选 ----
    if jenkins_data:
        for job in (jenkins_data.get('jobs') or []):
            jname = job.get('job_name')
            if not jname:
                continue
            jips = set(job.get('deploy_ips') or [])
            jprogs = set(job.get('supervisor_programs') or [])
            jports = set(int(p) for p in (job.get('ports') or []) if p)
            git_urls = job.get('git_urls') or []
            git_names = job.get('git_names') or []
            # 统一名/展示优先用 git 短名（如 h3_board），退化到完整 URL
            git_short = git_names[0] if git_names else ''
            git = git_short or (git_urls[0] if git_urls else '')
            matched = None
            # 优先：部署IP + supervisor程序名 命中
            for app in apps.values():
                if jips & app.server_ips and (jprogs & {app.supervisor_program}):
                    matched = app; break
            # 其次：部署IP + 端口 命中
            if not matched:
                for app in apps.values():
                    if jips & app.server_ips and (jports & app.ports):
                        matched = app; break
            # 再次：仅 supervisor 程序名命中（IP 可能是别名/未采到）
            if not matched:
                for app in apps.values():
                    if jprogs and (jprogs & {app.supervisor_program}):
                        matched = app; break
            if matched:
                matched.jenkins_job = matched.jenkins_job or jname
                matched.names.add(jname)
                if git_short:
                    matched.names.add(git_short)
                if git and not matched.git_project:
                    matched.git_project = git
                    matched.git_name = matched.git_name or git_short
                for ip in jips:
                    matched.add_ip(ip)
                    for p in jports:
                        matched.add_ipport(ip, p)
                matched.evidence.append('jenkins job %s 部署到 %s%s' % (
                    jname, ','.join(sorted(jips)) or '?',
                    ('(git %s)' % git) if git else ''))
            else:
                app = get_app(jname)
                app.jenkins_job = jname
                app.names.add(jname)
                if git:
                    app.git_project = git
                    app.git_name = git_short
                if git_short:
                    app.names.add(git_short)
                for ip in jips:
                    app.add_ip(ip)
                    for p in jports:
                        app.add_ipport(ip, p)
                for p in jports:
                    app.add_port(p)
                if jprogs:
                    app.supervisor_program = sorted(jprogs)[0]
                    app.names.add(app.supervisor_program)
                app.evidence.append('jenkins job %s（未与 nginx/supervisor 关联上，独立候选）' % jname)

    # ---- 3) 兜底：没被 nginx/jenkins 覆盖到的 supervisor 程序，各自成候选 ----
    covered = set()
    for app in apps.values():
        if app.supervisor_program:
            for ip in app.server_ips:
                covered.add((ip, app.supervisor_program))
    for ip, progs in sup_by_ip.items():
        for p in progs:
            nm = p.get('name')
            if not nm or (ip, nm) in covered:
                continue
            identity = '%s@%s' % (nm, ip)
            app = get_app(identity)
            app.names.add(nm)
            app.supervisor_program = nm
            app.add_ip(ip)
            app.add_port(p.get('port'))
            # ip:port 连接键：既用采集到的 port，也从 command 里抽（Windows 常抽不到
            # port 字段，但 command 里写着 --port 8878），供与 nginx upstream 合并
            app.add_ipport(ip, p.get('port'))
            for cp in _cmd_ports(p.get('command')):
                app.add_ipport(ip, cp)
            if p.get('stdout_logfile'):
                app.app_log_path = p['stdout_logfile']
            app.evidence.append('supervisor program %s@%s（仅本机发现）' % (nm, ip))
            covered.add((ip, nm))

    # ---- 4) 跨源合并：把"实际是同一个应用"的多条候选并成一条 ----
    merged = _merge_apps(apps)

    # ---- 补 os_type / port 落定 ----
    result = []
    for app in merged:
        if not app.server_ips and not app.domains and not app.jenkins_job:
            continue
        result.append(app)
    return result


def _looks_like_ip(s):
    parts = str(s).split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
    return True


# ------------------------------------------------------------------ 落库

def _choose_canonical(app):
    for cand in (app.supervisor_program, app.jenkins_job):
        if cand:
            return cand
    if app.domains:
        return sorted(app.domains)[0]
    return app.identity


def _merge_list(old, new):
    out = list(old or [])
    for x in (new or []):
        if x not in out:
            out.append(x)
    return out


def upsert_apps(apps, initiated_by='system'):
    """把聚合后的应用写入 ServiceRegistry。
    - 不存在 → 新建 candidate(source=auto)。
    - 已存在且 confirmed/manual → 只并集补充 aliases/domains/server_ips、填补空字段，绝不覆盖人工内容。
    - 已存在且 candidate+auto → 刷新为最新发现结果。
    返回统计 dict。"""
    from opsanalysis.models import ServiceRegistry

    created = 0; updated = 0; skipped = 0; retired = 0
    stamp = datetime.now().strftime('%Y-%m-%d %H:%M')
    live_names = set()        # 本次发现真实产出的记录名（含冲突后缀）
    alias_owner = {}          # 别名 → 它现在归属的记录名
    for app in apps:
        canonical = _choose_canonical(app)
        if not canonical:
            skipped += 1; continue
        aliases = sorted(n for n in app.names if n and n != canonical)
        domains = sorted(app.domains)
        server_ips = sorted(app.server_ips)
        port = sorted(app.ports)[0] if app.ports else None
        os_type = 'unknown'
        if server_ips:
            os_type = detect_os_type(server_ips[0])
        confidence = '自动发现(%s)：%s' % (stamp, '；'.join(app.evidence)) if app.evidence \
            else '自动发现(%s)' % stamp

        # canonical 冲突处理：若同名记录属于"另一个应用"（ip/port 无交集），加后缀区分
        qs_name = canonical
        existing = ServiceRegistry.objects.filter(canonical_name=qs_name).first()
        if existing:
            ex_ips = set(str(x) for x in (existing.server_ips or []))
            overlap = ex_ips & set(server_ips)
            same_port = (existing.port in (port, None)) or (port is None)
            if not overlap and not same_port and (server_ips or port):
                suffix = (':%s' % port) if port else ('@%s' % (server_ips[0] if server_ips else 'x'))
                qs_name = (canonical + suffix)[:128]
                existing = ServiceRegistry.objects.filter(canonical_name=qs_name).first()

        live_names.add(qs_name)
        for n in app.names:
            if n and n != qs_name:
                alias_owner.setdefault(n, qs_name)
        for n in app.absorbed:
            if n and n != qs_name:
                alias_owner.setdefault(n, qs_name)

        if existing is None:
            ServiceRegistry.objects.create(
                canonical_name=qs_name, aliases=aliases, domains=domains,
                server_ips=server_ips, os_type=os_type, port=port,
                supervisor_program=app.supervisor_program or '',
                jenkins_job=app.jenkins_job or '',
                git_project=app.git_project or '',
                app_log_path=app.app_log_path or '',
                nginx_access_log=app.nginx_access_log or '',
                nginx_error_log=app.nginx_error_log or '',
                status='candidate', source='auto',
                confidence=confidence,
            )
            created += 1
            continue

        # 已存在：并集补充 + 填空；confirmed/manual 不覆盖人工字段
        changed = False
        new_aliases = _merge_list(existing.aliases, aliases)
        new_domains = _merge_list(existing.domains, domains)
        new_ips = _merge_list(existing.server_ips, server_ips)
        if new_aliases != (existing.aliases or []):
            existing.aliases = new_aliases; changed = True
        if new_domains != (existing.domains or []):
            existing.domains = new_domains; changed = True
        if new_ips != (existing.server_ips or []):
            existing.server_ips = new_ips; changed = True
        # 机器发现拥有(candidate+auto)的记录：用最新发现结果覆盖，自愈陈旧/错误值
        # （如历史 bug 把 app_log_path 写成 "(10)"、或早期没关联上 nginx/jenkins）。
        # 人工 confirmed/manual 记录：只填空，绝不覆盖人工内容（红线）。
        auto_owned = (existing.status == 'candidate' and existing.source == 'auto')
        for field, val in (('port', port), ('os_type', os_type),
                           ('supervisor_program', app.supervisor_program),
                           ('jenkins_job', app.jenkins_job),
                           ('git_project', app.git_project),
                           ('app_log_path', app.app_log_path),
                           ('nginx_access_log', app.nginx_access_log),
                           ('nginx_error_log', app.nginx_error_log)):
            if val in (None, '', 'unknown'):
                continue
            cur = getattr(existing, field)
            if auto_owned:
                if cur != val:
                    setattr(existing, field, val); changed = True
            elif cur in (None, '', 'unknown', 0):
                setattr(existing, field, val); changed = True
        if changed:
            # 机器记录：confidence 用最新一次发现替换（避免反复发现导致无限增长）；
            # 人工记录：追加，保留历史佐证。
            if auto_owned:
                existing.confidence = confidence
            else:
                existing.confidence = (existing.confidence + '\n' if existing.confidence else '') + confidence
            existing.save()
            updated += 1
        else:
            skipped += 1

    # ---- 清理"陈旧拆分记录"----
    # 本次发现把同一个应用的多条候选合并后，旧记录的 canonical_name 已变成合并后
    # 记录的别名（如旧的 tasklist.4307.com / h5858_ywops@10.2.x.x 现都归到一条）。
    # 只删机器自己产出的 candidate+auto；人工 confirmed/manual 一律不碰（红线）。
    # 删除是可逆的：下次发现会按最新规则重新生成，且合并后记录已带齐全部字段；
    # 历史排查任务不会丢（AnalysisTask.service 是 SET_NULL，只断开关联）。
    stale = list(ServiceRegistry.objects.filter(status='candidate', source='auto'))
    for old in stale:
        nm = old.canonical_name
        if nm in live_names:
            continue
        owner = alias_owner.get(nm)
        if owner and owner in live_names:
            old.delete()
            retired += 1
            logger.info('清理陈旧拆分记录 %s → 已并入 %s', nm, owner)

    return {'created': created, 'updated': updated, 'skipped': skipped,
            'retired': retired, 'total_apps': len(apps)}


# ------------------------------------------------------------------ 编排

def mark_services_online(alive_ips):
    """把"本次发现确认在线"的服务器 IP 对应的服务登记，刷新 last_online_at=now。

    仅按主机可达性(能 ping 通/能采到 supervisor)判定"在线"，据此在列表里显示
    "最近在线多久"。长期关机/停用的机器不会被刷新，其 last_online_at 会停在
    上次在线时间，从而自然暴露"已停很久"的应用。返回被刷新的记录数。"""
    from django.utils import timezone
    from opsanalysis.models import ServiceRegistry
    alive = set(str(x) for x in (alive_ips or []))
    if not alive:
        return 0
    now = timezone.now()
    n = 0
    for svc in ServiceRegistry.objects.all():
        ips = set(str(x) for x in (svc.server_ips or []))
        if ips & alive:
            # 只更新 last_online_at，不动 updated_at(它表示"内容"变更)
            ServiceRegistry.objects.filter(pk=svc.pk).update(last_online_at=now)
            n += 1
    return n


def run_discovery(initiated_by='system'):
    """执行一次完整只读发现，返回 {'ok','summary','stats','errors'}。"""
    errors = []
    nginx_data = None
    jenkins_data = None
    try:
        nginx_data = collect_nginx(initiated_by=initiated_by)
        if nginx_data is None and _cfg().get('NGINX_HOST'):
            errors.append('nginx 采集失败或未返回')
    except Exception as e:
        errors.append('nginx 采集异常: %s' % e)
    try:
        jenkins_data = collect_jenkins(initiated_by=initiated_by)
        if jenkins_data is None and _cfg().get('JENKINS_HOST'):
            errors.append('jenkins 采集失败或未返回')
    except Exception as e:
        errors.append('jenkins 采集异常: %s' % e)

    # supervisor 扫描范围：显式配置 > nginx/jenkins 发现的部署 IP
    hosts = list(_cfg().get('SUPERVISOR_HOSTS') or [])
    if not hosts:
        found = set()
        if nginx_data:
            for u in (nginx_data.get('upstreams') or []):
                for m in (u.get('servers') or []):
                    if m.get('ip') and _looks_like_ip(m['ip']):
                        found.add(m['ip'])
        if jenkins_data:
            for job in (jenkins_data.get('jobs') or []):
                for ip in (job.get('deploy_ips') or []):
                    if _looks_like_ip(ip):
                        found.add(ip)
        hosts = sorted(found)

    sup_by_ip = {}
    alive_ips = set()
    offline_ips = []
    for ip in hosts:
        # 先探存活：明确不在线(关机)的机器直接跳过，不再下发采集，省时也避免误报不可达。
        # 无法判定(None，多为 ICMP 被拦)时保守起见照常采集。
        alive = host_alive(ip)
        if alive is False:
            offline_ips.append(ip)
            continue
        if alive is True:
            alive_ips.add(ip)
        try:
            progs = collect_supervisor(ip, initiated_by=initiated_by)
            if progs:
                sup_by_ip[ip] = progs
                alive_ips.add(ip)   # 能采到程序即证明在线
        except Exception as e:
            errors.append('supervisor 采集异常 %s: %s' % (ip, e))

    apps = correlate(nginx_data, jenkins_data, sup_by_ip)
    stats = upsert_apps(apps, initiated_by=initiated_by)
    online_marked = mark_services_online(alive_ips)
    if offline_ips:
        errors.append('已跳过 %d 台未开机/不可达服务器（不下发采集）：%s'
                      % (len(offline_ips), ', '.join(offline_ips)))
    summary = {
        'nginx_host': _cfg().get('NGINX_HOST') or '',
        'jenkins_host': _cfg().get('JENKINS_HOST') or '',
        'upstreams': len((nginx_data or {}).get('upstreams') or []),
        'jenkins_jobs': len((jenkins_data or {}).get('jobs') or []),
        'supervisor_hosts': len(sup_by_ip),
        'offline_hosts': offline_ips,
        'online_marked': online_marked,
    }
    logger.info('ops discovery 完成: %s stats=%s errors=%s', summary, stats, errors)
    return {'ok': True, 'summary': summary, 'stats': stats, 'errors': errors}
