"""批量远程执行：把一条命令通过 ansible ad-hoc 下发到多台机器，并逐台取回结果。

为什么走 ad-hoc 而不是新写 playbook：
  1) 复用既有收口。全平台只有两处远程执行通道（run_playbook / ssh_exec），两处
     都已接 sysmanage.ExecLog 留痕；ad-hoc 走 ssh_exec，天然就有留痕，不必再埋点。
     新增执行通道而不接留痕，正是"任务没有日志"这个老毛病的成因。
  2) 命令是用户输入的任意文本。若走 playbook，就得用 -e cmd= 把它塞进 Jinja
     模板里再 {{ cmd }} 展开——引号、反斜杠、`$`、`{{` 每一样都是一个转义坑，
     而且每加一个 playbook 就多一条同步链路。ad-hoc 的 -a 是一个整体字符串，
     控制机侧只需一次 shell 单引号转义（_sh），目标机侧再按 mode 分别处理。

Windows 为什么必须走 -EncodedCommand：
  用户命令是任意文本，要穿过两层解析才到目标机：控制机侧 shell → ansible -a →
  目标机侧 PowerShell。`|`、`&&`、单双引号、反引号、`$`、`{{`、中文，每一样都能
  在其中一层被吃掉或改写，而 `-File ''` 这种空实参还会直接让整次执行 rc=1。
  把整段 PowerShell 编成 UTF-16LE 的 base64，目标机侧就只剩"解码后原样执行"，
  两层解析全部绕开（控制机侧仍由 _sh 单引号保护，而 base64 字母表里不含单引号）。
  注意 win_shell 本身就在 PowerShell 里跑（经 cmd.exe 的是 win_command），所以这里
  是"PowerShell 里再套一层 powershell.exe"——子进程的进度流必须掐掉，见 PS_PRELUDE。

红线：本模块【可写】，与 opsanalysis 的"全程只读"是两个 app 的边界所在。
但可写不等于不留痕——每一次下发都必然产生一条 ExecLog（ssh_exec 内部写），
每一台机器的 rc/stdout/stderr 都必然落 ServerOpsHostResult。解析失败时保留
ansible 原文并把任务标 failed，绝不"猜"一个看起来正常的结果出来。
"""
import base64
import json
import logging
import time

from django.conf import settings
from django.utils import timezone

from opsanalysis.services.sync import _sh, ssh_exec

from serverops.models import ServerOpsHostResult

logger = logging.getLogger(__name__)

# 并发数：WinRM 握手慢，太大反而把控制机压垮；10 是 firewall/AV 模块的既有经验值
FORKS = 10
# 单机输出留存上限（字符）。批量执行时每台都留全量的话，一次 60 台就能写进几十 MB，
# 故按"头 + 尾各半"截断并【显式标注】——静默截断是本模块明确禁止的行为。
HOST_STDOUT_KEEP = 20000
HOST_STDERR_KEEP = 4000
# ansible 原始输出留存上限
RAW_KEEP = 200000
# 连接超时（ansible --timeout），与整批墙钟上限 timeout_sec 不是一回事
CONNECT_TIMEOUT = 20


def _clip(text, keep):
    """返回 (留存文本, 原始长度, 是否截断)。截断必须显式声明，不能静默丢。"""
    s = text if isinstance(text, str) else ('' if text is None else str(text))
    n = len(s)
    if n <= keep:
        return s, n, False
    half = keep // 2
    return ('%s\n…[中间省略 %d 字符，完整输出未留存]…\n%s'
            % (s[:half], n - half * 2, s[-half:])), n, True


def _adhoc_bin():
    """ad-hoc 用的 ansible 可执行文件路径。

    从 PLAYBOOK_BIN 推导而不是新增配置项：配置项越多，"控制机上到底用的哪个
    二进制"越难对齐；两者本来就同目录同前缀（/usr/bin/ansible-playbook ↔
    /usr/bin/ansible）。
    """
    cfg = settings.ANSIBLE_CONFIG or {}
    apb = cfg.get('PLAYBOOK_BIN') or '/usr/bin/ansible-playbook'
    if 'ansible-playbook' in apb:
        return apb.replace('ansible-playbook', 'ansible')
    return 'ansible'


def ps_encoded(script):
    """把 PowerShell 脚本编成 -EncodedCommand 需要的 base64(UTF-16LE)。

    去掉可能存在的 BOM：powershell.exe 收到带 BOM 的解码结果会把 BOM 当成
    第一条语句的一部分，报一个极难看懂的解析错误。
    """
    s = (script or '').lstrip('\ufeff')
    return base64.b64encode(s.encode('utf-16-le')).decode('ascii')


# 下发前必须先在目标机的子 powershell 里关掉进度流。
#
# 不关的后果：win_shell 自己就跑在 PowerShell 里，我们再套一层 powershell.exe，
# 子进程的进度流会被序列化成 CLIXML 写到 stderr（形如 `#< CLIXML` +
# `<Obj S="progress">...<AV>Preparing modules for first use.</AV>`）。
# PowerShell 5.1 里"原生命令往 stderr 写字"会被外层包成 NativeCommandError，
# 于是命令明明跑成功了、rc 也是 0，任务却被判 failed，而报出来的"错误"
# 只有那条进度记录，没有任何真实错误内容——运维根本无从下手。
#
# 只动 $ProgressPreference：它纯装饰性，不影响命令结果、不影响退出码，
# 也不会吞掉真正的报错。$ErrorActionPreference 一律不碰。
PS_PRELUDE = "$ProgressPreference='SilentlyContinue'; "

# PowerShell 硬性规定这几样必须是脚本的第一条语句，前置任何东西都会变成
# "param 不被识别"这类解析错误。用户往命令框里粘一段带 param() 的脚本时，
# 宁可不抑制进度流（顶多多一条 CLIXML 噪声），也不能让脚本直接跑不起来。
PS_MUST_BE_FIRST = ('param(', 'param (', '[cmdletbinding(', '#requires')


def _needs_prelude(script):
    head = (script or '').lstrip('\ufeff').lstrip()
    return not head.lower().startswith(PS_MUST_BE_FIRST)


def ps_payload(script):
    """真正会被编码下发的 PowerShell 正文：需要时在最前面加上进度流抑制。

    BOM 必须在这里就剥掉：前置语句一加，BOM 就不再位于串首，ps_encoded 里的
    lstrip('\\ufeff') 便剥不到它，于是 BOM 留在脚本中间成了非法字符（U+FEFF），
    报的是极难看懂的解析错误。
    """
    s = (script or '').lstrip('\ufeff')
    return (PS_PRELUDE + s) if _needs_prelude(s) else s


def module_and_args(job):
    """按 os_type/mode 决定 ansible 模块与 -a 的内容。返回 (module, args)。"""
    cmd = job.command or ''
    if job.os_type == 'windows':
        if job.mode == 'powershell':
            # -NonInteractive：目标机上没人能应答交互提示，挂着就是白等一个超时
            return 'win_shell', ('powershell -NoProfile -NonInteractive '
                                 '-ExecutionPolicy Bypass -EncodedCommand %s'
                                 % ps_encoded(ps_payload(cmd)))
        # win_cmd：原文直送 cmd.exe，给坚持要用 netsh/wmic 原生语法的人
        return 'win_shell', cmd
    return 'shell', cmd


def build_command(job, targets):
    """拼出【实际下发到控制机】的完整命令串。

    这个串会原样存进 job.resolved_command 并出现在页面上——用户看到的必须是
    真正会执行的东西，而不是他敲的那一行。少这一层回显，"我以为只跑一台"
    这类事故就无法避免。
    """
    cfg = settings.ANSIBLE_CONFIG or {}
    workdir = (cfg.get('WORKDIR') or '/etc/ansible').rstrip('/')
    pypath = cfg.get('PYTHONPATH', '/opt/venv/lib/python3.12/site-packages')
    export = 'export PYTHONPATH=%s:$PYTHONPATH && ' % pypath if pypath else ''

    module, args = module_and_args(job)
    pattern = ','.join(str(t) for t in targets)
    bits = [
        '%s -i %s %s' % (_adhoc_bin(), _sh(job.inventory), _sh(pattern)),
        '-m %s -a %s' % (module, _sh(args)),
        '-f %d' % FORKS,
        '--timeout %d' % CONNECT_TIMEOUT,
    ]
    if job.become:
        bits.append('-b')
    # ANSIBLE_STDOUT_CALLBACK=json：逐主机 rc/stdout/stderr 只能靠它拿到；
    # 默认 callback 的输出要按 "host | SUCCESS =>" 分段硬解，遇到 CLIXML/多行
    # 就崩。ANSIBLE_HOST_KEY_CHECKING=False：新机器首次连接不能卡在指纹确认上，
    # 那会把 Celery 唯一的 worker 一起挂住。
    env = 'ANSIBLE_STDOUT_CALLBACK=json ANSIBLE_HOST_KEY_CHECKING=False '
    return '%scd %s && %s%s' % (export, workdir, env, ' '.join(bits))


def parse_adhoc(raw):
    """把 JSON callback 的输出解析成逐主机结果；解析不出返回 None。

    返回 None 与返回 [] 是两件不同的事：
      [] → ansible 正常跑完但没匹配到任何主机（inventory 里没有这些 IP）
      None → 输出根本不是预期的 JSON（ansible 版本不同 / 中途被杀 / 混入了警告）
    后者必须把原文留给用户看，不能报成"没有主机"。
    """
    text = (raw or '').strip()
    if not text:
        return None
    # 控制机上偶尔会在 JSON 前面吐 [WARNING] 行（例如 inventory 里的主机名重复），
    # 从第一个 '{' 开始截，避免整段 json.loads 直接失败
    idx = text.find('{')
    if idx < 0:
        return None
    try:
        doc = json.loads(text[idx:])
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict):
        return None

    out = {}
    order = []
    for play in (doc.get('plays') or []):
        if not isinstance(play, dict):
            continue
        for task in (play.get('tasks') or []):
            if not isinstance(task, dict):
                continue
            hosts = task.get('hosts') or {}
            if not isinstance(hosts, dict):
                continue
            for name, body in hosts.items():
                if not isinstance(body, dict):
                    continue
                if name not in out:
                    out[name] = {}
                    order.append(name)
                out[name].update(body)

    # stats 里有、任务里没出现的主机（例如整个 play 就没匹配上）也要交代一句
    for name, st in (doc.get('stats') or {}).items():
        if isinstance(st, dict) and name not in out:
            out[name] = {'_stats': st}
            order.append(name)

    results = []
    for name in order:
        body = out[name]
        if body.get('unreachable'):
            status = 'unreachable'
        elif body.get('skipped'):
            status = 'skipped'
        elif body.get('failed') or (body.get('rc') not in (None, 0)):
            status = 'failed'
        else:
            status = 'ok'
        results.append({
            'host': str(name),
            'status': status,
            'rc': body.get('rc') if isinstance(body.get('rc'), int) else None,
            'stdout': body.get('stdout') or '\n'.join(body.get('stdout_lines') or []) or '',
            'stderr': body.get('stderr') or '',
            'msg': body.get('msg') or '',
            'duration_ms': _delta_ms(body.get('delta')),
        })
    return results


def _delta_ms(delta):
    """ansible 的 delta 形如 '0:00:00.123456'，转成毫秒；转不出返回 0。"""
    if not delta or not isinstance(delta, str):
        return 0
    try:
        hms, _, frac = delta.partition('.')
        h, m, s = [int(x) for x in hms.split(':')]
        return int(((h * 3600 + m * 60 + s) * 1000) + int((frac or '0')[:6].ljust(6, '0')[:3]))
    except (ValueError, AttributeError):
        return 0


def _write_result(job, host, rec, phase):
    out, out_len, trunc = _clip(rec.get('stdout') or '', HOST_STDOUT_KEEP)
    err, _n, _t = _clip(rec.get('stderr') or '', HOST_STDERR_KEEP)
    msg, _m, _mt = _clip(rec.get('msg') or '', HOST_STDERR_KEEP)
    return ServerOpsHostResult.objects.create(
        job=job, host=str(host)[:128], phase=phase,
        status=rec.get('status') or 'failed',
        rc=rec.get('rc'),
        stdout=out, stdout_bytes=out_len, truncated=bool(trunc),
        stderr=err, msg=msg,
        duration_ms=int(rec.get('duration_ms') or 0),
    )


def run_phase(job, targets, phase):
    """对一批主机下发一次，返回 (results_or_None, raw, error)。

    results 为 None 表示"没解析出来"，此时 error 说明原因、raw 是原文——
    调用方必须把 raw 展示出来，这是用户唯一能自查的线索。
    """
    cmd = build_command(job, targets)
    if phase == 'canary':
        # 灰度那一台单独下发，故 resolved_command 以全量那条为准，这里只用于留痕备注
        note = '灰度(canary)：%s' % job.reason[:200]
    else:
        note = job.reason[:200]

    rc, out, err = ssh_exec(
        cmd, timeout=int(job.timeout_sec or 300),
        module='serverops', kind='ansible',
        target=','.join(str(t) for t in targets)[:255],
        task_ref=job.exec_ref, initiated_by=job.created_by or 'system', note=note,
    )

    results = parse_adhoc(out)
    if results is None:
        if not out and err:
            return None, out or err, '控制机命令未返回输出（rc=%s）：%s' % (rc, err[:500])
        return None, out or err, (
            'ansible 输出无法按 JSON 解析（rc=%s）。原文已完整保留在下方，'
            '请据此判断实际结果——本模块不会替它猜一个成功或失败。'
            % rc + ((' stderr: %s' % err[:300]) if err else ''))

    if not results:
        # 正常退出但一台都没匹配上：最常见的原因是 IP 不在该 inventory 里
        return [], out, ('没有匹配到任何主机。请确认这些 IP 已登记在控制机的 %s 中'
                         '（Linux 用 hosts、Windows 用 inventory.d/windows_dynamic.ini）。'
                         % (job.inventory or 'inventory'))

    return results, out, ''


def execute_job(job):
    """按「先灰度、再全量」执行任务，逐台落 ServerOpsHostResult，最后更新汇总。

    灰度(canary)不是可选项里的花架子：批量下发一旦命令写错，60 台机器会一起中招，
    而且没有中途叫停的机会。先在一台上跑、失败即中止，是这个模块唯一能提供的
    "反悔窗口"，故灰度失败时其余主机一律记 skipped 并写明原因。
    """
    job.status = 'running'
    job.started_at = timezone.now()
    job.save(update_fields=['status', 'started_at'])

    targets = [str(t) for t in (job.targets or [])]
    canary = (job.canary or '').strip()
    if canary and canary not in targets:
        canary = ''

    phases = []
    if canary:
        phases.append(('canary', [canary]))
        rest = [t for t in targets if t != canary]
        if rest:
            phases.append(('full', rest))
    else:
        phases.append(('full', targets))

    raws = []
    errors = []
    ok = failed = unreachable = skipped = 0
    aborted = False
    parsed = False
    started = time.monotonic()

    for phase, batch in phases:
        if not batch:
            continue
        results, raw, error = run_phase(job, batch, phase)
        if raw:
            raws.append('===== %s（%d 台）=====\n%s' % (phase, len(batch), raw))
        if error:
            errors.append(error)

        if results is None:
            # 解析不出结果：这一批的每台都记 failed，并说明"原文已保留"。
            # parsed 保持 False —— 页面上要能一眼看出"这次的结果不是解析出来的"。
            for host in batch:
                _write_result(job, host, {
                    'status': 'failed', 'rc': None, 'stdout': '',
                    'stderr': '', 'msg': error or '未能解析 ansible 输出',
                }, phase)
                failed += 1
            aborted = True
            break
        parsed = True

        if not results:
            for host in batch:
                _write_result(job, host, {
                    'status': 'unreachable', 'rc': None, 'stdout': '', 'stderr': '',
                    'msg': 'ansible 未匹配到该主机（inventory 中不存在或名称不一致）',
                }, phase)
                unreachable += 1
            aborted = True
            break

        for rec in results:
            row = _write_result(job, rec['host'], rec, phase)
            if row.status == 'ok':
                ok += 1
            elif row.status == 'unreachable':
                unreachable += 1
            elif row.status == 'skipped':
                skipped += 1
            else:
                failed += 1

        if phase == 'canary' and (failed or unreachable):
            # 灰度未通过 → 剩余主机全部标 skipped，绝不再往下发
            for host in [t for t in targets if t != canary]:
                _write_result(job, host, {
                    'status': 'skipped', 'rc': None, 'stdout': '', 'stderr': '',
                    'msg': '灰度主机 %s 执行未通过，已中止全量下发（命令未发到本机）' % canary,
                }, 'full')
                skipped += 1
            aborted = True
            errors.append('灰度未通过，已中止全量下发。')
            break

    raw_text, _n, raw_trunc = _clip('\n\n'.join(raws), RAW_KEEP)
    job.raw_output = raw_text
    job.raw_truncated = bool(raw_trunc)
    job.parsed = parsed
    job.ok_count = ok
    job.failed_count = failed
    job.unreachable_count = unreachable
    job.skipped_count = skipped
    job.error = '\n'.join(errors)[:4000]
    job.duration_ms = int((time.monotonic() - started) * 1000)
    job.finished_at = timezone.now()

    total = ok + failed + unreachable
    if aborted and not ok and not failed and not unreachable:
        job.status = 'aborted'
    elif failed or unreachable:
        job.status = 'partial' if ok else 'failed'
    elif total == 0:
        job.status = 'aborted'
    else:
        job.status = 'success'
    job.save()
    return job
