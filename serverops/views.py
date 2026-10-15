"""服务器运维模块视图：命令控制台 + 执行记录 + 运维问答。

权限口径与 tiers.py 的判级一一对应：
  L1 只读 → 任何 SSO 登录用户
  L2 / L3 → 仅管理员（角色含"兼职信息化管理员"）
  L3 额外 → 必填执行原因

两条实现约定：
  1) 判级一律在【服务端重算】，绝不信前端传来的 tier——前端那份只用于即时回显。
     提交时按 command + targets + mode 重新判一遍，否则改一下请求体就能把 L3 说成 L1。
  2) L3 不设手输确认口令（别加回来）。它拦不住误操作——口令就显示在页面上，
     复制粘贴即可——只会给每次下发添一道无意义的摩擦。
     真正的收口是：管理员角色 + 必填理由 + 提交前二次确认 + 全量留痕 + 灰度。

问答窗只要 @sso_required：提问不执行任何东西，模型也没有执行能力，
把它锁在管理员后面只会让"记不住命令"的人重新回到手敲 SSH。
"""
import json
import logging
import re
import uuid

from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.views.decorators.http import require_POST

from resize.sso_utils import get_sso_username, is_admin, sso_required

from serverops.models import ChatMessage, ServerOpsJob
from serverops.services import recipes, runner, tiers

logger = logging.getLogger(__name__)

PAGE_SIZE = 30
MAX_TARGETS = 200
MAX_COMMAND_LEN = 20000
# 整批墙钟上限。1800s 已经很宽——Celery 是 -P solo 单 worker，一个任务卡住
# 整个平台都不动，故不提供"无限等待"这一档。
TIMEOUT_CHOICES = (60, 120, 300, 600, 1200, 1800)
DEFAULT_TIMEOUT = 300

# 目标主机标识：只允许 IP 或主机名里会出现的字符。
# 逗号会破坏 ansible 的 pattern 分隔，空格/引号/`$` 会牵涉多层转义，
# 一律在入口挡掉——不是怕注入（下发前还有 _sh 单引号保护），是怕"看起来提交了、
# 实际 ansible 匹配到的是另一批机器"这种更难的错。
_TARGET_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')

DRAFT_KEY = 'serverops_draft'
CHAT_SESSION_KEY = 'serverops_chat_session'


# ------------------------------------------------------------------ 小工具

def _json_body(request):
    """取 JSON 请求体；不是合法 JSON 就退回 POST 表单（两种调用方式都容得下）。"""
    try:
        return json.loads(request.body.decode('utf-8') or '{}')
    except (ValueError, UnicodeDecodeError):
        return request.POST


def _inventory_for(os_type):
    from opsanalysis.services.sync import linux_inventory, windows_inventory
    return windows_inventory() if os_type == 'windows' else linux_inventory()


def _split_hosts(values):
    """把表单里的主机字段摊平成去重的有序列表。

    控制台的 targets 是一个 hidden 输入，值是空格拼接的一整串；
    但历史提交（和测试）会发多个 targets 字段。两种都在这拆，别各写一份。
    """
    out = []
    for v in values or []:
        for t in re.split(r'[\s,;]+', str(v or '')):
            t = t.strip()
            if t and t not in out:
                out.append(t)
    return out


def _collect_targets(request):
    """取本次目标主机，返回 (合法列表, 非法列表)。

    资产表里的主机和手填的 IP 走的是同一个字段：搜索框能点到就用点，
    点不到（不在资产表里）就把 IP 敲进搜索框回车，两者都落进 targets。
    """
    out, bad = [], []
    for t in _split_hosts(request.POST.getlist('targets')):
        if _TARGET_RE.match(t):
            out.append(t)
        elif t not in bad:
            bad.append(t)
    return out, bad


def _os_guess(host):
    """只依据资产表字段本地猜 OS，不 SSH、不查控制机（打开页面不能等几秒）。

    猜不出来就返回 ''，页面上标"未识别"让用户自己确认。真正的权威判定发生在
    下发那一刻：机器不在 windows_dynamic.ini 里，WinRM 就连不上，结果会如实报
    unreachable——这比这里猜得准，也是我们不在此处猜死的原因。
    """
    blob = '%s %s' % (host.ansible_group or '', host.os_version or '')
    low = blob.lower()
    if any(k in low for k in ('linux', 'centos', 'ubuntu', 'rhel', 'debian', 'kylin')):
        return 'linux'
    if 'win' in low:
        return 'windows'
    return ''


def _host_rows():
    from firewall.models import FirewallHost
    rows = []
    for h in FirewallHost.objects.filter(enabled=True).order_by('ip'):
        rows.append({
            'ip': h.ip, 'hostname': h.hostname,
            'os_version': h.os_version or '', 'department': h.department or '',
            'is_online': h.is_online, 'os_guess': _os_guess(h),
        })
    return rows


def _stash_draft(request, extra=None):
    """校验失败时把用户填的东西存进 session，重定向后回填。

    一条几百字的 PowerShell 因为"忘了填原因"被整页丢掉，是最容易让人放弃这个
    模块、转回手敲 SSH 的体验问题。
    """
    data = {k: request.POST.get(k, '')
            for k in ('command', 'os_type', 'mode', 'reason', 'canary', 'timeout_sec')}
    # targets 归一化成列表：草稿要能直接喂给搜索框重建 chips，
    # 不该让模板去猜它这次是一串还是一个数组。
    data['targets'] = _split_hosts(request.POST.getlist('targets'))
    data['become'] = 'on' if request.POST.get('become') else ''
    data.update(extra or {})
    try:
        request.session[DRAFT_KEY] = data
    except Exception:
        logger.warning('草稿写入 session 失败（忽略）', exc_info=True)
    return data


def _take_draft(request):
    """取出并清掉草稿（只回填一次，避免刷新页面又冒出旧内容）。"""
    try:
        data = request.session.pop(DRAFT_KEY, None)
        if data is not None:
            request.session.modified = True
        return data or {}
    except Exception:
        return {}


# ------------------------------------------------------------------ 命令控制台

@sso_required
def console(request):
    """命令控制台 + 运维问答：一页里选机器、写命令、看判级、下发。

    两个页面原来分开，问答里点"填入控制台"要跨页传命令（sessionStorage），
    用户得在两页之间来回跳。合到一页之后"填入控制台"就是页内一个赋值动作，
    提问用的系统也直接跟着左边的目标系统走，少一份状态、也少一处不同步。

    页面上必须出现三样东西，缺一样就等于把风险藏起来了：
      ① 实际下发到控制机的完整命令串（不是用户敲的那一行）；
      ② 全量主机清单（不是"已选 12 台"这个数字）；
      ③ 判级依据（命中了哪些模式、哪些段认不出来）。
    """
    if request.GET.get('new'):
        try:
            request.session.pop(CHAT_SESSION_KEY, None)
            request.session.modified = True
        except Exception:
            pass
        return redirect('serverops_console')

    draft = _take_draft(request)
    os_type = (draft.get('os_type') or request.GET.get('os') or 'windows').strip()
    if os_type not in ('windows', 'linux'):
        os_type = 'windows'
    mode = draft.get('mode') or ('powershell' if os_type == 'windows' else 'shell')
    if os_type == 'linux':
        mode = 'shell'
    elif mode not in ('powershell', 'win_cmd'):
        mode = 'powershell'

    hosts = _host_rows()
    selected = _split_hosts(draft.get('targets'))
    sid = _chat_session(request)
    # QuerySet 不支持负数切片（会抛 ValueError），"最近 40 条"得倒序取再翻回来。
    chat_msgs = list(ChatMessage.objects.filter(session=sid)
                     .order_by('-id')[:40])[::-1]

    from opsanalysis.services import llm

    return render(request, 'serverops/console.html', {
        'hosts': hosts,
        'host_total': len(hosts),
        'os_type': os_type,
        'mode': mode,
        'modes': ServerOpsJob.MODES,
        'inventory': _inventory_for(os_type),
        'linux_inventory': _inventory_for('linux'),
        'windows_inventory': _inventory_for('windows'),
        'timeouts': TIMEOUT_CHOICES,
        'timeout_sec': int(draft.get('timeout_sec') or DEFAULT_TIMEOUT),
        'draft': draft,
        'selected': selected,
        # 两套速查都下发到页面：切换 Windows/Linux 时纯前端换一组按钮即可，
        # 不必重新请求页面——否则写了一半的 PowerShell 会被整页刷掉。
        'recipes_win': recipes.WINDOWS,
        'recipes_linux': recipes.LINUX,
        'recipes_change_win': recipes.WINDOWS_CHANGE,
        'recipes_change_linux': recipes.LINUX_CHANGE,
        'max_targets': MAX_TARGETS,
        'admin': is_admin(request),
        'username': get_sso_username(request) or 'system',
        'recent_jobs': ServerOpsJob.objects.all()[:5],
        # 问答窗现在也在这同一页里，所以下面这几项和 console 的表单一起下发
        'messages_list': chat_msgs,
        'llm_enabled': llm.enabled(),
        'llm_reason': llm.disabled_reason(),
        'llm_model': (llm.config() or {}).get('MODEL', ''),
    })


@sso_required
def api_classify(request):
    """实时判级。前端边打字边问，回显等级/依据/需要哪些额外确认。

    这个接口只判级、不执行，故不做管理员限制——让非管理员也能看到"这条为什么
    要管理员"，比直接给他一个灰按钮强。真正的门槛在 job_run 里重算一遍。
    """
    data = _json_body(request)
    command = (data.get('command') or '').strip()
    targets = data.get('targets') or []
    if isinstance(targets, str):
        targets = [t for t in re.split(r'[\s,;]+', targets) if t]
    targets = [str(t).strip() for t in targets if _TARGET_RE.match(str(t).strip())][:MAX_TARGETS]
    os_type = data.get('os_type') or ''
    mode = data.get('mode') or ''

    res = tiers.classify(command, targets=targets, os_type=os_type, mode=mode)
    res['admin_required'] = bool(res.get('needs_admin'))
    res['is_admin'] = is_admin(request)
    res['allowed'] = (not res.get('needs_admin')) or is_admin(request)
    res['target_count'] = len(targets)
    # 把实际会下发的命令串回显出来：用户看到的必须等于将要执行的
    if command and targets and os_type in ('windows', 'linux'):
        try:
            stub = ServerOpsJob(
                os_type=os_type, mode=('shell' if os_type == 'linux' else (mode or 'powershell')),
                command=command, inventory=_inventory_for(os_type),
                become=bool(data.get('become')) and os_type == 'linux',
            )
            res['resolved_command'] = runner.build_command(stub, targets)
        except Exception:
            logger.warning('判级接口回显命令串失败（忽略）', exc_info=True)
            res['resolved_command'] = ''
    else:
        res['resolved_command'] = ''
    return JsonResponse(res)


@require_POST
@sso_required
def job_run(request):
    """提交一次批量执行。判级、权限、原因全部在此重算，不信前端。"""
    command = (request.POST.get('command') or '').strip()
    if not command:
        _stash_draft(request)
        messages.error(request, '命令不能为空。')
        return redirect('serverops_console')
    if len(command) > MAX_COMMAND_LEN:
        _stash_draft(request)
        messages.error(request, '命令过长（%d 字符，上限 %d）。请拆成多次下发。'
                       % (len(command), MAX_COMMAND_LEN))
        return redirect('serverops_console')

    targets, bad = _collect_targets(request)
    if bad:
        _stash_draft(request)
        messages.error(request, '这些主机标识含非法字符，已拒绝：%s（只允许字母、数字、'
                                '点、下划线、连字符）' % '、'.join(bad[:10]))
        return redirect('serverops_console')
    if not targets:
        _stash_draft(request)
        messages.error(request, '请至少选择一台目标主机。')
        return redirect('serverops_console')
    if len(targets) > MAX_TARGETS:
        _stash_draft(request)
        messages.error(request, '一次最多下发 %d 台（本次 %d 台）。请分批执行。'
                       % (MAX_TARGETS, len(targets)))
        return redirect('serverops_console')

    os_type = (request.POST.get('os_type') or '').strip()
    if os_type not in ('windows', 'linux'):
        _stash_draft(request)
        messages.error(request, '请选择目标系统类型（Windows / Linux）。')
        return redirect('serverops_console')

    mode = (request.POST.get('mode') or '').strip()
    if os_type == 'linux':
        mode = 'shell'
    elif mode not in ('powershell', 'win_cmd'):
        mode = 'powershell'

    become = bool(request.POST.get('become'))
    if become and os_type == 'windows':
        _stash_draft(request)
        messages.error(request, 'Windows 不走 sudo/become：WinRM 用的账号本身就是管理员账号，'
                                '请取消勾选"提权执行"。')
        return redirect('serverops_console')

    cls = tiers.classify(command, targets=targets, os_type=os_type, mode=mode)
    tier = cls['tier']
    username = get_sso_username(request) or 'system'

    if cls['needs_admin'] and not is_admin(request):
        _stash_draft(request)
        messages.error(request, '这条命令判定为 %s（%s），需要"兼职信息化管理员"角色才能执行。'
                                '当前账号：%s。只读命令（L1）任何登录用户都可以执行。'
                       % (tier, cls['label'], username))
        return redirect('serverops_console')

    reason = (request.POST.get('reason') or '').strip()
    if cls['needs_reason'] and len(reason) < 4:
        _stash_draft(request)
        messages.error(request, '%s 级命令必须填写执行原因（至少 4 个字）。'
                                '这条原因会随命令一起进留痕，事后追溯全靠它。' % tier)
        return redirect('serverops_console')

    canary = (request.POST.get('canary') or '').strip()
    if canary and canary not in targets:
        _stash_draft(request)
        messages.error(request, '灰度主机 %s 不在本次目标清单里。灰度必须是清单中的一台，'
                                '否则"先试一台"就没有意义。' % canary)
        return redirect('serverops_console')

    try:
        timeout_sec = int(request.POST.get('timeout_sec') or DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        timeout_sec = DEFAULT_TIMEOUT
    if timeout_sec not in TIMEOUT_CHOICES:
        timeout_sec = DEFAULT_TIMEOUT

    job = ServerOpsJob.objects.create(
        os_type=os_type, mode=mode, command=command, tier=tier,
        tier_detail=cls, targets=targets, inventory=_inventory_for(os_type),
        become=become, canary=canary, status='pending', created_by=username,
        reason=reason, timeout_sec=timeout_sec,
    )
    # 实际下发的命令串在下发【之前】就落库：万一执行过程崩了，
    # 至少还能查到"当时准备发的是什么"。
    try:
        job.resolved_command = runner.build_command(job, targets)
        job.save(update_fields=['resolved_command'])
    except Exception:
        logger.exception('生成 resolved_command 失败（job #%s）', job.pk)

    try:
        from serverops.tasks import run_serverops_job
        run_serverops_job.delay(job.id)
    except Exception as exc:
        # broker 挂了/worker 没起：任务会永远停在 pending 且没有任何提示，
        # 这是最难查的一类"点了没反应"。故当场标失败并说明原因。
        logger.exception('派发 serverops 任务失败（job #%s）', job.pk)
        job.status = 'failed'
        job.error = ('任务派发失败（Celery 不可用）：%s: %s。'
                     '命令【未下发】到任何主机。请检查 worker 是否在运行。'
                     % (type(exc).__name__, exc))[:4000]
        job.finished_at = timezone.now()
        job.save(update_fields=['status', 'error', 'finished_at'])
        messages.error(request, '任务派发失败，命令未下发：%s' % exc)
        return redirect('serverops_job_detail', pk=job.pk)

    level = '%s（%s）' % (tier, cls['label'])
    messages.success(request, '已提交：%s → %d 台 %s 机器，判级 %s。正在执行，稍候自动刷新。'
                     % (command[:60], len(targets), os_type, level))
    return redirect('serverops_job_detail', pk=job.pk)


# ------------------------------------------------------------------ 执行记录

@sso_required
def job_list(request):
    """执行记录：谁、什么时候、对哪些机器、发了什么、结果如何。"""
    qs = ServerOpsJob.objects.all()
    f_tier = request.GET.get('tier') or ''
    f_status = request.GET.get('status') or ''
    f_os = request.GET.get('os_type') or ''
    f_by = (request.GET.get('created_by') or '').strip()
    f_q = (request.GET.get('q') or '').strip()
    start = parse_date(request.GET.get('start') or '') or None
    end = parse_date(request.GET.get('end') or '') or None

    if f_tier in ('L1', 'L2', 'L3'):
        qs = qs.filter(tier=f_tier)
    if f_status == 'not_success':
        qs = qs.filter(status__in=('failed', 'partial', 'aborted'))
    elif f_status:
        qs = qs.filter(status=f_status)
    if f_os in ('windows', 'linux'):
        qs = qs.filter(os_type=f_os)
    if f_by:
        qs = qs.filter(created_by__icontains=f_by)
    if f_q:
        qs = qs.filter(command__icontains=f_q)
    if start:
        qs = qs.filter(created_at__date__gte=start)
    if end:
        qs = qs.filter(created_at__date__lte=end)

    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get('page'))
    return render(request, 'serverops/job_list.html', {
        'page': page,
        'tiers': ServerOpsJob.TIERS,
        'statuses': ServerOpsJob.STATUSES,
        'f_tier': f_tier, 'f_status': f_status, 'f_os': f_os,
        'f_by': f_by, 'f_q': f_q,
        'start': start.isoformat() if start else '',
        'end': end.isoformat() if end else '',
        'people': sorted(set(ServerOpsJob.objects.values_list('created_by', flat=True)
                             .distinct())),
        'stat_total': ServerOpsJob.objects.count(),
        'stat_l3': ServerOpsJob.objects.filter(tier='L3').count(),
        'stat_bad': ServerOpsJob.objects.filter(
            status__in=('failed', 'partial', 'aborted')).count(),
    })


@sso_required
def job_detail(request, pk):
    """单次执行的完整交代：命令、判级依据、逐台结果、控制机留痕。

    逐台结果一律展开可见（不做"只看失败的"默认筛选）：批量执行最容易出的事故是
    "汇总说成功了，其实有 3 台 unreachable"，把成功的藏起来、把失败的摊开，
    才不会有这种错觉。
    """
    job = get_object_or_404(ServerOpsJob, pk=pk)
    results = list(job.host_results.all())
    logs = list(job.exec_logs())
    return render(request, 'serverops/job_detail.html', {
        'job': job,
        'results': results,
        'detail': job.tier_detail or {},
        'logs': logs,
        # 本页已内嵌本次任务的留痕；这个链接是去"平台所有 serverops 下发"的全量视图
        'sys_execlog_url': '/sysmanage/execlogs/?module=serverops',
    })


@sso_required
def api_job(request, pk):
    """轮询任务进度。返回汇总数字，页面在任务结束后整页刷新拿完整明细。"""
    job = get_object_or_404(ServerOpsJob, pk=pk)
    return JsonResponse({
        'status': job.status,
        'status_label': job.get_status_display(),
        'finished': job.finished,
        'ok': job.ok_count, 'failed': job.failed_count,
        'unreachable': job.unreachable_count, 'skipped': job.skipped_count,
        'total': job.target_count,
        'duration_ms': job.duration_ms,
        'error': job.error[:500],
    })


# ------------------------------------------------------------------ 运维问答

def _chat_session(request):
    """当前用户的会话标识：存在 Django session 里，"开启新会话"时重置。"""
    sid = ''
    try:
        sid = request.session.get(CHAT_SESSION_KEY) or ''
    except Exception:
        pass
    if not sid:
        sid = uuid.uuid4().hex[:12]
        try:
            request.session[CHAT_SESSION_KEY] = sid
        except Exception:
            pass
    return sid


@sso_required
def chat_view(request):
    """旧问答页入口，已停用：跳转到命令控制台。

    问答窗现在就在控制台右侧，"填入控制台"不必再跨页传命令。路由和 name 都留着
    是因为导航、收藏夹和 chat_history 里的链接都指向它；这里再删就成 404 了。
    """
    return redirect('serverops_console')


@sso_required
def api_chat_send(request):
    """发一个问题：落两行（user + pending 的 assistant），派发任务，立刻返回。

    不在这里同步等模型：思考型模型 10~60s，nginx 的读超时比这短，同步等必然
    偶发 504，而且 -P solo 的 worker 会被 HTTP 请求占住。
    """
    data = _json_body(request)
    content = (data.get('content') or '').strip()
    if not content:
        return JsonResponse({'ok': False, 'error': '问题不能为空'}, status=400)
    if len(content) > 8000:
        return JsonResponse({'ok': False, 'error': '问题过长（上限 8000 字符）'}, status=400)

    from opsanalysis.services import llm
    if not llm.enabled():
        return JsonResponse({'ok': False,
                             'error': '大模型未启用：%s' % (llm.disabled_reason() or '')},
                            status=503)

    sid = _chat_session(request)
    who = get_sso_username(request) or 'system'
    os_type = (data.get('os_type') or '').strip()
    if os_type not in ('windows', 'linux'):
        os_type = ''
    host = str(data.get('host') or '').strip()[:128]

    ChatMessage.objects.create(session=sid, role='user', content=content,
                               status='done', os_type=os_type, host=host,
                               created_by=who)
    reply = ChatMessage.objects.create(session=sid, role='assistant', content='',
                                       status='pending', os_type=os_type, host=host,
                                       created_by=who)
    try:
        from serverops.tasks import run_chat_reply
        run_chat_reply.delay(reply.id)
    except Exception as exc:
        logger.exception('派发问答任务失败')
        reply.status = 'failed'
        reply.ok = False
        reply.error = '任务派发失败（Celery 不可用）：%s: %s' % (type(exc).__name__, exc)
        reply.save(update_fields=['status', 'ok', 'error'])
    return JsonResponse({'ok': True, 'id': reply.id, 'session': sid})


@sso_required
def api_chat_poll(request, pk):
    msg = get_object_or_404(ChatMessage, pk=pk)
    return JsonResponse({
        'id': msg.pk, 'status': msg.status, 'role': msg.role,
        'content': msg.content, 'error': msg.error,
        'model': msg.model, 'latency_ms': msg.latency_ms,
        'finished': msg.status != 'pending',
    })


@sso_required
def chat_history(request):
    """问答历史：按会话分组，方便回看"上次那条命令是怎么问出来的"。"""
    qs = ChatMessage.objects.filter(role='user').order_by('-id')
    f_q = (request.GET.get('q') or '').strip()
    if f_q:
        qs = qs.filter(content__icontains=f_q)
    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get('page'))

    # 提问与回答是两行，配对要按"同会话里紧随其后的那条 assistant"来算。
    # 一次性取回本页涉及会话的相关行再线性配对，避免每行一次查询。
    items = []
    rows = list(page)
    if rows:
        lo = min(m.pk for m in rows)
        sessions = {m.session for m in rows}
        waiting = {}
        reply_of = {}
        for r in ChatMessage.objects.filter(session__in=sessions, id__gte=lo
                                            ).order_by('session', 'id'):
            if r.role == 'user':
                waiting[r.session] = r.pk
            elif r.role == 'assistant':
                qid = waiting.pop(r.session, None)
                if qid is not None:
                    reply_of[qid] = r
        items = [{'q': m, 'a': reply_of.get(m.pk)} for m in rows]

    return render(request, 'serverops/chat_history.html', {
        'page': page, 'items': items, 'f_q': f_q,
        'stat_total': ChatMessage.objects.filter(role='user').count(),
        'stat_failed': ChatMessage.objects.filter(role='assistant', ok=False).count(),
        'stat_sessions': ChatMessage.objects.filter(role='user'
                            ).values_list('session', flat=True).distinct().count(),
    })
