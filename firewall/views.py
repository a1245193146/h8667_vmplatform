"""防火墙模块视图（SPEC-firewall.md §6）。

红线（§8）：
- 全部视图 @sso_required；关防火墙/删规则/审批 → fw_admin_required（仅管理员）。
- 页面请求一律读库展示，绝不实时调 Ansible；仅 POST 按钮触发 Celery/Ansible。
- 服务层（rule_engine/analysis/audit/tasks）由其他代理并行开发，
  一律在函数内延迟导入，避免模块合并顺序导致视图无法加载。
"""
import hashlib
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from resize.sso_utils import get_sso_username, sso_required

from firewall.models import (
    AnsibleTaskRecord,
    CommunicationRelation,
    FirewallAuditLog,
    FirewallEvent,
    FirewallHost,
    FirewallRule,
    FirewallRuleRequest,
)
from firewall.serializers import build_dashboard_data
from firewall.utils.rbac import fw_admin_required

PAGE_SIZE = 20


# ---------------------------------------------------------------- 辅助

def _paginate(request, qs):
    """全模块统一分页：20/页，模板变量 page_obj。"""
    return Paginator(qs, PAGE_SIZE).get_page(request.GET.get('page'))


def _query_string(request):
    """保留筛选参数的分页 querystring（去掉 page）。"""
    params = request.GET.copy()
    params.pop('page', None)
    return params.urlencode()


def _audit(username, action, host=None, object_repr='', old=None, new=None,
           task_ref='', result='success', detail=''):
    """写审计：优先走 services.audit.log_action（Agent D），缺失时直写模型。"""
    try:
        from firewall.services.audit import log_action
    except ImportError:
        log_action = None
    if log_action is not None:
        return log_action(username, action, host=host, object_repr=object_repr,
                          old=old, new=new, task_ref=task_ref, result=result,
                          detail=detail)
    return FirewallAuditLog.objects.create(
        username=username, action=action, host=host, object_repr=object_repr,
        old_value=old, new_value=new, ansible_task_ref=task_ref,
        result=result, detail=detail)


def _trigger_collect(host_id):
    """触发 Celery 采集任务；任务层未就绪/提交失败只提示不中断。"""
    try:
        from firewall.tasks.collection import collect_host_task
        collect_host_task.delay(host_id)
        return True
    except Exception:
        return False


def _rule_fingerprint(direction, protocol, program, remote_address,
                      remote_port, local_port=''):
    """优先复用 services.analysis.rule_fingerprint，缺失时本地同口径计算。"""
    try:
        from firewall.services.analysis import rule_fingerprint
    except ImportError:
        rule_fingerprint = None
    if rule_fingerprint is not None:
        return rule_fingerprint(direction, protocol, program, remote_address,
                                remote_port, local_port)
    raw = '|'.join(str(x or '') for x in (
        direction, protocol, program, remote_address, remote_port, local_port))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]


def _get_rule_engine():
    try:
        from firewall.services import rule_engine
    except ImportError:
        return None
    return rule_engine


def _safe_next(request, default='fw_rules'):
    nxt = request.POST.get('next', '')
    if nxt.startswith('/'):
        return nxt
    return default


# ---------------------------------------------------------------- 看板

@sso_required
def dashboard(request):
    """监控看板：KPI + 24h 趋势 + TOP 榜（数据纯查库）。"""
    return render(request, 'firewall/dashboard.html', {
        'data': build_dashboard_data(),
    })


@sso_required
def api_dashboard(request):
    """看板 JSON API（§6 结构冻结）。"""
    return JsonResponse(build_dashboard_data())


# ---------------------------------------------------------------- 主机

@sso_required
def hosts(request):
    qs = FirewallHost.objects.all().order_by('hostname')
    status = request.GET.get('status', '')
    dept = request.GET.get('dept', '')
    q = request.GET.get('q', '').strip()
    if status:
        qs = qs.filter(firewall_status=status)
    if dept:
        qs = qs.filter(department=dept)
    if q:
        qs = qs.filter(hostname__icontains=q) | qs.filter(ip__icontains=q)
    depts = (FirewallHost.objects.exclude(department='')
             .values_list('department', flat=True).distinct().order_by('department'))
    return render(request, 'firewall/hosts.html', {
        'page_obj': _paginate(request, qs),
        'status_choices': FirewallHost._meta.get_field('firewall_status').choices,
        'depts': depts,
        'f_status': status,
        'f_dept': dept,
        'f_q': q,
        'query': _query_string(request),
    })


@sso_required
@require_POST
def hosts_sync(request):
    """从 Ansible inventory 同步主机（POST 触发 Celery）。"""
    try:
        from firewall.tasks.collection import sync_inventory_task
        sync_inventory_task.delay()
        messages.success(request, '主机同步任务已提交，稍后请刷新查看')
    except Exception as exc:
        messages.error(request, f'同步任务提交失败：{exc}')
    _audit(get_sso_username(request), 'sync_hosts',
           object_repr='inventory', detail='页面手动触发')
    return redirect('fw_hosts')


@sso_required
def host_detail(request, hid):
    host = get_object_or_404(FirewallHost, id=hid)
    rules = (host.rules.exclude(status='deleted')
             .order_by('status', '-created_at'))
    drop_events = host.events.filter(action='DROP').order_by('-timestamp')[:20]
    recycle_candidates = host.rules.filter(status='recycle_candidate')
    return render(request, 'firewall/host_detail.html', {
        'host': host,
        'rules': rules,
        'drop_events': drop_events,
        'recycle_candidates': recycle_candidates,
    })


@sso_required
@require_POST
def host_collect(request, hid):
    host = get_object_or_404(FirewallHost, id=hid)
    if _trigger_collect(host.id):
        messages.success(request, f'主机 {host.hostname} 重新采集任务已提交')
        _audit(get_sso_username(request), 'collect', host=host,
               object_repr=str(host), detail='页面手动触发')
    else:
        messages.error(request, '采集任务提交失败，请联系管理员')
    return redirect('fw_host_detail', hid=hid)


@sso_required
@require_POST
def host_firewall(request, hid, op):
    """开启/关闭主机防火墙。op=disable 仅管理员（红线 §8.1）。"""
    if op == 'disable':
        return fw_admin_required(_host_firewall_impl)(request, hid, op)
    return _host_firewall_impl(request, hid, op)


def _host_firewall_impl(request, hid, op):
    host = get_object_or_404(FirewallHost, id=hid)
    username = get_sso_username(request)
    op_text = {'enable': '开启', 'disable': '关闭'}.get(op)
    if op_text is None:
        messages.error(request, '不支持的操作')
        return redirect('fw_host_detail', hid=hid)

    try:
        from firewall.services.ansible_executor import run_playbook
        result = run_playbook('set_profile.yml', {
            'target_host': host.ip,
            'profile': 'All',
            'fw_enabled': 'true' if op == 'enable' else 'false',
            'ansible_ip': settings.ANSIBLE_CONFIG['HOST'],
        }, initiated_by=username)
    except Exception as exc:
        _audit(username, f'{op}_firewall', host=host, object_repr=str(host),
               result='failed', detail=str(exc))
        messages.error(request, f'防火墙{op_text}任务执行失败：{exc}')
        return redirect('fw_host_detail', hid=hid)

    _audit(username,
           'enable_firewall' if op == 'enable' else 'disable_firewall',
           host=host, object_repr=str(host),
           task_ref=result.get('task_ref', ''),
           result='success' if result.get('ok') else 'failed',
           detail=result.get('error', ''))

    # 下发后触发重新采集刷新状态（失败不阻断）
    _trigger_collect(host.id)

    if result.get('ok'):
        messages.success(
            request,
            f'主机 {host.hostname} 防火墙{op_text}命令已下发，正在重新采集状态')
    else:
        messages.warning(
            request,
            f'防火墙{op_text}命令已提交但执行未确认成功：{result.get("error", "")}')
    return redirect('fw_host_detail', hid=hid)


# ---------------------------------------------------------------- 规则

@sso_required
def rules(request):
    qs = FirewallRule.objects.select_related('host').order_by('-created_at')
    status = request.GET.get('status', '')
    source = request.GET.get('source', '')
    risk = request.GET.get('risk', '')
    q = request.GET.get('q', '').strip()
    if status:
        qs = qs.filter(status=status)
    if source:
        qs = qs.filter(source=source)
    if risk:
        qs = qs.filter(risk_level=risk)
    if q:
        qs = (qs.filter(rule_name__icontains=q)
              | qs.filter(display_name__icontains=q)
              | qs.filter(program__icontains=q)
              | qs.filter(host__hostname__icontains=q))
    return render(request, 'firewall/rules.html', {
        'page_obj': _paginate(request, qs),
        'status_choices': FirewallRule._meta.get_field('status').choices,
        'source_choices': FirewallRule._meta.get_field('source').choices,
        'risk_choices': FirewallRule._meta.get_field('risk_level').choices,
        'f_status': status,
        'f_source': source,
        'f_risk': risk,
        'f_q': q,
        'query': _query_string(request),
    })


@fw_admin_required
@require_POST
def rule_remove(request, rid):
    """删除规则（仅管理员；rule_engine 双重拒绝非本系统规则）。"""
    engine = _get_rule_engine()
    if engine is None:
        messages.error(request, '规则引擎服务尚未就绪，请稍后再试')
        return redirect(_safe_next(request))
    username = get_sso_username(request)
    try:
        ok = engine.remove_rule(rid, operator=username)
    except Exception as exc:
        messages.error(request, f'规则删除异常：{exc}')
        return redirect(_safe_next(request))
    if ok:
        messages.success(request, '规则已删除')
    else:
        messages.error(request, '规则删除失败（非本系统规则或主机不可达）')
    return redirect(_safe_next(request))


@fw_admin_required
@require_POST
def rule_rollback(request, rid):
    """回滚规则（仅管理员）。"""
    engine = _get_rule_engine()
    if engine is None:
        messages.error(request, '规则引擎服务尚未就绪，请稍后再试')
        return redirect(_safe_next(request))
    username = get_sso_username(request)
    try:
        ok = engine.rollback_rule(rid, operator=username)
    except Exception as exc:
        messages.error(request, f'规则回滚异常：{exc}')
        return redirect(_safe_next(request))
    if ok:
        messages.success(request, '规则已回滚')
    else:
        messages.error(request, '规则回滚失败（非本系统规则或主机不可达）')
    return redirect(_safe_next(request))


# ---------------------------------------------------------------- 策略申请

@sso_required
def requests(request):
    qs = (FirewallRuleRequest.objects.select_related('host')
          .order_by('-created_at'))
    status = request.GET.get('status', '')
    if status:
        qs = qs.filter(status=status)
    return render(request, 'firewall/requests.html', {
        'page_obj': _paginate(request, qs),
        'status_choices': FirewallRuleRequest._meta.get_field('status').choices,
        'f_status': status,
        'query': _query_string(request),
    })


@sso_required
def request_new(request):
    """新建策略申请：GET 表单 / POST 创建（status='pending'）。"""
    enabled_hosts = FirewallHost.objects.filter(enabled=True).order_by('hostname')
    if request.method == 'POST':
        host = get_object_or_404(FirewallHost,
                                 id=request.POST.get('host'), enabled=True)
        application = request.POST.get('application', '').strip()
        reason = request.POST.get('reason', '').strip()
        if not application or not reason:
            messages.error(request, '应用名称与申请原因必填')
            return render(request, 'firewall/request_new.html', {
                'hosts': enabled_hosts,
                'prefill_host': host.id,
                'old': request.POST,
            })
        is_temporary = request.POST.get('is_temporary') == 'on'
        try:
            expire_days = int(request.POST.get('expire_days') or 30)
        except (TypeError, ValueError):
            expire_days = 30
        username = get_sso_username(request)
        req = FirewallRuleRequest.objects.create(
            host=host,
            application=application,
            program=request.POST.get('program', '').strip(),
            direction=request.POST.get('direction', 'Outbound'),
            protocol=request.POST.get('protocol', 'TCP'),
            remote_address=request.POST.get('remote_address', '').strip() or 'Any',
            remote_port=request.POST.get('remote_port', '').strip(),
            reason=reason,
            is_temporary=is_temporary,
            expire_days=expire_days,
            applicant=username,
            status='pending',
        )
        _audit(username, 'create_rule', host=host,
               object_repr=f'策略申请#{req.id} {application}',
               new={'application': application,
                    'direction': req.direction,
                    'protocol': req.protocol,
                    'remote_address': req.remote_address,
                    'remote_port': req.remote_port},
               detail=reason)
        messages.success(request, f'策略申请 #{req.id} 已提交，等待管理员审批')
        return redirect('fw_requests')

    prefill = request.GET.get('host', '')
    return render(request, 'firewall/request_new.html', {
        'hosts': enabled_hosts,
        'prefill_host': prefill,
        'old': {},
    })


@fw_admin_required
@require_POST
def request_review(request, rid, op):
    """审批策略申请（仅管理员）。approve 创建规则并下发；reject 记录驳回原因。"""
    req = get_object_or_404(FirewallRuleRequest.objects.select_related('host'),
                            id=rid)
    username = get_sso_username(request)
    if req.status != 'pending':
        messages.warning(request, '该申请已处理')
        return redirect('fw_requests')

    if op == 'approve':
        req.status = 'approved'
        req.reviewer = username
        req.reviewed_at = timezone.now()
        req.save(update_fields=['status', 'reviewer', 'reviewed_at',
                                'updated_at'])

        expire_at = None
        if req.is_temporary:
            expire_at = timezone.now() + timedelta(days=req.expire_days)
        fp = _rule_fingerprint(req.direction, req.protocol, req.program,
                               req.remote_address, req.remote_port)
        rule = FirewallRule(
            host=req.host,
            display_name=req.application,
            direction=req.direction,
            action='Allow',
            protocol=req.protocol,
            program=req.program,
            remote_address=req.remote_address,
            remote_port=req.remote_port,
            source='request',
            status='pending_deploy',
            risk_level=req.risk_level,
            fingerprint=fp,
            expire_at=expire_at,
        )
        engine = _get_rule_engine()
        if engine is not None:
            rule.rule_name = engine.build_rule_name(rule)
        else:
            rule.rule_name = f'AUTO-ITOPS-REQ-{fp[:16]}'
        rule.save()

        if engine is None:
            messages.warning(
                request, f'申请 #{req.id} 已批准，规则 #{rule.id} 已创建；'
                         '规则引擎尚未就绪，待其上线后自动下发')
        else:
            try:
                ok = engine.deploy_rule(rule.id, operator=username)
            except Exception as exc:
                ok = False
                messages.warning(request, f'规则下发异常：{exc}')
            if ok:
                messages.success(
                    request, f'申请 #{req.id} 已批准，规则已下发到 {req.host.hostname}')
            else:
                messages.warning(
                    request, f'申请 #{req.id} 已批准，但规则下发失败，'
                             '可在规则列表稍后重试')
        _audit(username, 'approve', host=req.host,
               object_repr=f'策略申请#{req.id} {req.application}',
               new={'rule_id': rule.id, 'rule_name': rule.rule_name})
    elif op == 'reject':
        req.status = 'rejected'
        req.reviewer = username
        req.reviewed_at = timezone.now()
        req.reject_reason = request.POST.get('reject_reason', '').strip()
        req.save(update_fields=['status', 'reviewer', 'reviewed_at',
                                'reject_reason', 'updated_at'])
        messages.success(request, f'申请 #{req.id} 已驳回')
        _audit(username, 'reject', host=req.host,
               object_repr=f'策略申请#{req.id} {req.application}',
               detail=req.reject_reason)
    else:
        messages.error(request, '不支持的审批操作')
    return redirect('fw_requests')


# ---------------------------------------------------------------- 通信关系

@sso_required
def communications(request):
    """通信关系：主机→程序→协议→目标IP→端口 五级展示 + 筛选。"""
    qs = (CommunicationRelation.objects.select_related('host')
          .order_by('host__hostname', 'program', 'protocol',
                    'remote_ip', 'remote_port'))
    f_host = request.GET.get('host', '').strip()
    f_ip = request.GET.get('ip', '').strip()
    f_port = request.GET.get('port', '').strip()
    f_app = request.GET.get('app', '').strip()
    f_dept = request.GET.get('dept', '').strip()
    if f_host:
        qs = qs.filter(host__hostname__icontains=f_host) | qs.filter(
            host__ip__icontains=f_host)
    if f_ip:
        qs = qs.filter(remote_ip__icontains=f_ip)
    if f_port.isdigit():
        qs = qs.filter(remote_port=int(f_port))
    if f_app:
        qs = (qs.filter(program__icontains=f_app)
              | qs.filter(process_name__icontains=f_app))
    if f_dept:
        qs = qs.filter(host__department__icontains=f_dept)

    page_obj = _paginate(request, qs)

    # 当前页数据聚合为 主机→程序→协议→目标IP→端口 五级树
    tree = []
    host_map = {}
    for comm in page_obj:
        hnode = host_map.get(comm.host_id)
        if hnode is None:
            hnode = {'host': comm.host, 'programs': [], '_pmap': {}}
            host_map[comm.host_id] = hnode
            tree.append(hnode)
        pkey = comm.program or '(未知程序)'
        pnode = hnode['_pmap'].get(pkey)
        if pnode is None:
            pnode = {'program': comm.program, 'process_name': comm.process_name,
                     'protocols': [], '_tmap': {}}
            hnode['_pmap'][pkey] = pnode
            hnode['programs'].append(pnode)
        tkey = comm.protocol
        tnode = pnode['_tmap'].get(tkey)
        if tnode is None:
            tnode = {'protocol': comm.protocol, 'ips': [], '_imap': {}}
            pnode['_tmap'][tkey] = tnode
            pnode['protocols'].append(tnode)
        inode = tnode['_imap'].get(comm.remote_ip)
        if inode is None:
            inode = {'remote_ip': comm.remote_ip, 'ports': []}
            tnode['_imap'][comm.remote_ip] = inode
            tnode['ips'].append(inode)
        inode['ports'].append(comm)
    for hnode in tree:
        hnode.pop('_pmap')
        for pnode in hnode['programs']:
            pnode.pop('_tmap')
            for tnode in pnode['protocols']:
                tnode.pop('_imap')

    return render(request, 'firewall/communications.html', {
        'page_obj': page_obj,
        'comm_tree': tree,
        'f_host': f_host,
        'f_ip': f_ip,
        'f_port': f_port,
        'f_app': f_app,
        'f_dept': f_dept,
        'query': _query_string(request),
    })


# ---------------------------------------------------------------- 审计 / 任务

@sso_required
def audit(request):
    qs = FirewallAuditLog.objects.select_related('host').order_by('-created_at')
    action = request.GET.get('action', '').strip()
    q = request.GET.get('q', '').strip()
    if action:
        qs = qs.filter(action=action)
    if q:
        qs = (qs.filter(username__icontains=q)
              | qs.filter(object_repr__icontains=q))
    actions = (FirewallAuditLog.objects.values_list('action', flat=True)
               .distinct().order_by('action'))
    return render(request, 'firewall/audit.html', {
        'page_obj': _paginate(request, qs),
        'actions': actions,
        'f_action': action,
        'f_q': q,
        'query': _query_string(request),
    })


@sso_required
def tasks(request):
    qs = AnsibleTaskRecord.objects.order_by('-created_at')
    status = request.GET.get('status', '')
    if status:
        qs = qs.filter(status=status)
    return render(request, 'firewall/tasks.html', {
        'page_obj': _paginate(request, qs),
        'status_choices': AnsibleTaskRecord._meta.get_field('status').choices,
        'f_status': status,
        'query': _query_string(request),
    })
