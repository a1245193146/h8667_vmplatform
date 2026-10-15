"""系统管理模块视图：执行留痕 + 配置管理 + 配置审计。

权限口径与平台其它模块一致（resize.sso_utils）：
- 查看类页面：@sso_required（登录即可看，运维排障需要）
- 改配置：@admin_required（仅管理员），且只能改白名单里的键
"""
import logging
from datetime import timedelta

from django.contrib import messages
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.views.decorators.http import require_POST

from resize.sso_utils import admin_required, get_sso_username, sso_required

from sysmanage.models import ConfigAuditLog, ExecLog
from sysmanage.services import config as cfg
from sysmanage.services import execlog

logger = logging.getLogger(__name__)

PAGE_SIZE = 50


def _date_range(request):
    """从查询串取 [start, end] 日期闭区间；非法或缺省返回 (None, None)。"""
    start = parse_date(request.GET.get('start') or '') or None
    end = parse_date(request.GET.get('end') or '') or None
    return start, end


@sso_required
def index(request):
    """系统管理首页：三个子功能的入口 + 一眼可见的当前状态。"""
    now = timezone.now()
    day_ago = now - timedelta(days=1)
    ctx = {
        'exec_total': ExecLog.objects.count(),
        'exec_day': ExecLog.objects.filter(created_at__gte=day_ago).count(),
        'exec_failed_day': ExecLog.objects.filter(
            created_at__gte=day_ago).exclude(status='success').count(),
        'config_overridden': cfg_override_count(),
        'audit_day': ConfigAuditLog.objects.filter(created_at__gte=day_ago).count(),
    }
    return render(request, 'sysmanage/index.html', ctx)


def cfg_override_count():
    try:
        from sysmanage.models import SysConfig
        return SysConfig.objects.exclude(value=None).count()
    except Exception:
        return 0


# ------------------------------------------------------------------ 执行留痕


@sso_required
def execlogs(request):
    """执行留痕列表：按模块/类型/结果/目标/关键字/日期筛选，分页展示。

    这一页就是"平台到底往服务器上发过什么命令"的唯一权威答案——
    过去 ssh_exec 直连控制机的动作完全不落库，出了事无从追溯。
    """
    qs = ExecLog.objects.all()
    f_module = request.GET.get('module') or ''
    f_kind = request.GET.get('kind') or ''
    f_status = request.GET.get('status') or ''
    f_target = (request.GET.get('target') or '').strip()
    f_q = (request.GET.get('q') or '').strip()
    start, end = _date_range(request)

    if f_module:
        qs = qs.filter(module=f_module)
    if f_kind:
        qs = qs.filter(kind=f_kind)
    if f_status:
        qs = qs.filter(status=f_status) if f_status != 'not_success' \
            else qs.exclude(status='success')
    if f_target:
        qs = qs.filter(target__icontains=f_target)
    if f_q:
        qs = qs.filter(command__icontains=f_q)
    if start:
        qs = qs.filter(created_at__date__gte=start)
    if end:
        qs = qs.filter(created_at__date__lte=end)

    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get('page'))
    modules = sorted(set(ExecLog.objects.values_list('module', flat=True).distinct()))
    return render(request, 'sysmanage/execlog_list.html', {
        'page': page,
        'modules': modules,
        'kinds': ExecLog.KINDS,
        'statuses': ExecLog.STATUSES,
        'f_module': f_module, 'f_kind': f_kind, 'f_status': f_status,
        'f_target': f_target, 'f_q': f_q,
        'start': start.isoformat() if start else '',
        'end': end.isoformat() if end else '',
    })


@sso_required
def execlog_detail(request, pk):
    """单条留痕详情：完整命令 + 头尾留存输出 + 关联的 Ansible 任务。

    输出被截断时页面必须显式说明"完整输出未留存"，不能让人误以为
    看到的就是全部——这条口径与采集侧的截断声明一致。
    """
    row = get_object_or_404(ExecLog, pk=pk)
    task = None
    if row.task_ref:
        try:
            from firewall.models import AnsibleTaskRecord
            task = AnsibleTaskRecord.objects.filter(task_ref=row.task_ref).first()
        except Exception:
            task = None
    return render(request, 'sysmanage/execlog_detail.html', {'row': row, 'task': task})


@require_POST
@admin_required
def execlog_purge(request):
    """手动触发一次留痕清理。保留天数取当前生效配置。"""
    keep = cfg.effective('SYS_EXECLOG_KEEP_DAYS') or 90
    keep_probe = cfg.effective('SYS_EXECLOG_PROBE_KEEP_DAYS') or 7
    try:
        deleted = execlog.purge(keep_days_shell=keep, keep_days_probe=keep_probe)
        total = sum(deleted.values())
        messages.success(
            request,
            '已清理 %d 条留痕（探活 %d 条保留 %d 天，其余 %d 条保留 %d 天）。'
            '本次清理已写入留痕。' % (total, deleted.get('probe', 0), keep_probe,
                                    deleted.get('other', 0), keep))
    except Exception as exc:
        logger.exception('手动清理执行留痕失败')
        messages.error(request, '清理失败：%s: %s' % (type(exc).__name__, exc))
    return redirect('sys_execlogs')


# ------------------------------------------------------------------ 配置管理


@sso_required
def config_list(request):
    """配置页：按分组列出白名单内的可编辑项，标出"已覆盖/仍为默认"。

    凭据类只显示掩码，输入框永远留空——页面上任何位置都不出现明文。
    """
    from sysmanage.models import SysConfig
    try:
        groups = cfg.items_for_page()
        db_ok = True
        db_error = ''
    except Exception as exc:
        # 表还没 migrate 时也要能打开页面并说清原因，而不是抛 500
        groups = []
        db_ok = False
        db_error = '%s: %s' % (type(exc).__name__, exc)
    return render(request, 'sysmanage/config_list.html', {
        'groups': groups,
        'db_ok': db_ok,
        'db_error': db_error,
        'overridden': SysConfig.objects.exclude(value=None).count() if db_ok else 0,
        'total_editable': len(cfg.EDITABLE),
    })


@require_POST
@admin_required
def config_save(request):
    """保存单个配置项。key 必须在白名单内，值按声明的类型校验。"""
    key = (request.POST.get('key') or '').strip()
    raw = request.POST.get('value')
    user = get_sso_username(request) or 'unknown'
    ok, msg = cfg.set_value(key, raw, user)
    (messages.success if ok else messages.error)(request, msg)
    if not ok:
        logger.warning('配置保存被拒绝 %s by %s: %s', key, user, msg)
    return redirect('sys_config')


@require_POST
@admin_required
def config_reset(request):
    """删除某项的数据库覆盖，恢复 settings 默认值。"""
    key = (request.POST.get('key') or '').strip()
    user = get_sso_username(request) or 'unknown'
    ok, msg = cfg.reset_value(key, user)
    (messages.success if ok else messages.error)(request, msg)
    return redirect('sys_config')


@sso_required
def config_audit(request):
    """配置变更审计：长期保留，只记值的摘要（凭据只记长度，绝不落明文）。"""
    qs = ConfigAuditLog.objects.all()
    f_key = (request.GET.get('key') or '').strip()
    f_user = (request.GET.get('username') or '').strip()
    start, end = _date_range(request)
    if f_key:
        qs = qs.filter(key__icontains=f_key)
    if f_user:
        qs = qs.filter(username__icontains=f_user)
    if start:
        qs = qs.filter(created_at__date__gte=start)
    if end:
        qs = qs.filter(created_at__date__lte=end)
    page = Paginator(qs, PAGE_SIZE).get_page(request.GET.get('page'))
    return render(request, 'sysmanage/config_audit.html', {
        'page': page, 'f_key': f_key, 'f_user': f_user,
        'start': start.isoformat() if start else '',
        'end': end.isoformat() if end else '',
    })
