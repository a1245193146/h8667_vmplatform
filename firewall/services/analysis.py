"""防火墙风险分析与候选规则生成。

- classify_risk：按 SPEC §4 规则分 high/medium/low。
- rule_fingerprint：与采集侧 collectors._rule_fingerprint 同算法（六字段拼接 sha256[:32]）。
- build_candidate_rules：从 CommunicationRelation 聚合学习，low 自动建规则并下发，
  medium/high 建审批申请；三层去重（fingerprint + 已有规则 + pending 申请）。
"""
import hashlib
import logging
from datetime import timedelta

from django.db import IntegrityError

from django.conf import settings
from django.utils import timezone

from firewall.models import (
    CommunicationRelation,
    FirewallRule,
    FirewallRuleRequest,
)

logger = logging.getLogger(__name__)

SENSITIVE_PORTS = {135, 139, 445, 3389, 5985, 5986}
DB_PORTS = {1433, 1521, 3306, 5432, 6379, 27017}
GENERIC_RUNTIMES = {
    'python.exe', 'pythonw.exe', 'powershell.exe', 'pwsh.exe', 'java.exe',
    'javaw.exe', 'wscript.exe', 'cscript.exe', 'rundll32.exe', 'svchost.exe',
    'cmd.exe', 'w3wp.exe',
}

_DEFAULT_INTERNAL_CIDRS = ['10.', '172.16.', '192.168.']
_UNKNOWN_PROGRAMS = {'', 'unknown', 'system', '-'}


def _internal_prefixes():
    """读取 settings.FW_INTERNAL_CIDRS，缺失/为空时兜底默认值。"""
    cidrs = getattr(settings, 'FW_INTERNAL_CIDRS', None)
    if not cidrs:
        return list(_DEFAULT_INTERNAL_CIDRS)
    return list(cidrs)


def is_internal_ip(ip) -> bool:
    """内网判定：settings.FW_INTERNAL_CIDRS 前缀匹配 + RFC1918/169.254/127 兜底。"""
    if not ip:
        return False
    ip = str(ip).strip()
    for prefix in _internal_prefixes():
        if prefix and ip.startswith(prefix):
            return True
    # RFC1918 + 链路本地 + 回环（兜底，防止 settings 配置遗漏）
    if ip.startswith(('10.', '192.168.', '127.', '169.254.')):
        return True
    if ip.startswith('172.'):
        parts = ip.split('.')
        try:
            if 16 <= int(parts[1]) <= 31:
                return True
        except (IndexError, ValueError):
            pass
    return False


def classify_risk(*, remote_ip, remote_port, program, process_name,
                  protocol) -> str:
    """按 SPEC §4 规则分类：
    high: 非内部IP 或 remote_port∈SENSITIVE_PORTS
    medium: 程序名为空/未知 或 process_name∈GENERIC_RUNTIMES 或 remote_port∈DB_PORTS
    low: 其余（内部IP+已识别程序+非敏感端口）
    """
    port = None
    try:
        port = int(remote_port) if remote_port not in (None, '') else None
    except (TypeError, ValueError):
        port = None

    if not is_internal_ip(remote_ip):
        return 'high'
    if port is not None and port in SENSITIVE_PORTS:
        return 'high'

    program_text = str(program or '').strip().lower()
    if program_text in _UNKNOWN_PROGRAMS:
        return 'medium'
    proc = str(process_name or '').strip().lower()
    if proc and proc in GENERIC_RUNTIMES:
        return 'medium'
    if port is not None and port in DB_PORTS:
        return 'medium'
    return 'low'


def rule_fingerprint(direction, protocol, program, remote_address,
                     remote_port, local_port='') -> str:
    """规则指纹：direction|protocol|program|remote_address|remote_port|local_port
    空值按空字符串参与拼接，sha256[:32]。与采集侧算法一致。"""
    raw = '|'.join(str(v or '') for v in (
        direction, protocol, program, remote_address, remote_port, local_port,
    ))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]


def _rule_direction(rel_direction) -> str:
    """CommunicationRelation 的小写方向 → FirewallRule 的 Inbound/Outbound。"""
    return 'Inbound' if str(rel_direction or '').lower().startswith('in') else 'Outbound'


def _program_tail(program) -> str:
    """取程序路径尾段作为应用名兜底。"""
    text = str(program or '').replace('/', '\\').rstrip('\\')
    if not text:
        return ''
    return text.split('\\')[-1]


def _request_fingerprint(req) -> str:
    """FirewallRuleRequest 无 fingerprint 字段，按同算法现算用于去重。"""
    return rule_fingerprint(
        req.direction, req.protocol, req.program,
        req.remote_address, req.remote_port, '',
    )


def build_candidate_rules(host_id=None, window_days=7, min_hits=3):
    """从 CommunicationRelation 聚合候选规则。

    hit_count>=min_hits 且 last_seen 在 window_days 内 → classify_risk：
    - low：创建 FirewallRule(source='auto', status='pending_deploy', risk_level='low',
      rule_name 留空由 deploy 时生成)，并调用 rule_engine.deploy_rule 自动下发；
    - medium/high：创建 FirewallRuleRequest(status='pending')，reason 自动生成。
    去重：同 host+fingerprint 已有 active/pending_deploy 规则或 pending 申请则跳过。
    单条失败 try/except 继续。返回创建的 FirewallRule 对象列表。
    """
    from firewall.services import rule_engine  # 延迟导入避免循环依赖

    now = timezone.now()
    since = now - timedelta(days=window_days)
    relations = CommunicationRelation.objects.filter(
        hit_count__gte=min_hits, last_seen__gte=since,
    ).select_related('host')
    if host_id is not None:
        relations = relations.filter(host_id=host_id)

    # 预取去重集合：host_id -> {fingerprint}
    host_ids = set(relations.values_list('host_id', flat=True))
    existing_rule_fps = {}
    for hid, fp in FirewallRule.objects.filter(
        host_id__in=host_ids, status__in=('active', 'pending_deploy'),
    ).values_list('host_id', 'fingerprint'):
        existing_rule_fps.setdefault(hid, set()).add(fp)
    pending_req_fps = {}
    for req in FirewallRuleRequest.objects.filter(
        host_id__in=host_ids, status='pending',
    ):
        pending_req_fps.setdefault(req.host_id, set()).add(
            _request_fingerprint(req))

    created_rules = []
    seen_in_run = set()
    for rel in relations:
        try:
            direction = _rule_direction(rel.direction)
            protocol = str(rel.protocol or 'TCP').upper()[:10]
            program = str(rel.program or '')[:500]
            remote_address = rel.remote_ip or 'Any'
            remote_port = (str(rel.remote_port)
                           if rel.remote_port is not None else '')
            fp = rule_fingerprint(direction, protocol, program,
                                  remote_address, remote_port, '')

            if (rel.host_id, fp) in seen_in_run:
                continue
            if fp in existing_rule_fps.get(rel.host_id, set()):
                continue
            if fp in pending_req_fps.get(rel.host_id, set()):
                continue
            seen_in_run.add((rel.host_id, fp))

            risk = classify_risk(
                remote_ip=rel.remote_ip, remote_port=rel.remote_port,
                program=rel.program, process_name=rel.process_name,
                protocol=protocol,
            )

            if risk == 'low':
                rule = FirewallRule(
                    host=rel.host,
                    rule_name='',  # 由 deploy_rule 时生成
                    direction=direction,
                    action='Allow',
                    protocol=protocol,
                    program=program,
                    remote_address=remote_address,
                    remote_port=remote_port,
                    source='auto',
                    risk_level='low',
                    status='pending_deploy',
                    fingerprint=fp,
                )
                try:
                    rule.save()
                except IntegrityError:
                    # unique(host, rule_name)：主机已有留空名字的规则
                    # （如下发失败残留），退化为立即生成名字避免冲突
                    rule.rule_name = rule_engine.build_rule_name(rule)
                    rule.save()
                created_rules.append(rule)
                existing_rule_fps.setdefault(rel.host_id, set()).add(fp)
                # 低风险自动下发；失败仅该规则 deploy_failed，不影响其他
                try:
                    rule_engine.deploy_rule(rule.id, operator='system')
                except Exception:
                    logger.exception('候选规则自动下发异常 rule_id=%s', rule.id)
            else:
                app = (str(rel.process_name or '').strip()
                       or _program_tail(rel.program) or '未知程序')
                target = rel.remote_ip or '任意地址'
                if rel.remote_port is not None:
                    target = f'{target}:{rel.remote_port}'
                reason = (
                    f'系统学习发现 {rel.hit_count} 次通信：'
                    f'程序 {app} 与 {target} 建立{direction}'
                    f'/{protocol} 连接，风险等级 {risk}，需人工审核放行。'
                )
                FirewallRuleRequest.objects.create(
                    host=rel.host,
                    application=app[:255],
                    program=program,
                    direction=direction,
                    protocol=protocol,
                    remote_address=remote_address,
                    remote_port=remote_port,
                    reason=reason,
                    risk_level=risk,
                    status='pending',
                    applicant='system',
                )
                pending_req_fps.setdefault(rel.host_id, set()).add(fp)
        except Exception:
            logger.exception('处理候选通信关系失败 relation_id=%s', rel.id)
            continue

    logger.info('build_candidate_rules 完成：新建自动规则 %d 条',
                len(created_rules))
    return created_rules
