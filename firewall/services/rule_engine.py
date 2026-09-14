"""防火墙规则引擎：规则命名、下发、删除、回滚。

红线：
- 所有自动规则必须 AUTO-ITOPS- 前缀；remove_rule 拒绝删除非本系统规则。
- deploy_rule 失败只置该规则 deploy_failed，绝不影响主机其他规则。
- 任何 Ansible 异常不向上抛。
"""
import json
import logging

from firewall.models import FirewallRule
from firewall.services import audit
from firewall.services.analysis import rule_fingerprint  # noqa: F401  (对外再导出)
from firewall.services.ansible_executor import parse_host_json, run_playbook

logger = logging.getLogger(__name__)

AUTO_PREFIX = 'AUTO-ITOPS-'

_DIRECTION_CN = {'Outbound': '出站', 'Inbound': '入站'}


def _is_ipv4(text) -> bool:
    parts = str(text or '').split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def build_rule_name(rule: FirewallRule) -> str:
    """AUTO-ITOPS- + 方向首字母(O/I) + 协议 + 远程IP末段(非IP用any) + 端口(空则any)
    + 指纹前6，如 AUTO-ITOPS-O-TCP-188-8878-a1b2c3；<=255 字符。"""
    direction = 'I' if str(rule.direction or '').lower().startswith('in') else 'O'
    protocol = str(rule.protocol or 'TCP').upper()
    remote = str(rule.remote_address or '').strip()
    ip_seg = remote.split('.')[-1] if _is_ipv4(remote) else 'any'
    port = str(rule.remote_port or '').strip() or 'any'
    fp6 = (rule.fingerprint or
           rule_fingerprint(rule.direction, rule.protocol, rule.program,
                            rule.remote_address, rule.remote_port,
                            rule.local_port))[:6]
    name = f'{AUTO_PREFIX}{direction}-{protocol}-{ip_seg}-{port}-{fp6}'
    return name[:255]


def build_display_name(rule: FirewallRule) -> str:
    """自动生成中文描述。"""
    direction = _DIRECTION_CN.get(rule.direction, str(rule.direction or '出站'))
    program = str(rule.program or '').replace('/', '\\').rstrip('\\')
    app = program.split('\\')[-1] if program else '任意程序'
    remote = str(rule.remote_address or 'Any')
    port = str(rule.remote_port or '').strip()
    target = f'{remote}:{port}' if port else remote
    action = '允许' if str(rule.action or '').lower() == 'allow' else '阻止'
    return f'自动规则-{action}{app}{direction}访问{target}'[:255]


def rule_to_json(rule: FirewallRule) -> dict:
    """FirewallRule → New-FwRule.ps1 的 RuleJson。"""
    return {
        'name': rule.rule_name,
        'display_name': rule.display_name or build_display_name(rule),
        'direction': rule.direction or 'Outbound',
        'action': rule.action or 'Allow',
        'protocol': rule.protocol or 'TCP',
        'program': rule.program or '',
        'service': rule.service_name or '',
        'local_address': rule.local_address or 'Any',
        'local_port': rule.local_port or '',
        'remote_address': rule.remote_address or 'Any',
        'remote_port': rule.remote_port or '',
        'profile': rule.profile or 'Any',
        'enabled': bool(rule.enabled),
    }


def _rule_snapshot(rule: FirewallRule) -> dict:
    return {
        'id': rule.id,
        'rule_name': rule.rule_name,
        'display_name': rule.display_name,
        'direction': rule.direction,
        'action': rule.action,
        'protocol': rule.protocol,
        'program': rule.program,
        'local_port': rule.local_port,
        'remote_address': rule.remote_address,
        'remote_port': rule.remote_port,
        'source': rule.source,
        'risk_level': rule.risk_level,
        'status': rule.status,
        'fingerprint': rule.fingerprint,
    }


def deploy_rule(rule_id, operator='system') -> bool:
    """下发规则到主机。幂等：已 active 直接返回 True。

    rule_name 为空则生成并保存；rule_to_json → run_playbook('deploy_rule.yml')；
    解析返回 ok → status='active'，否则 'deploy_failed'；写审计。
    失败绝不影响主机其他规则，异常不抛出。
    """
    try:
        rule = FirewallRule.objects.select_related('host').get(id=rule_id)
    except FirewallRule.DoesNotExist:
        logger.warning('deploy_rule: 规则不存在 id=%s', rule_id)
        return False

    if rule.status == 'active':
        logger.info('规则 %s 已 active，跳过重复下发', rule.rule_name)
        return True

    try:
        if not rule.rule_name:
            rule.rule_name = build_rule_name(rule)
        if not rule.display_name:
            rule.display_name = build_display_name(rule)
        rule.save(update_fields=['rule_name', 'display_name', 'updated_at'])

        rule_json = json.dumps(rule_to_json(rule), ensure_ascii=False)
        res = run_playbook(
            'deploy_rule.yml',
            {'target_host': rule.host.ip, 'rule_json': rule_json},
            initiated_by=operator or 'system',
            name='deploy_rule',
        )
        data = parse_host_json(res.get('stdout', ''), rule.host.ip) \
            if res.get('ok') else None
        ok = bool(res.get('ok')) and data is not None

        if ok:
            rule.status = 'active'
            rule.save(update_fields=['status', 'updated_at'])
            audit.log_action(
                operator, 'create_rule', host=rule.host,
                object_repr=rule.rule_name, new=_rule_snapshot(rule),
                task_ref=res.get('task_ref', ''), result='success',
                detail=f'规则下发成功: {data}',
            )
            logger.info('规则 %s 下发成功 host=%s', rule.rule_name, rule.host.ip)
            return True

        rule.status = 'deploy_failed'
        rule.save(update_fields=['status', 'updated_at'])
        audit.log_action(
            operator, 'create_rule', host=rule.host,
            object_repr=rule.rule_name, new=_rule_snapshot(rule),
            task_ref=res.get('task_ref', ''), result='failed',
            detail=res.get('error', '') or 'playbook 返回解析失败',
        )
        logger.warning('规则 %s 下发失败 host=%s: %s',
                       rule.rule_name, rule.host.ip, res.get('error'))
        return False
    except Exception as exc:  # 任何异常不影响主机其他规则
        logger.exception('deploy_rule 异常 rule_id=%s: %s', rule_id, exc)
        try:
            rule.status = 'deploy_failed'
            rule.save(update_fields=['status', 'updated_at'])
            audit.log_action(
                operator, 'create_rule', host=rule.host,
                object_repr=rule.rule_name, result='failed',
                detail=f'下发异常: {exc}',
            )
        except Exception:
            logger.exception('deploy_rule 异常后的状态回写失败 rule_id=%s', rule_id)
        return False


def _do_remove(rule: FirewallRule, operator, action: str) -> bool:
    """删除/回滚公共逻辑。仅 source in ('auto','request') 且 AUTO-ITOPS- 前缀可删。"""
    if rule.source not in ('auto', 'request') \
            or not str(rule.rule_name or '').startswith(AUTO_PREFIX):
        audit.log_action(
            operator, action, host=rule.host,
            object_repr=rule.rule_name or f'rule#{rule.id}',
            old=_rule_snapshot(rule), result='failed',
            detail='拒绝删除非本系统规则',
        )
        logger.warning('拒绝删除非本系统规则 rule_id=%s name=%s source=%s',
                       rule.id, rule.rule_name, rule.source)
        return False

    old = _rule_snapshot(rule)
    try:
        res = run_playbook(
            'remove_rule.yml',
            {'target_host': rule.host.ip, 'rule_name': rule.rule_name},
            initiated_by=operator or 'system',
            name='remove_rule',
        )
        data = parse_host_json(res.get('stdout', ''), rule.host.ip) \
            if res.get('ok') else None
        ok = bool(res.get('ok')) and data is not None

        if ok:
            rule.status = 'deleted'
            rule.enabled = False
            rule.save(update_fields=['status', 'enabled', 'updated_at'])
            audit.log_action(
                operator, action, host=rule.host,
                object_repr=rule.rule_name, old=old,
                new=_rule_snapshot(rule),
                task_ref=res.get('task_ref', ''), result='success',
                detail=f'规则删除成功: {data}',
            )
            logger.info('规则 %s 已删除 host=%s', rule.rule_name, rule.host.ip)
            return True

        audit.log_action(
            operator, action, host=rule.host,
            object_repr=rule.rule_name, old=old,
            task_ref=res.get('task_ref', ''), result='failed',
            detail=res.get('error', '') or 'playbook 返回解析失败',
        )
        logger.warning('规则 %s 删除失败 host=%s: %s',
                       rule.rule_name, rule.host.ip, res.get('error'))
        return False
    except Exception as exc:
        logger.exception('删除规则异常 rule_id=%s: %s', rule.id, exc)
        audit.log_action(
            operator, action, host=rule.host,
            object_repr=rule.rule_name, old=old, result='failed',
            detail=f'删除异常: {exc}',
        )
        return False


def remove_rule(rule_id, operator) -> bool:
    """删除本系统规则（审计 action='delete_rule'）。"""
    try:
        rule = FirewallRule.objects.select_related('host').get(id=rule_id)
    except FirewallRule.DoesNotExist:
        logger.warning('remove_rule: 规则不存在 id=%s', rule_id)
        return False
    return _do_remove(rule, operator, 'delete_rule')


def rollback_rule(rule_id, operator) -> bool:
    """回滚 = 删除本系统规则（审计 action='rollback_rule'）。"""
    try:
        rule = FirewallRule.objects.select_related('host').get(id=rule_id)
    except FirewallRule.DoesNotExist:
        logger.warning('rollback_rule: 规则不存在 id=%s', rule_id)
        return False
    return _do_remove(rule, operator, 'rollback_rule')
