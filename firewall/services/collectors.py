"""采集编排：状态/规则/连接/事件四项采集 + inventory 同步。

容错红线：任何 Ansible/主机失败只影响该主机该步，写入 last_ansible_status，
绝不中断批量任务；单步失败继续其他步骤。
"""
import hashlib
import logging

from django.conf import settings
from django.utils import timezone

from firewall.models import (
    CommunicationRelation,
    FirewallHost,
    FirewallRule,
)
from firewall.services import event_ingest
from firewall.services.ansible_executor import parse_host_json, run_playbook

logger = logging.getLogger(__name__)

AUTO_PREFIX = 'AUTO-ITOPS-'

# 离线主机连续失败达到该次数后，跳过非状态采集（仅探测状态等待恢复）
_OFFLINE_SKIP_THRESHOLD = 3


def _rule_fingerprint(direction, protocol, program, remote_address,
                      remote_port, local_port='') -> str:
    """与 SPEC §4 rule_fingerprint 相同算法：六字段拼接 sha256[:32]。"""
    raw = '|'.join(str(v or '') for v in (
        direction, protocol, program, remote_address, remote_port, local_port,
    ))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]


def _get_host(host_id) -> FirewallHost:
    return FirewallHost.objects.get(id=host_id)


def _mark_unreachable(host: FirewallHost):
    host.is_online = False
    host.last_ansible_status = 'unreachable'
    host.save(update_fields=['is_online', 'last_ansible_status', 'updated_at'])


def _mark_failed(host: FirewallHost, status: str = 'failed'):
    host.last_ansible_status = status
    host.save(update_fields=['last_ansible_status', 'updated_at'])


def collect_host_status(host_id) -> bool:
    """Collect-FwStatus → 更新 firewall_status/profiles_detail/is_online/last_*。"""
    host = _get_host(host_id)
    res = run_playbook('collect_status.yml', {'target_host': host.ip},
                       name='collect_status')
    if not res['ok']:
        _mark_failed(host)
        return False
    data = parse_host_json(res['stdout'], host.ip)
    if data is None:
        _mark_unreachable(host)
        return False

    profiles = data.get('profiles') or {}
    states = [bool((profiles.get(p) or {}).get('enabled'))
              for p in ('Domain', 'Private', 'Public')]
    if all(states):
        fw_status = 'on'
    elif not any(states):
        fw_status = 'off'
    else:
        fw_status = 'partial'

    # profiles_detail 保留 log_offset 等采集游标
    detail = dict(profiles)
    old_detail = host.profiles_detail or {}
    for key in ('log_offset', 'consecutive_failures'):
        if key in old_detail:
            detail[key] = old_detail[key]
    detail['service_running'] = bool(data.get('service_running'))

    host.firewall_status = fw_status
    host.profiles_detail = detail
    host.is_online = True
    host.last_collection_time = timezone.now()
    host.last_ansible_status = 'success'
    if data.get('os'):
        host.os_version = str(data['os'])[:128]
    host.save(update_fields=['firewall_status', 'profiles_detail', 'is_online',
                             'last_collection_time', 'last_ansible_status',
                             'os_version', 'updated_at'])
    logger.info('主机 %s 状态采集成功: %s', host.ip, fw_status)
    return True


def collect_host_rules(host_id) -> int:
    """Collect-FwRules → upsert FirewallRule；返回条数。

    source：rule_name 以 AUTO-ITOPS- 开头 → 'auto'，否则 'imported'；
    人工(manual)/申请(request)来源的既有规则只更新采集字段，不动 source
    及 risk_level/status/hit_count/expire_at 等其他信息。
    """
    host = _get_host(host_id)
    res = run_playbook('collect_rules.yml', {'target_host': host.ip},
                       name='collect_rules')
    if not res['ok']:
        _mark_failed(host)
        return 0
    data = parse_host_json(res['stdout'], host.ip)
    if data is None:
        _mark_unreachable(host)
        return 0

    rules = data.get('rules') or []
    count = 0
    for item in rules:
        if not isinstance(item, dict):
            continue
        rule_name = str(item.get('name') or '').strip()
        if not rule_name:
            continue
        source = 'auto' if rule_name.startswith(AUTO_PREFIX) else 'imported'
        collected = {
            'display_name': str(item.get('display_name') or '')[:255],
            'direction': str(item.get('direction') or 'Outbound')[:10],
            'action': str(item.get('action') or 'Allow')[:10],
            'protocol': str(item.get('protocol') or 'TCP')[:10],
            'program': str(item.get('program') or '')[:500],
            'service_name': str(item.get('service') or '')[:255],
            'local_address': str(item.get('local_address') or 'Any')[:255],
            'local_port': str(item.get('local_port') or '')[:100],
            'remote_address': str(item.get('remote_address') or 'Any')[:255],
            'remote_port': str(item.get('remote_port') or '')[:100],
            'profile': str(item.get('profile') or 'Any')[:50],
            'enabled': bool(item.get('enabled', True)),
        }
        collected['fingerprint'] = _rule_fingerprint(
            collected['direction'], collected['protocol'], collected['program'],
            collected['remote_address'], collected['remote_port'],
            collected['local_port'],
        )
        defaults = dict(collected)
        defaults['source'] = source
        obj, created = FirewallRule.objects.get_or_create(
            host=host, rule_name=rule_name[:255], defaults=defaults,
        )
        if not created:
            for field, value in collected.items():
                setattr(obj, field, value)
            update_fields = list(collected.keys()) + ['updated_at']
            if obj.source not in ('manual', 'request'):
                obj.source = source
                update_fields.append('source')
            obj.save(update_fields=update_fields)
        count += 1
    logger.info('主机 %s 规则采集 %d 条', host.ip, count)
    return count


def collect_host_connections(host_id) -> int:
    """Collect-FwConnections → 更新 CommunicationRelation(first/last_seen/hit_count)。"""
    host = _get_host(host_id)
    res = run_playbook('collect_connections.yml', {'target_host': host.ip},
                       name='collect_connections')
    if not res['ok']:
        _mark_failed(host)
        return 0
    data = parse_host_json(res['stdout'], host.ip)
    if data is None:
        _mark_unreachable(host)
        return 0

    now = timezone.now()
    count = 0
    for item in data.get('connections') or []:
        if not isinstance(item, dict):
            continue
        remote_ip = str(item.get('remote_address') or '').strip()
        if not remote_ip or remote_ip in ('0.0.0.0', '::', '127.0.0.1', '::1'):
            continue
        try:
            remote_port = int(item.get('remote_port'))
        except (TypeError, ValueError):
            remote_port = None
        state = str(item.get('state') or '')
        direction = 'inbound' if state.lower() == 'listen' else 'outbound'
        program = str(item.get('process_path') or '')[:500]
        process_name = str(item.get('process_name') or '')[:255]
        protocol = str(item.get('protocol') or 'TCP').upper()[:10]

        obj, created = CommunicationRelation.objects.get_or_create(
            host=host,
            program=program,
            protocol=protocol,
            remote_ip=remote_ip[:64],
            remote_port=remote_port,
            direction=direction,
            defaults={
                'process_name': process_name,
                'first_seen': now,
                'last_seen': now,
                'hit_count': 1,
            },
        )
        if not created:
            obj.last_seen = now
            obj.hit_count = (obj.hit_count or 0) + 1
            update_fields = ['last_seen', 'hit_count']
            if process_name and not obj.process_name:
                obj.process_name = process_name
                update_fields.append('process_name')
            obj.save(update_fields=update_fields)
        count += 1
    logger.info('主机 %s 连接采集 %d 条', host.ip, count)
    return count


def collect_host_events(host_id) -> int:
    """Read-FwLog(offset 存 host.profiles_detail['log_offset']) + Read-FwSecurityEvents
    → event_ingest 统一去重；返回新增条数。单步失败继续另一步。"""
    host = _get_host(host_id)
    events = []

    offset = 0
    try:
        offset = int((host.profiles_detail or {}).get('log_offset', 0) or 0)
    except (TypeError, ValueError):
        offset = 0

    res = run_playbook('collect_fwlog.yml',
                       {'target_host': host.ip, 'offset': offset,
                        'max_lines': 2000},
                       name='collect_fwlog')
    if res['ok']:
        data = parse_host_json(res['stdout'], host.ip)
        if data is not None:
            events.extend(data.get('events') or [])
            new_offset = data.get('offset')
            if new_offset is not None:
                detail = dict(host.profiles_detail or {})
                detail['log_offset'] = new_offset
                host.profiles_detail = detail
                host.save(update_fields=['profiles_detail', 'updated_at'])
        else:
            _mark_unreachable(host)
    else:
        _mark_failed(host)
        logger.warning('主机 %s 防火墙日志采集失败: %s', host.ip, res['error'])

    res = run_playbook('collect_events.yml',
                       {'target_host': host.ip, 'since_minutes': 10},
                       name='collect_events')
    if res['ok']:
        data = parse_host_json(res['stdout'], host.ip)
        if data is not None:
            events.extend(data.get('events') or [])
        else:
            _mark_unreachable(host)
    else:
        _mark_failed(host)
        logger.warning('主机 %s 安全事件采集失败: %s', host.ip, res['error'])

    added = event_ingest.ingest_events(host, events)
    logger.info('主机 %s 事件采集新增 %d 条', host.ip, added)
    return added


def collect_host_all(host_id) -> dict:
    """顺序执行状态/规则/连接/事件四项采集，容错单步失败不影响其他。

    离线主机（is_online=False 且最近3次采集失败）跳过非状态采集。
    """
    host = _get_host(host_id)
    detail = host.profiles_detail or {}
    try:
        failures = int(detail.get('consecutive_failures', 0) or 0)
    except (TypeError, ValueError):
        failures = 0
    skip_extra = (not host.is_online) and failures >= _OFFLINE_SKIP_THRESHOLD

    result = {'status': False, 'rules': 0, 'connections': 0, 'events': 0,
              'skipped': skip_extra}

    try:
        result['status'] = collect_host_status(host_id)
    except Exception:
        logger.exception('主机 %s 状态采集异常', host.ip)
        result['status'] = False

    # 维护连续失败计数（用于离线跳过判定）
    try:
        host.refresh_from_db()
        detail = dict(host.profiles_detail or {})
        if result['status']:
            detail['consecutive_failures'] = 0
        else:
            detail['consecutive_failures'] = failures + 1
        host.profiles_detail = detail
        host.save(update_fields=['profiles_detail', 'updated_at'])
    except Exception:
        logger.exception('主机 %s 失败计数更新异常', host.ip)

    if skip_extra:
        logger.info('主机 %s 离线且连续失败 %d 次，跳过非状态采集',
                    host.ip, failures)
        return result

    for key, func in (('rules', collect_host_rules),
                      ('connections', collect_host_connections),
                      ('events', collect_host_events)):
        try:
            result[key] = func(host_id)
        except Exception:
            logger.exception('主机 %s %s 采集异常', host.ip, key)
            try:
                _mark_failed(_get_host(host_id))
            except Exception:
                logger.exception('主机 %s 状态标记失败', host.ip)

    return result


def sync_hosts_from_inventory() -> int:
    """sync_inventory_hosts.yml → upsert FirewallHost；返回同步条数。

    inventory 文件默认用 Ansible 服务器上的 /etc/ansible/hosts，
    可通过 settings.FW_INVENTORY_PATH 指定其他文件（如 inventory.d/windows_dynamic.ini）。
    """
    extra_vars = {}
    inv_path = getattr(settings, 'FW_INVENTORY_PATH', '')
    if inv_path:
        extra_vars['inventory_path'] = inv_path
    res = run_playbook('sync_inventory_hosts.yml', extra_vars, name='sync_inventory')
    if not res['ok']:
        logger.error('inventory 同步 playbook 执行失败: %s', res['error'])
        return 0
    # 该 playbook 在 Ansible 服务器本地执行，不连 Windows
    data = (parse_host_json(res['stdout'], 'localhost')
            or parse_host_json(res['stdout'], '127.0.0.1'))
    if data is None:
        logger.error('inventory 同步输出解析失败 task_ref=%s', res['task_ref'])
        return 0

    count = 0
    for item in data.get('hosts') or []:
        if not isinstance(item, dict):
            continue
        ip = str(item.get('ip') or '').strip()
        if not ip:
            continue
        FirewallHost.objects.update_or_create(
            ip=ip,
            defaults={
                'hostname': str(item.get('hostname') or ip)[:128],
                'ansible_group': str(item.get('group') or 'windows')[:128],
            },
        )
        count += 1
    logger.info('inventory 同步主机 %d 台', count)
    return count
