"""防火墙规则生命周期回收：临时规则到期、长期未命中识别、命中数刷新。

所有批量函数单条失败 try/except 继续，最后返回处理数。
"""
import logging
from collections import defaultdict
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from firewall.models import FirewallEvent, FirewallRule
from firewall.services import audit
from firewall.services.analysis import rule_fingerprint

logger = logging.getLogger(__name__)


def expire_temporary_rules() -> int:
    """expire_at<now 且 status='active' → status='recycle_candidate'；返回处理数。"""
    now = timezone.now()
    candidates = FirewallRule.objects.filter(
        status='active', expire_at__isnull=False, expire_at__lt=now,
    )
    count = 0
    for rule in candidates:
        try:
            rule.status = 'recycle_candidate'
            rule.save(update_fields=['status', 'updated_at'])
            audit.log_action(
                'system', 'recycle', host=rule.host,
                object_repr=rule.rule_name,
                detail=f'临时规则到期(expire_at={rule.expire_at})，转为待回收',
            )
            count += 1
        except Exception:
            logger.exception('临时规则到期处理失败 rule_id=%s', rule.id)
            continue
    logger.info('expire_temporary_rules: %d 条规则转为待回收', count)
    return count


def detect_unused_rules(days=30) -> int:
    """active 且 source='auto' 且 (last_hit_time 空或 < now-days) → 'recycle_candidate'。"""
    cutoff = timezone.now() - timedelta(days=days)
    candidates = FirewallRule.objects.filter(
        status='active', source='auto',
    ).filter(Q(last_hit_time__isnull=True) | Q(last_hit_time__lt=cutoff))
    count = 0
    for rule in candidates:
        try:
            rule.status = 'recycle_candidate'
            rule.save(update_fields=['status', 'updated_at'])
            audit.log_action(
                'system', 'recycle', host=rule.host,
                object_repr=rule.rule_name,
                detail=f'超过 {days} 天未命中，转为待回收',
            )
            count += 1
        except Exception:
            logger.exception('未命中规则识别失败 rule_id=%s', rule.id)
            continue
    logger.info('detect_unused_rules: %d 条规则转为待回收', count)
    return count


def _event_direction(direction) -> str:
    return 'Inbound' if str(direction or '').lower().startswith('in') else 'Outbound'


def _rule_match_fingerprints(rule: FirewallRule):
    """规则用于事件匹配的指纹集合。local_port 空视为通配（不计入指纹）。"""
    local_port = str(rule.local_port or '').strip()
    return {
        rule_fingerprint(rule.direction, rule.protocol, rule.program,
                         rule.remote_address, rule.remote_port, local_port),
    }


def _event_candidate_fingerprints(event) -> list:
    """由事件 (program或process_path, dst_ip, dst_port, protocol) 生成候选指纹。

    outbound：remote=dst_ip/dst_port；inbound：remote=src_ip/src_port、local=dst_port。
    """
    program = event.process_path or event.process_name or ''
    protocol = str(event.protocol or 'TCP').upper()
    direction = _event_direction(event.direction)
    dst_port = str(event.dst_port) if event.dst_port is not None else ''
    src_port = str(event.src_port) if event.src_port is not None else ''
    cands = []
    if direction == 'Inbound':
        remote_ip = event.src_ip or ''
        cands.append(rule_fingerprint(direction, protocol, program,
                                      remote_ip, src_port, dst_port))
        cands.append(rule_fingerprint(direction, protocol, program,
                                      remote_ip, src_port, ''))
        cands.append(rule_fingerprint(direction, protocol, program,
                                      remote_ip, '', dst_port))
        cands.append(rule_fingerprint(direction, protocol, program,
                                      remote_ip, '', ''))
    else:
        remote_ip = event.dst_ip or ''
        cands.append(rule_fingerprint(direction, protocol, program,
                                      remote_ip, dst_port, ''))
        cands.append(rule_fingerprint(direction, protocol, program,
                                      remote_ip, '', ''))
    return cands


def update_rule_hits(window_hours=24) -> int:
    """近 window_hours 的 ALLOW 事件按 host 分组，与该主机 active 规则指纹匹配，
    命中则 hit_count+=1、last_hit_time=max(timestamp)，bulk update。返回命中规则数。"""
    since = timezone.now() - timedelta(hours=window_hours)
    events = (
        FirewallEvent.objects.filter(action='ALLOW', timestamp__gte=since)
        .order_by('host_id', 'timestamp')
    )

    # 按 host 分组事件
    events_by_host = defaultdict(list)
    for event in events:
        events_by_host[event.host_id].append(event)

    # 命中聚合：rule_id -> [累计命中数, 最大命中时间]
    hits = {}
    for host_id, host_events in events_by_host.items():
        try:
            rules = list(FirewallRule.objects.filter(
                host_id=host_id, status='active'))
        except Exception:
            logger.exception('加载主机规则失败 host_id=%s', host_id)
            continue
        if not rules:
            continue
        fp_map = {}
        for rule in rules:
            for fp in _rule_match_fingerprints(rule):
                fp_map.setdefault(fp, rule)

        for event in host_events:
            try:
                matched = None
                for fp in _event_candidate_fingerprints(event):
                    matched = fp_map.get(fp)
                    if matched is not None:
                        break
                if matched is None:
                    continue
                agg = hits.setdefault(matched.id, [0, None, matched])
                agg[0] += 1
                if agg[1] is None or event.timestamp > agg[1]:
                    agg[1] = event.timestamp
            except Exception:
                logger.exception('事件匹配规则失败 event_id=%s', event.id)
                continue

    updated = []
    for rule_id, (n, max_ts, rule) in hits.items():
        try:
            rule.hit_count = (rule.hit_count or 0) + n
            if max_ts is not None and (
                    rule.last_hit_time is None or max_ts > rule.last_hit_time):
                rule.last_hit_time = max_ts
            updated.append(rule)
        except Exception:
            logger.exception('规则命中聚合失败 rule_id=%s', rule_id)
            continue

    if updated:
        try:
            FirewallRule.objects.bulk_update(
                updated, ['hit_count', 'last_hit_time', 'updated_at'])
        except Exception:
            logger.exception('规则命中 bulk_update 失败，逐条保存')
            saved = 0
            for rule in updated:
                try:
                    rule.save(update_fields=[
                        'hit_count', 'last_hit_time', 'updated_at'])
                    saved += 1
                except Exception:
                    logger.exception('规则命中保存失败 rule_id=%s', rule.id)
            logger.info('update_rule_hits: 逐条保存 %d 条规则命中', saved)
            return saved
    logger.info('update_rule_hits: %d 条规则命中更新', len(updated))
    return len(updated)
