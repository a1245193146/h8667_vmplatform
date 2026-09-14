"""防火墙生命周期 Celery 任务。

每个任务只做一件事：调用对应服务函数并记日志。
beat schedule 见 h8667_vmplatform/settings.py CELERY_BEAT_SCHEDULE。
"""
import logging
from collections import defaultdict
from datetime import timedelta

from celery import shared_task
from django.db.models import Count
from django.utils import timezone

from firewall.models import (
    CommunicationRelation,
    DailyFirewallStat,
    FirewallEvent,
)
from firewall.services import analysis, recycle

logger = logging.getLogger(__name__)


@shared_task
def analyze_candidates_task():
    """每日 03:00：从通信关系学习生成候选规则/申请。"""
    rules = analysis.build_candidate_rules()
    logger.info('analyze_candidates_task 完成，新建自动规则 %d 条', len(rules))
    return len(rules)


@shared_task
def daily_rollup_task():
    """每日 00:30：聚合"昨天"的 FirewallEvent 到 DailyFirewallStat。"""
    yesterday = timezone.localdate() - timedelta(days=1)
    rows = (
        FirewallEvent.objects.filter(timestamp__date=yesterday)
        .values('host_id', 'action')
        .annotate(n=Count('id'))
    )
    counts = defaultdict(lambda: {'drop_count': 0, 'allow_count': 0})
    for row in rows:
        if row['action'] == 'DROP':
            counts[row['host_id']]['drop_count'] = row['n']
        elif row['action'] == 'ALLOW':
            counts[row['host_id']]['allow_count'] = row['n']

    done = 0
    for host_id, c in counts.items():
        try:
            DailyFirewallStat.objects.update_or_create(
                host_id=host_id, date=yesterday, defaults=c,
            )
            done += 1
        except Exception:
            logger.exception('daily_rollup 失败 host_id=%s', host_id)
            continue
    logger.info('daily_rollup_task 完成：%s 聚合 %d 台主机', yesterday, done)
    return done


@shared_task
def refresh_relations_task():
    """每 30 分钟：用近 7 天事件 upsert CommunicationRelation。

    direction 取事件 direction，缺省 'outbound'；program 取 process_path。
    """
    since = timezone.now() - timedelta(days=7)
    events = FirewallEvent.objects.filter(timestamp__gte=since).values(
        'host_id', 'process_path', 'process_name', 'protocol',
        'dst_ip', 'dst_port', 'direction', 'timestamp',
    )

    # 聚合：key -> {first, last, count, process_name}
    grouped = {}
    for e in events:
        key = (
            e['host_id'], e['process_path'] or '', e['protocol'] or 'TCP',
            e['dst_ip'] or '', e['dst_port'], e['direction'] or 'outbound',
        )
        g = grouped.get(key)
        if g is None:
            grouped[key] = {
                'first': e['timestamp'], 'last': e['timestamp'],
                'count': 1, 'process_name': e['process_name'] or '',
            }
        else:
            g['count'] += 1
            if e['timestamp'] < g['first']:
                g['first'] = e['timestamp']
            if e['timestamp'] > g['last']:
                g['last'] = e['timestamp']
            if not g['process_name'] and e['process_name']:
                g['process_name'] = e['process_name']

    done = 0
    for (host_id, program, protocol, dst_ip, dst_port, direction), g \
            in grouped.items():
        try:
            risk = analysis.classify_risk(
                remote_ip=dst_ip, remote_port=dst_port, program=program,
                process_name=g['process_name'], protocol=protocol,
            )
            obj, created = CommunicationRelation.objects.get_or_create(
                host_id=host_id,
                program=program[:500],
                protocol=protocol[:10],
                remote_ip=dst_ip[:64],
                remote_port=dst_port,
                direction=direction[:10] or 'outbound',
                defaults={
                    'process_name': g['process_name'][:255],
                    'risk_level': risk,
                    'first_seen': g['first'],
                    'last_seen': g['last'],
                    'hit_count': g['count'],
                },
            )
            if not created:
                obj.last_seen = max(obj.last_seen, g['last'])
                obj.first_seen = min(obj.first_seen, g['first'])
                obj.hit_count = g['count']
                obj.risk_level = risk
                update_fields = ['last_seen', 'first_seen', 'hit_count',
                                 'risk_level']
                if g['process_name'] and not obj.process_name:
                    obj.process_name = g['process_name'][:255]
                    update_fields.append('process_name')
                obj.save(update_fields=update_fields)
            done += 1
        except Exception:
            logger.exception('refresh_relations 失败 host_id=%s key=%s',
                             host_id, (program, protocol, dst_ip, dst_port))
            continue
    logger.info('refresh_relations_task 完成：upsert %d 条通信关系', done)
    return done


@shared_task
def expire_rules_task():
    """每小时：临时规则到期 → 待回收。"""
    count = recycle.expire_temporary_rules()
    logger.info('expire_rules_task 完成，处理 %d 条', count)
    return count


@shared_task
def detect_unused_task():
    """每日 01:00：长期未命中的自动规则 → 待回收。"""
    count = recycle.detect_unused_rules()
    logger.info('detect_unused_task 完成，处理 %d 条', count)
    return count


@shared_task
def update_hits_task():
    """每 15 分钟：用 ALLOW 事件刷新规则命中数。"""
    count = recycle.update_rule_hits()
    logger.info('update_hits_task 完成，更新 %d 条规则命中', count)
    return count
