"""API 序列化 / 聚合查询辅助（SPEC-firewall.md §6）。

视图保持薄：api_dashboard 只调用 build_dashboard_data() 并 JsonResponse。
所有数据纯查库，绝不实时调 Ansible（红线 §8.7）。
"""
import ipaddress
from datetime import timedelta

from django.conf import settings
from django.db.models import Count
from django.db.models.functions import TruncHour
from django.utils import timezone

from firewall.models import (
    AnsibleTaskRecord,
    CommunicationRelation,
    FirewallEvent,
    FirewallHost,
    FirewallRule,
)

# 与 services/analysis.py 口径一致（§4）
SENSITIVE_PORTS = {135, 139, 445, 3389, 5985, 5986}

TOP_N = 8
STALE_HOURS = 1
EXPIRING_DAYS = 7


def _is_internal_ip(ip: str) -> bool:
    """RFC1918 + 169.254 + 127/8 + settings.FW_INTERNAL_CIDRS 前缀。"""
    if not ip:
        return True
    for prefix in getattr(settings, 'FW_INTERNAL_CIDRS',
                          ['10.', '172.16.', '192.168.']):
        if ip.startswith(prefix):
            return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _host_summary(now):
    qs = FirewallHost.objects.all()
    stale_before = now - timedelta(hours=STALE_HOURS)
    return {
        'total': qs.count(),
        'on': qs.filter(firewall_status='on').count(),
        'off': qs.filter(firewall_status='off').count(),
        'partial': qs.filter(firewall_status='partial').count(),
        'offline': qs.filter(is_online=False).count(),
        # 最近采集时间超过 1 小时或从未采集的主机数
        'stale': qs.filter(last_collection_time__lt=stale_before).count()
                 + qs.filter(last_collection_time__isnull=True).count(),
    }


def _today_events(now):
    today = timezone.localdate(now)
    qs = FirewallEvent.objects.filter(timestamp__date=today)
    return {
        'drop': qs.filter(action='DROP').count(),
        'allow': qs.filter(action='ALLOW').count(),
    }


def _trend_24h(now):
    """近 24 小时按小时聚合 DROP/ALLOW，24 个桶（旧→新）。"""
    local_now = timezone.localtime(now)
    start = (local_now - timedelta(hours=23)).replace(
        minute=0, second=0, microsecond=0)
    buckets = {}
    for i in range(24):
        h = start + timedelta(hours=i)
        buckets[h.strftime('%m-%d %H:00')] = {'hour': h.strftime('%m-%d %H:00'),
                                              'drop': 0, 'allow': 0}
    rows = (
        FirewallEvent.objects
        .filter(timestamp__gte=start)
        .annotate(hour=TruncHour('timestamp',
                                 tzinfo=timezone.get_current_timezone()))
        .values('hour', 'action')
        .annotate(n=Count('id'))
    )
    for row in rows:
        label = timezone.localtime(row['hour']).strftime('%m-%d %H:00')
        if label in buckets:
            if row['action'] == 'DROP':
                buckets[label]['drop'] = row['n']
            elif row['action'] == 'ALLOW':
                buckets[label]['allow'] = row['n']
    return list(buckets.values())


def _top_lists(now):
    """近 24h 事件的 TOP 榜，各取前 8。"""
    since = now - timedelta(hours=24)
    qs = FirewallEvent.objects.filter(timestamp__gte=since)

    def top(values_field, is_text=True):
        q = qs
        if is_text:
            q = q.exclude(**{values_field: ''})
        q = q.exclude(**{values_field + '__isnull': True})
        return [
            [row[values_field], row['n']]
            for row in q.values(values_field).annotate(n=Count('id'))
            .order_by('-n')[:TOP_N]
        ]

    return {
        'hosts': [[r['host__hostname'], r['n']] for r in
                  qs.values('host__hostname').annotate(n=Count('id'))
                  .order_by('-n')[:TOP_N]],
        'ports': top('dst_port', is_text=False),
        'ips': top('dst_ip'),
        'apps': top('process_name'),
    }


def _rules_summary(now):
    qs = FirewallRule.objects.all()
    return {
        'total': qs.count(),
        'pending': qs.filter(status='pending_deploy').count(),
        'auto': qs.filter(source='auto').count(),
        'temporary': qs.filter(expire_at__isnull=False).count(),
        'expiring': qs.filter(
            expire_at__gt=now,
            expire_at__lte=now + timedelta(days=EXPIRING_DAYS),
        ).count(),
        'unused': qs.filter(status='recycle_candidate').count(),
    }


def _tasks_summary():
    qs = AnsibleTaskRecord.objects.all()
    return {
        'running': qs.filter(status__in=('pending', 'running')).count(),
        'success': qs.filter(status='success').count(),
        'failed': qs.filter(status__in=('failed', 'timeout')).count(),
    }


def _risk_summary(now):
    since = now - timedelta(hours=24)
    comms = CommunicationRelation.objects.all()
    external = 0
    for ip in comms.values_list('remote_ip', flat=True):
        if ip and not _is_internal_ip(ip):
            external += 1
    return {
        # 近 24h 被阻断的事件数（攻击/越权访问尝试）
        'high_events': FirewallEvent.objects.filter(
            timestamp__gte=since, action='DROP').count(),
        # 进程名未知的通信关系
        'unknown_apps': comms.filter(process_name='').count(),
        # 目标为非内网 IP 的通信关系
        'external_comms': external,
        # 涉及敏感端口的通信关系
        'sensitive_ports': comms.filter(
            remote_port__in=SENSITIVE_PORTS).count(),
    }


def build_dashboard_data() -> dict:
    """监控看板聚合数据（§6 JSON 结构冻结）。"""
    now = timezone.now()
    return {
        'host_summary': _host_summary(now),
        'today': _today_events(now),
        'trend_24h': _trend_24h(now),
        'top': _top_lists(now),
        'rules': _rules_summary(now),
        'tasks': _tasks_summary(),
        'risk': _risk_summary(now),
    }
