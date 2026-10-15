"""病毒模块看板聚合 / API 序列化。

视图保持薄：api_dashboard 只调用 build_dashboard_data() 并 JsonResponse。
所有统计走 DB 聚合（Count / TruncDate），绝不全表 Python 扫描，也不实时调 Ansible。
"""
from datetime import timedelta

from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone

from antivirus.models import AvCollectState, AvDetection

TOP_N = 8
TREND_DAYS = 14


def _status_summary():
    qs = AvDetection.objects.all()
    return {
        'total': qs.count(),
        'pending_review': qs.filter(status='pending_review').count(),
        'confirmed_malicious': qs.filter(status='confirmed_malicious').count(),
        'false_positive': qs.filter(status='false_positive').count(),
        'restored': qs.filter(status='restored').count(),
        'cleaned': qs.filter(status='cleaned').count(),
    }


def _quarantine_summary():
    qs = AvDetection.objects.all()
    return {
        'preserved': qs.filter(quarantine_status='preserved').count(),
        'pending': qs.filter(quarantine_status='pending').count(),
        'unavailable': qs.filter(quarantine_status='unavailable').count(),
    }


def _by_host():
    """按服务器统计检测数（TOP N）。"""
    rows = (AvDetection.objects
            .values('host__hostname', 'host__ip')
            .annotate(n=Count('id'))
            .order_by('-n')[:TOP_N])
    return [[f"{r['host__hostname']}({r['host__ip']})", r['n']] for r in rows]


def _by_threat_type():
    """按威胁类型统计（TOP N）；threat_type 为空时归入"未分类"。"""
    rows = (AvDetection.objects
            .values('threat_type')
            .annotate(n=Count('id'))
            .order_by('-n')[:TOP_N])
    return [[(r['threat_type'] or '未分类'), r['n']] for r in rows]


def _by_threat_name():
    """按 Defender 威胁名称统计（TOP N）。"""
    rows = (AvDetection.objects
            .exclude(threat_name='')
            .values('threat_name')
            .annotate(n=Count('id'))
            .order_by('-n')[:TOP_N])
    return [[r['threat_name'], r['n']] for r in rows]


def _trend(now):
    """近 TREND_DAYS 天按日聚合检测数（旧→新）。"""
    local_now = timezone.localtime(now)
    start_date = (local_now - timedelta(days=TREND_DAYS - 1)).date()
    buckets = {}
    for i in range(TREND_DAYS):
        d = start_date + timedelta(days=i)
        buckets[d.strftime('%m-%d')] = {'day': d.strftime('%m-%d'), 'count': 0}
    rows = (AvDetection.objects
            .filter(detected_at__date__gte=start_date)
            .annotate(day=TruncDate('detected_at',
                                    tzinfo=timezone.get_current_timezone()))
            .values('day')
            .annotate(n=Count('id')))
    for row in rows:
        label = timezone.localtime(row['day']).strftime('%m-%d') \
            if hasattr(row['day'], 'hour') else row['day'].strftime('%m-%d')
        if label in buckets:
            buckets[label]['count'] = row['n']
    return list(buckets.values())


def _collect_summary(now):
    """采集健康度：纳入管理主机数、最近 1 小时内成功采集数、失败/过期数。"""
    stale_before = now - timedelta(hours=1)
    qs = AvCollectState.objects.all()
    return {
        'tracked': qs.count(),
        'ok': qs.filter(last_status='success',
                        last_collect_time__gte=stale_before).count(),
        'failed': qs.filter(last_status__in=('failed', 'unreachable',
                                             'parse_failed')).count(),
        'stale': qs.filter(last_collect_time__lt=stale_before).count()
                 + qs.filter(last_collect_time__isnull=True).count(),
    }


def build_dashboard_data() -> dict:
    """病毒检测与隔离看板聚合数据。"""
    now = timezone.now()
    return {
        'status': _status_summary(),
        'quarantine': _quarantine_summary(),
        'by_host': _by_host(),
        'by_threat_type': _by_threat_type(),
        'by_threat_name': _by_threat_name(),
        'trend': _trend(now),
        'collect': _collect_summary(now),
    }
