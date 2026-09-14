"""防火墙事件入库：字段归一化 + event_hash 去重 + bulk_create。

去重红线：unique(host, event_hash) + 预查已存在 hash + ignore_conflicts。
时区：naive datetime 一律按 Asia/Shanghai 转 aware。
"""
import hashlib
import logging
from datetime import datetime
from zoneinfo import ZoneInfo

from firewall.models import FirewallEvent

logger = logging.getLogger(__name__)

LOCAL_TZ = ZoneInfo('Asia/Shanghai')

_QUERY_BATCH = 500
_CREATE_BATCH = 500


def make_event_hash(host_id, ts, action, proto, src_ip, src_port,
                    dst_ip, dst_port, pid) -> str:
    """事件指纹：同参同值，sha256[:32]。"""
    if isinstance(ts, datetime):
        ts_str = ts.isoformat()
    else:
        ts_str = str(ts or '')
    raw = '|'.join([
        str(host_id), ts_str, str(action or ''), str(proto or ''),
        str(src_ip or ''), str(src_port if src_port is not None else ''),
        str(dst_ip or ''), str(dst_port if dst_port is not None else ''),
        str(pid if pid is not None else ''),
    ])
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:32]


def _to_int(value):
    if value is None or value == '':
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_ts(value):
    """解析事件时间；naive 按 Asia/Shanghai 转 aware；解析失败返回 None。"""
    if value is None or value == '':
        return None
    dt = None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        try:
            dt = datetime.fromisoformat(text.replace('Z', '+00:00'))
        except ValueError:
            for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S',
                        '%Y/%m/%d %H:%M:%S', '%m/%d/%Y %H:%M:%S'):
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=LOCAL_TZ)
    return dt


def _normalize(event: dict):
    """归一化字段：缺省补空/None、端口与 pid 转 int 或 None。
    返回 (kwargs, event_hash) 或 None（时间/动作无效时丢弃）。"""
    ts = _parse_ts(event.get('time') or event.get('timestamp'))
    if ts is None:
        return None
    action = str(event.get('action') or '').upper()
    if action not in ('DROP', 'ALLOW'):
        return None
    protocol = str(event.get('protocol') or 'TCP').upper()[:10]
    src_port = _to_int(event.get('src_port'))
    dst_port = _to_int(event.get('dst_port'))
    pid = _to_int(event.get('pid'))
    kwargs = {
        'timestamp': ts,
        'action': action,
        'protocol': protocol,
        'direction': str(event.get('direction') or '')[:10],
        'src_ip': str(event.get('src_ip') or '')[:64],
        'src_port': src_port,
        'dst_ip': str(event.get('dst_ip') or '')[:64],
        'dst_port': dst_port,
        'process_name': str(event.get('process_name') or '')[:255],
        'process_path': str(event.get('process_path') or '')[:500],
        'pid': pid,
        'service_name': str(event.get('service_name') or '')[:255],
    }
    return kwargs, ts, action, protocol, src_port, dst_port, pid


def ingest_events(host, events: list[dict]) -> int:
    """归一化字段→make_event_hash→查重→bulk_create 去重；返回实际新增数。"""
    if not events:
        return 0

    candidates = []
    seen_in_batch = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        norm = _normalize(event)
        if norm is None:
            continue
        kwargs, ts, action, protocol, src_port, dst_port, pid = norm
        event_hash = make_event_hash(
            host.id, ts, action, protocol,
            kwargs['src_ip'], src_port, kwargs['dst_ip'], dst_port, pid,
        )
        if event_hash in seen_in_batch:
            continue
        seen_in_batch.add(event_hash)
        kwargs['event_hash'] = event_hash
        candidates.append(kwargs)

    if not candidates:
        return 0

    # 分批 in 查询已存在的 hash
    hashes = [c['event_hash'] for c in candidates]
    existing = set()
    for i in range(0, len(hashes), _QUERY_BATCH):
        chunk = hashes[i:i + _QUERY_BATCH]
        existing.update(
            FirewallEvent.objects.filter(host=host, event_hash__in=chunk)
            .values_list('event_hash', flat=True)
        )

    new_objects = [
        FirewallEvent(host=host, **c) for c in candidates
        if c['event_hash'] not in existing
    ]
    if not new_objects:
        return 0

    FirewallEvent.objects.bulk_create(
        new_objects, batch_size=_CREATE_BATCH, ignore_conflicts=True,
    )
    logger.info('主机 %s 事件入库：候选 %d，新增 %d',
                host.ip, len(candidates), len(new_objects))
    return len(new_objects)
