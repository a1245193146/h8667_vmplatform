"""病毒检测事件入库：字段归一化 + event_hash 去重 + bulk_create。

去重红线：unique(host, event_hash) + 预查已存在 hash + ignore_conflicts，
采集重试/断点续采重复投递时幂等，不会产生重复记录。
时区：naive datetime 一律按 Asia/Shanghai 转 aware。
"""
import hashlib
import logging
import os
import re
from datetime import datetime
from zoneinfo import ZoneInfo

from antivirus.defender_resources import resolve_resource
from antivirus.models import AvDetection

logger = logging.getLogger(__name__)

LOCAL_TZ = ZoneInfo('Asia/Shanghai')

_QUERY_BATCH = 500
_CREATE_BATCH = 500

# Defender 事件 Path 偶带前缀杂质（file: / containerfile: / 逗号 / 下划线等），
# 且压缩包嵌套感染时为 "<磁盘容器>;file:_<容器>-><内层>->...-><感染文件>"。
# 只有第一个 '->' 之前、第一个 ';' 之前才是磁盘上真实存在的最外层容器。
_DRIVE_RE = re.compile(r'[A-Za-z]:[\\/]')


def _clean_path(path: str) -> str:
    p = (path or '').strip()
    if not p:
        return ''
    arrow = p.find('->')
    if arrow >= 0:
        p = p[:arrow]
    semi = p.find(';')
    if semi >= 0:
        p = p[:semi]
    p = p.strip()
    m = _DRIVE_RE.search(p)
    if m and m.start() > 0:
        p = p[m.start():]
    return p


def make_event_hash(host_id, detection_id, record_id, threat_id,
                    resource_path) -> str:
    """事件指纹：同参同值，sha256[:32]。

    以 Defender 的 Detection ID（一次检出实例的 GUID，1116 检出与 1117 处置
    两条事件共享）为去重主键，保证"每个病毒文件唯一记录"，且跨采集批次幂等。
    Detection ID 缺失时退化为事件 RecordId。
    """
    ident = detection_id if detection_id else (
        str(record_id) if record_id is not None else '')
    raw = '|'.join([
        str(host_id), str(ident), str(threat_id or ''), str(resource_path or ''),
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
    """解析检测时间；naive 按 Asia/Shanghai 转 aware；解析失败返回 None。"""
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
                        '%Y/%m/%d %H:%M:%S', '%m/%d/%Y %H:%M:%S',
                        '%Y-%m-%dT%H:%M:%S.%f'):
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


def _basename(path: str) -> str:
    """从 Windows/UNC 路径取文件名（兼容 \\ 与 / 分隔）。"""
    if not path:
        return ''
    normalized = path.replace('/', '\\')
    return os.path.basename(normalized.replace('\\', '/'))


def _normalize(event: dict):
    """归一化一条 Defender 检出事件；时间无效则丢弃（返回 None）。"""
    detected_at = _parse_ts(event.get('detected_at') or event.get('time'))
    if detected_at is None:
        return None

    original_path = _clean_path(
        str(event.get('original_path') or event.get('path') or ''))[:500]
    # 完整原始资源链留档（不截断）：优先用采集脚本回传的 resource_path，
    # 兼容旧输出时回退到未清洗的 path。
    resource_path = str(event.get('resource_path') or event.get('path') or '')
    file_name = str(event.get('file_name') or '')[:255] or _basename(original_path)[:255]
    record_id = _to_int(event.get('record_id'))
    threat_id = str(event.get('threat_id') or '')[:64]
    detection_id = str(event.get('detection_id') or '')[:64]

    event_hash = make_event_hash(
        event.get('_host_id'), detection_id, record_id, threat_id, original_path)

    kwargs = {
        'detected_at': detected_at,
        'original_path': original_path,
        'resource_path': resource_path,
        'file_name': file_name,
        'file_size': _to_int(event.get('file_size')),
        'sha256': str(event.get('sha256') or '')[:64].lower(),
        'threat_name': str(event.get('threat_name') or '')[:255],
        # %%NNN 是 Defender 未渲染的消息资源引用（如 %%809=Quarantine），入库即还原成
        # 可读文本，避免界面/筛选/导出里出现用户看不懂的 %%809。未收录编号原样保留。
        'threat_type': resolve_resource(str(event.get('threat_type') or ''))[:100],
        'severity': resolve_resource(str(event.get('severity') or ''))[:50],
        'category': resolve_resource(str(event.get('category') or ''))[:100],
        'action_taken': resolve_resource(str(event.get('action_taken') or ''))[:50],
        'process_name': str(event.get('process_name') or '')[:500],
        'defender_threat_id': threat_id,
        'detection_source': str(event.get('detection_source') or 'eventlog')[:30],
        'defender_record_id': record_id,
        'event_hash': event_hash,
    }
    return kwargs, event_hash


def ingest_detections(host, events: list) -> int:
    """归一化→make_event_hash→查重→bulk_create 去重；返回候选新增数。

    注意：ignore_conflicts 下返回值是"预查后未存在的候选数"，
    与并发采集竞争时实际入库可能略少（与 firewall.event_ingest 同口径）。
    """
    if not events:
        return 0
    # PowerShell ConvertTo-Json 对单元素数组可能解包成对象，这里统一成 list
    if isinstance(events, dict):
        events = [events]

    candidates = []
    seen_in_batch = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        event = dict(event)
        event['_host_id'] = host.id
        norm = _normalize(event)
        if norm is None:
            continue
        kwargs, event_hash = norm
        if event_hash in seen_in_batch:
            continue
        seen_in_batch.add(event_hash)
        candidates.append(kwargs)

    if not candidates:
        return 0

    hashes = [c['event_hash'] for c in candidates]
    existing = set()
    for i in range(0, len(hashes), _QUERY_BATCH):
        chunk = hashes[i:i + _QUERY_BATCH]
        existing.update(
            AvDetection.objects.filter(host=host, event_hash__in=chunk)
            .values_list('event_hash', flat=True)
        )

    new_objects = [
        AvDetection(host=host, **c) for c in candidates
        if c['event_hash'] not in existing
    ]
    if new_objects:
        AvDetection.objects.bulk_create(
            new_objects, batch_size=_CREATE_BATCH, ignore_conflicts=True)

    # 富化已存在记录：1116(检出) 与 1117(处置) 可能跨采集批次到达，
    # 后到的处置结果/SHA256/大小等补齐到既有行（仅在原值为空时写入，不覆盖人工字段）。
    enriched = 0
    existing_candidates = [c for c in candidates if c['event_hash'] in existing]
    if existing_candidates:
        enriched = _enrich_existing(host, existing_candidates)

    logger.info('主机 %s 病毒事件入库：候选 %d，新增 %d，富化 %d',
                host.ip, len(candidates), len(new_objects), enriched)
    return len(new_objects)


# 允许富化的字段：仅当库中为空/None 且新值非空时写入（不覆盖状态/复核等人工字段）
_ENRICH_FIELDS = ('action_taken', 'sha256', 'file_size', 'threat_name',
                  'severity', 'category', 'threat_type', 'process_name')


def _enrich_existing(host, candidates: list) -> int:
    by_hash = {c['event_hash']: c for c in candidates}
    rows = AvDetection.objects.filter(host=host, event_hash__in=list(by_hash))
    updated = 0
    for row in rows:
        cand = by_hash.get(row.event_hash)
        if not cand:
            continue
        fields = []
        for f in _ENRICH_FIELDS:
            cur = getattr(row, f, None)
            new = cand.get(f)
            empty_cur = (cur is None) or (cur == '')
            if empty_cur and new not in (None, ''):
                setattr(row, f, new)
                fields.append(f)
        if fields:
            fields.append('updated_at')
            row.save(update_fields=fields)
            updated += 1
    return updated
