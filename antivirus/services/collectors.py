"""病毒检测采集编排：读取 Defender 检出事件（断点续采）+ 隔离文件留存到 UNC。

容错红线：任何 Ansible/主机失败只影响该主机该步，写入 AvCollectState.last_status，
绝不中断批量任务；不触碰 Defender 内部隔离目录。

主机清单与 Ansible 执行层复用 firewall 模块（FirewallHost / run_playbook /
parse_host_json / AnsibleTaskRecord），AV playbook 位于 firewall/ansible/av_*.yml。
"""
import logging

from django.conf import settings
from django.utils import timezone

from firewall.models import FirewallHost
from firewall.services.ansible_executor import parse_host_json, run_playbook

from antivirus.models import AvCollectState, AvDetection
from antivirus.services import ingest

logger = logging.getLogger(__name__)


def _get_host(host_id) -> FirewallHost:
    return FirewallHost.objects.get(id=host_id)


def _get_state(host) -> AvCollectState:
    state, _ = AvCollectState.objects.get_or_create(host=host)
    return state


def _allowed_av_ips() -> set:
    """采集白名单：settings.AV_COLLECT_HOST_IPS（去空白）。"""
    return {str(ip).strip()
            for ip in getattr(settings, 'AV_COLLECT_HOST_IPS', [])
            if ip and str(ip).strip()}


def is_av_collect_enabled(host) -> bool:
    """该主机是否在采集白名单内。白名单为空时一律不采集（安全默认）。"""
    allowed = _allowed_av_ips()
    return bool(allowed) and host.ip in allowed


def get_av_collect_host_ids() -> list:
    """允许采集的主机 id：防火墙侧 enabled 且 IP 命中 AV_COLLECT_HOST_IPS。"""
    allowed = _allowed_av_ips()
    if not allowed:
        return []
    return list(FirewallHost.objects
                .filter(enabled=True, ip__in=allowed)
                .values_list('id', flat=True))


def build_quarantine_dir(detection: AvDetection) -> str:
    """按"日期/事件ID"构造 UNC 隔离目录：{ROOT}\\YYYY\\MM\\DD\\{detection_id}。

    路径供目标 Windows 主机上的 PowerShell 脚本使用，故统一用反斜杠拼接。
    """
    root = str(getattr(settings, 'AV_QUARANTINE_ROOT', '') or '').rstrip('\\/')
    local_date = timezone.localtime(detection.detected_at).date()
    return f'{root}\\{local_date:%Y}\\{local_date:%m}\\{local_date:%d}\\{detection.id}'


def collect_host_detections(host_id) -> int:
    """读取主机 Defender 检出事件并入库；返回新增条数。

    断点续采：以 AvCollectState.last_record_id 为水位，只采 RecordId 更大的事件；
    成功后把水位推进到本批最大 RecordId，服务器/采集程序重启后不重不漏。

    采集范围：仅白名单(settings.AV_COLLECT_HOST_IPS)内的主机才执行，其余直接跳过。
    """
    host = _get_host(host_id)
    if not is_av_collect_enabled(host):
        logger.info('主机 %s 不在病毒采集白名单(AV_COLLECT_HOST_IPS)，跳过采集',
                    host.ip)
        return 0
    state = _get_state(host)
    since_record_id = int(state.last_record_id or 0)

    # 单批最多处理 max_events 条事件（PS 脚本默认 1000，这里收紧为可配置）。
    # 与下面的 timeout 配合，保证「一批能在超时内跑完 → 返回 max_record_id →
    # 水位推进 → 积压分多批排空」。此前用默认 300s 超时且不限制批量，一旦积压的
    # 事件里需要 Get-FileHash 的文件较多，单批耗时 >300s → run_playbook 超时 →
    # stdout 为空 → 水位不推进 → 下次同样批量再次超时，形成永不排空的死循环
    # （现场表现：av_collect_detections 执行超时，Task 每次都在 ~320s 失败）。
    max_events = int(getattr(settings, 'AV_COLLECT_MAX_EVENTS', 300) or 300)
    av_timeout = int(getattr(settings, 'AV_COLLECT_TIMEOUT', 600) or 600)
    # 哈希预算：Get-FileHash 整文件读盘，遇大容器(ISO/VHD/大压缩包)单个就可能数分钟，
    # 是历史超时(609s>600s)的主因。给单文件/文件数/累计字节三重上限，超限文件跳过哈希
    # 但仍记录检出(file_size + hash_skipped)，绝不丢事件。默认值已足够保守，可按需调大。
    max_hash_files = int(getattr(settings, 'AV_COLLECT_MAX_HASH_FILES', 50) or 50)
    max_hash_bytes = int(getattr(settings, 'AV_COLLECT_MAX_HASH_BYTES', 104857600) or 104857600)
    max_hash_total_bytes = int(
        getattr(settings, 'AV_COLLECT_MAX_HASH_TOTAL_BYTES', 314572800) or 314572800)

    res = run_playbook(
        'av_collect_detections.yml',
        {'target_host': host.ip, 'since_record_id': since_record_id,
         'max_events': max_events, 'max_hash_files': max_hash_files,
         'max_hash_bytes': max_hash_bytes,
         'max_hash_total_bytes': max_hash_total_bytes},
        name='av_collect_detections', timeout=av_timeout)

    if not res['ok']:
        blob = (res.get('stdout', '') + res.get('error', '')).lower()
        state.last_status = 'unreachable' if 'unreachable' in blob else 'failed'
        state.last_collect_time = timezone.now()
        state.save(update_fields=['last_status', 'last_collect_time', 'updated_at'])
        logger.warning('主机 %s 病毒事件采集失败: %s', host.ip, res.get('error'))
        return 0

    data = parse_host_json(res['stdout'], host.ip)
    if data is None:
        state.last_status = 'parse_failed'
        state.last_collect_time = timezone.now()
        state.save(update_fields=['last_status', 'last_collect_time', 'updated_at'])
        logger.warning('主机 %s 病毒事件采集输出解析失败', host.ip)
        return 0

    events = data.get('events') or []
    # 回传各相位耗时与哈希统计：直接回答"日志检索慢还是哈希慢"，便于现场诊断超时。
    timings = data.get('timings') or {}
    if timings:
        logger.info('主机 %s 采集耗时(ms) fetch=%s parse=%s hash=%s total=%s；哈希统计 %s；计数 %s',
                    host.ip, timings.get('fetch_ms'), timings.get('parse_ms'),
                    timings.get('hash_ms'), timings.get('total_ms'),
                    data.get('hash_stats') or {}, data.get('counts') or {})
    added = ingest.ingest_detections(host, events)

    # 推进水位：取脚本回传的 max_record_id；缺失时用本批事件最大 RecordId 兜底
    max_record_id = data.get('max_record_id')
    if max_record_id is None:
        record_ids = [e.get('record_id') for e in events
                      if isinstance(e, dict) and e.get('record_id') is not None]
        max_record_id = max(record_ids) if record_ids else since_record_id
    try:
        max_record_id = int(max_record_id)
    except (TypeError, ValueError):
        max_record_id = since_record_id
    # 水位只前进不后退
    if max_record_id > since_record_id:
        state.last_record_id = max_record_id

    state.last_status = 'success'
    state.last_collect_time = timezone.now()
    state.save(update_fields=['last_record_id', 'last_status',
                              'last_collect_time', 'updated_at'])
    logger.info('主机 %s 病毒事件采集新增 %d 条，水位推进到 %s',
                host.ip, added, state.last_record_id)
    return added


def collect_all_hosts() -> int:
    """仅对采集白名单(settings.AV_COLLECT_HOST_IPS)内的主机逐个采集；返回分发主机数。

    白名单是采集范围的唯一开关：需要给新机器开通病毒检测，把它的 IP 加进
    settings.AV_COLLECT_HOST_IPS（或环境变量）即可，无需改代码。白名单为空则不采集。
    """
    host_ids = get_av_collect_host_ids()
    for host_id in host_ids:
        try:
            collect_host_detections(host_id)
        except Exception:
            logger.exception('主机 %s 病毒事件采集异常', host_id)
    return len(host_ids)


def preserve_quarantine_file(detection_id, operator='system'):
    """把检出文件从原始路径安全转存到 UNC 隔离目录（不触碰 Defender 内部目录）。

    返回 (ok: bool, message: str)。成功后回写 quarantine_path / sha256 /
    file_size / quarantine_status。原文件已被 Defender 清除时标记 unavailable。
    """
    detection = AvDetection.objects.get(id=detection_id)
    host = detection.host
    dest_dir = build_quarantine_dir(detection)

    res = run_playbook(
        'av_preserve_file.yml',
        {'target_host': host.ip,
         'source_path': detection.original_path,
         'dest_dir': dest_dir,
         'file_name': detection.file_name},
        name='av_preserve_file', initiated_by=operator)

    if not res['ok']:
        logger.warning('主机 %s 隔离留存任务失败: %s', host.ip, res.get('error'))
        return False, res.get('error') or '留存任务执行失败'

    data = parse_host_json(res['stdout'], host.ip)
    if data is None:
        return False, '留存结果解析失败'

    preserved_path = str(data.get('preserved_path') or '')
    sha256 = str(data.get('sha256') or '').lower()
    file_size = data.get('file_size')

    if data.get('source_exists') is False or not preserved_path:
        # 原文件已不可得（多已被 Defender 隔离/清除）：记录状态，不视为错误
        detection.quarantine_status = 'unavailable'
        if sha256 and not detection.sha256:
            detection.sha256 = sha256[:64]
        detection.save(update_fields=['quarantine_status', 'sha256', 'updated_at'])
        return True, '原文件已不可得（可能已被 Defender 隔离），已记录状态'

    detection.quarantine_path = preserved_path[:500]
    detection.quarantine_status = 'preserved'
    if sha256:
        detection.sha256 = sha256[:64]
    if file_size is not None:
        try:
            detection.file_size = int(file_size)
        except (TypeError, ValueError):
            pass
    detection.save(update_fields=['quarantine_path', 'quarantine_status',
                                  'sha256', 'file_size', 'updated_at'])
    return True, f'已留存到 {preserved_path}'
