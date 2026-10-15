# -*- coding: utf-8 -*-
"""运维分析——Nginx 日志窗口只读统计（服务故障排查用）。

红线：只读，仅读取日志文件尾部，绝不改写/轮转/重载 nginx。
在给定时间窗口内统计：
  - access 日志：请求总数、各 HTTP 状态码计数（重点 502/503/504）、按分钟分布
  - error  日志：upstream 相关错误签名计数（connect() failed / upstream timed out /
    no live upstreams / recv() failed / prematurely closed 等）+ 少量样本行作证据
只读文件尾部若干字节，避免加载超大日志。时间为服务器本地时间（naive）比较。

兼容 Python 2.7 / 3.x。用法:
    python probe_nginx_logs.py --access "a.log,b.log" --error "e.log" [--window-min 30] [--tail-bytes 4194304] [--match "ip:port,domain"]
  --match: 本服务归属标识(后端IP:端口 / 域名)。error 日志通常全局共享，只统计命中这些
           token 的行(属于本服务)，避免把别的服务的 connection refused 也算进来。
  路径变量: --access/--error 的路径若含 nginx 变量(如 $yms)，会自动 glob 解析成磁盘真实
           文件(取最近修改者)——按月/日轮转的日志名下个月还会变，故在探测时动态解析。
作者: AUTO-GENERATED (opsanalysis module)
"""
from __future__ import print_function

import glob
import json
import os
import re
import sys
from datetime import datetime, timedelta

# access 时间戳有两种常见写法，都要能识别（否则整份日志一条都匹配不上，误报"尾部无记录"）：
#   $time_local   : [11/Oct/2026:20:56:58 +0800]
#   $time_iso8601 : [2026-10-11T20:56:58+08:00]
# group(1) 只截到"秒"，时区后缀由后面的 [^\]]* 吃掉，保证解析用固定格式即可。
ACCESS_RE = re.compile(
    r'\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}'   # $time_local
    r'|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'          # $time_iso8601
    r')[^\]]*\]\s+"[^"]*"\s+(\d{3})')
# error: yyyy/mm/dd HH:MM:SS [level] ...
ERROR_TS_RE = re.compile(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})')

ERROR_SIGNATURES = [
    ('connect() failed', 'connect() failed'),
    ('connection refused', 'Connection refused'),
    ('upstream timed out', 'upstream timed out'),
    ('no live upstreams', 'no live upstreams'),
    ('recv() failed', 'recv() failed'),
    ('prematurely closed', 'prematurely closed connection'),
    ('upstream prematurely', 'upstream prematurely closed'),
    ('502', ' 502 '),
]

# 兼容 $time_local / $time_iso8601（含空格变体）三种秒级格式
ACCESS_TS_FMTS = ('%d/%b/%Y:%H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S')
ERROR_TS_FMT = '%Y/%m/%d %H:%M:%S'


def _parse_access_ts(raw):
    """把 access 日志里的时间戳字符串解析成 naive datetime（丢弃时区，按服务器本地时间比较）。
    依次尝试 $time_local / $time_iso8601 两种格式，都不匹配则返回 None。"""
    if not raw:
        return None
    for fmt in ACCESS_TS_FMTS:
        try:
            return datetime.strptime(raw, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _args(argv):
    access = ''; error = ''; window = 30; tail = 4 * 1024 * 1024; match = ''
    i = 0
    while i < len(argv):
        a = argv[i]
        try:
            if a == '--access' and i + 1 < len(argv):
                access = argv[i + 1]; i += 2; continue
            if a == '--error' and i + 1 < len(argv):
                error = argv[i + 1]; i += 2; continue
            if a == '--window-min' and i + 1 < len(argv):
                window = int(argv[i + 1]); i += 2; continue
            if a == '--tail-bytes' and i + 1 < len(argv):
                tail = int(argv[i + 1]); i += 2; continue
            if a == '--match' and i + 1 < len(argv):
                match = argv[i + 1]; i += 2; continue
        except (ValueError, TypeError):
            pass
        i += 1
    return access, error, window, tail, match


def _split_paths(s):
    return [x.strip() for x in re.split(r'[,;\n]', s or '') if x.strip()]


# nginx 路径变量：$yms / ${yms} 等（access_log/error_log 指令里可含变量，写盘时求值）
_NGINX_VAR_RE = re.compile(r'\$\{?[A-Za-z0-9_]+\}?')


def _resolve_log_path(path):
    """把 nginx 配置里带变量的日志路径解析成磁盘上的真实文件名。

    nginx 的 access_log/error_log 路径可含变量(如 $yms)，实际写盘时被求值——
    例如配置 /log/$yms.mes-access.log 的真实文件是 /log/2026-10.mes-access.log，
    且按月/日轮转，下个月文件名还会变。故登记里存的是配置原文(带 $var)，
    探测时必须动态解析：
      - 原样能找到文件 → 直接用；
      - 含 $var 且原样找不到 → 把 $var 当通配符 glob，取"最近修改"的匹配文件
        (通常就是当前周期正在写入的那个)；
      - glob 也无匹配 → 原样返回(交由上层报"文件不存在")。
    返回 (真实路径, 是否经过变量解析)。"""
    if not path:
        return path, False
    if os.path.isfile(path):
        return path, False
    if '$' not in path:
        return path, False
    pattern = _NGINX_VAR_RE.sub('*', path)
    try:
        matches = [m for m in glob.glob(pattern) if os.path.isfile(m)]
    except Exception:
        matches = []
    if not matches:
        return path, False
    try:
        matches.sort(key=lambda m: os.path.getmtime(m), reverse=True)
    except Exception:
        pass
    return matches[0], True


def _tail_text(path, tail_bytes):
    """只读文件尾部 tail_bytes 字节，返回文本行列表。"""
    try:
        size = os.path.getsize(path)
        with open(path, 'rb') as f:
            if size > tail_bytes:
                f.seek(size - tail_bytes)
                f.read(1024)  # 丢弃可能被截断的半行
            raw = f.read()
        return raw.decode('utf-8', 'replace').splitlines()
    except Exception:
        return None


def probe_access(path, window_start, tail_bytes):
    # last_any_ts / last_ok_ts：扫描整个尾部(不受窗口限制)，回答"最近一次(正常)访问是何时"。
    # 日志按时间追加，故最后一条匹配行即最近；ok 指 2xx/3xx。
    res = {'path': path, 'exists': os.path.isfile(path), 'total_in_window': 0,
           'ok_in_window': 0, 'status_counts': {}, 'per_minute_5xx': {},
           'last_ts': '', 'last_any_ts': '', 'last_ok_ts': '',
           'lines_scanned': 0, 'lines_matched': 0, 'sample_tail': '', 'error': ''}
    if not res['exists']:
        res['error'] = '文件不存在'
        return res
    lines = _tail_text(path, tail_bytes)
    if lines is None:
        res['error'] = '读取失败'
        return res
    for line in lines:
        if not line.strip():
            continue
        res['lines_scanned'] += 1
        # 记下尾部一条原始样本：万一格式仍不识别(0 matched)，上层能据此看出真实时间戳格式
        res['sample_tail'] = line.strip()[:200]
        m = ACCESS_RE.search(line)
        if not m:
            continue
        ts = _parse_access_ts(m.group(1))
        if ts is None:
            continue
        res['lines_matched'] += 1
        status = m.group(2)
        raw_ts = m.group(1)
        # 全量最近访问（跨窗口，供"最近正常访问日期"用）
        res['last_any_ts'] = raw_ts
        if status[0] in ('2', '3'):
            res['last_ok_ts'] = raw_ts
        if ts < window_start:
            continue
        res['total_in_window'] += 1
        res['status_counts'][status] = res['status_counts'].get(status, 0) + 1
        res['last_ts'] = raw_ts
        if status[0] in ('2', '3'):
            res['ok_in_window'] += 1
        if status.startswith('5'):
            minute = ts.strftime('%Y-%m-%d %H:%M')
            res['per_minute_5xx'][minute] = res['per_minute_5xx'].get(minute, 0) + 1
    return res


def probe_error(path, window_start, tail_bytes, match_tokens=None):
    # nginx error 日志通常是全局共享的：一个文件里混着所有 upstream/服务的错误。
    # 若不按服务过滤，会把别的服务的 connection refused 也算到本服务头上，排查失真。
    # nginx 的 upstream 错误行带归属信息：upstream: "http://后端IP:端口/"、server:/host: 域名。
    # match_tokens 传入本服务的 [后端IP:端口, 域名...]，只有行里命中任一 token 才算"属于本服务"。
    #   total_in_window   —— 属于本服务的命中行数（权威计数，用于排查）
    #   total_all_services—— 该文件窗口内所有服务的命中行数（对照，让你知道过滤掉了多少）
    # signatures/first_ts/last_ts/per_minute/samples 均只统计"属于本服务"的行。
    # match_tokens 为空时无法区分归属，退回统计全部，并置 service_scoped=False 明确告知。
    tokens = [t.lower() for t in (match_tokens or []) if t]
    service_scoped = bool(tokens)
    res = {'path': path, 'exists': os.path.isfile(path), 'total_in_window': 0,
           'total_all_services': 0, 'service_scoped': service_scoped,
           'match_tokens': list(match_tokens or []),
           'signatures': {}, 'samples': [], 'first_ts': '', 'last_ts': '',
           'per_minute': {}, 'error': ''}
    if not res['exists']:
        res['error'] = '文件不存在'
        return res
    lines = _tail_text(path, tail_bytes)
    if lines is None:
        res['error'] = '读取失败'
        return res
    for line in lines:
        m = ERROR_TS_RE.match(line)
        ts = None
        if m:
            try:
                ts = datetime.strptime(m.group(1), ERROR_TS_FMT)
            except (ValueError, TypeError):
                ts = None
        if ts is not None and ts < window_start:
            continue
        # 无时间戳的行（续行）也参与签名匹配，但不计入窗口过滤
        low = line.lower()
        hit_sig = False
        for key, sig in ERROR_SIGNATURES:
            if sig.lower() in low:
                hit_sig = True
                break
        if not hit_sig:
            continue
        # 命中签名 → 先计入"全局所有服务"
        res['total_all_services'] += 1
        # 归属过滤：提供了 token 就只认属于本服务的行
        if service_scoped and not any(tok in low for tok in tokens):
            continue
        for key, sig in ERROR_SIGNATURES:
            if sig.lower() in low:
                res['signatures'][key] = res['signatures'].get(key, 0) + 1
        res['total_in_window'] += 1
        if ts is not None:
            if not res['first_ts']:
                res['first_ts'] = m.group(1)
            res['last_ts'] = m.group(1)
            minute = ts.strftime('%Y-%m-%d %H:%M')
            res['per_minute'][minute] = res['per_minute'].get(minute, 0) + 1
        if len(res['samples']) < 8:
            res['samples'].append(line.strip()[:300])
    return res


def main():
    access, error, window, tail, match = _args(sys.argv[1:])
    now = datetime.now()
    window_start = now - timedelta(minutes=window)
    match_tokens = _split_paths(match)  # 复用分隔逻辑：逗号/分号/换行分隔的归属 token

    # nginx 日志路径可能含变量($yms 等)，先解析成磁盘真实文件再探测
    access_logs = []
    for cp in _split_paths(access):
        rp, resolved = _resolve_log_path(cp)
        r = probe_access(rp, window_start, tail)
        r['configured_path'] = cp
        r['path_resolved'] = resolved
        access_logs.append(r)
    error_logs = []
    for cp in _split_paths(error):
        rp, resolved = _resolve_log_path(cp)
        r = probe_error(rp, window_start, tail, match_tokens)
        r['configured_path'] = cp
        r['path_resolved'] = resolved
        error_logs.append(r)

    data = {
        'window_min': window,
        'window_start': window_start.strftime('%Y-%m-%d %H:%M:%S'),
        'now': now.strftime('%Y-%m-%d %H:%M:%S'),
        'match_tokens': match_tokens,
        'access_logs': access_logs,
        'error_logs': error_logs,
        'error': '',
    }
    # 汇总标记
    has_5xx = any(int(k) >= 500 for a in data['access_logs']
                  for k in a.get('status_counts', {}))
    has_upstream_err = any(e.get('signatures') for e in data['error_logs'])
    data['summary'] = {'has_5xx': has_5xx, 'has_upstream_errors': has_upstream_err}
    print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))


if __name__ == '__main__':
    main()
