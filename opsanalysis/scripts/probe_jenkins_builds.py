# -*- coding: utf-8 -*-
"""运维分析——Jenkins 最近构建只读探测（服务故障排查用）。

红线：只读，仅读取 jobs/<job>/builds/*/build.xml 与 changelog.xml，
绝不触发构建、绝不改配置。给出最近若干次构建的时间/结果/耗时与提交摘要，
用于把"最近一次部署时间"放进排查时间线（时间关联，不作因果断言）。

兼容 Python 2.7 / 3.x。用法:
    python probe_jenkins_builds.py --jobs-dir /var/lib/jenkins/jobs --job h5858_ywops [--max-builds 10]
作者: AUTO-GENERATED (opsanalysis module)
"""
from __future__ import print_function

import json
import os
import re
import sys
from datetime import datetime

try:
    import xml.etree.ElementTree as ET
except Exception:  # pragma: no cover
    ET = None


def _args(argv):
    jobs_dir = '/var/lib/jenkins/jobs'
    job = ''
    max_builds = 10
    i = 0
    while i < len(argv):
        a = argv[i]
        try:
            if a == '--jobs-dir' and i + 1 < len(argv):
                jobs_dir = argv[i + 1]; i += 2; continue
            if a == '--job' and i + 1 < len(argv):
                job = argv[i + 1]; i += 2; continue
            if a == '--max-builds' and i + 1 < len(argv):
                max_builds = int(argv[i + 1]); i += 2; continue
        except (ValueError, TypeError):
            pass
        i += 1
    return jobs_dir, job, max_builds


def _ms_to_iso(ms):
    try:
        return datetime.fromtimestamp(int(ms) / 1000.0).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError, OSError):
        return ''


def _tag(elem, name):
    """取直接/深层子节点文本（Jenkins build.xml 结构较稳定）。"""
    if elem is None:
        return ''
    node = elem.find(name)
    if node is None:
        # 退而用正则式遍历
        for child in elem.iter():
            if child.tag == name and child.text:
                return child.text.strip()
        return ''
    return (node.text or '').strip()


def parse_build(build_dir, number):
    info = {'number': number, 'result': '', 'timestamp': '', 'iso_time': '',
            'duration_ms': None, 'building': False, 'commits': []}
    bxml = os.path.join(build_dir, 'build.xml')
    if ET is not None and os.path.isfile(bxml):
        try:
            root = ET.parse(bxml).getroot()
            info['result'] = _tag(root, 'result')
            ts = _tag(root, 'timestamp')
            info['timestamp'] = ts
            info['iso_time'] = _ms_to_iso(ts)
            dur = _tag(root, 'duration')
            try:
                info['duration_ms'] = int(dur) if dur else None
            except (ValueError, TypeError):
                info['duration_ms'] = None
            building = _tag(root, 'building')
            info['building'] = str(building).lower() == 'true'
        except Exception:
            pass
    # changelog.xml：抓提交信息与作者（best-effort，纯文本正则，容忍结构差异）
    cxml = os.path.join(build_dir, 'changelog.xml')
    if os.path.isfile(cxml):
        try:
            with open(cxml) as f:
                text = f.read()
            for msg in re.findall(r'<msg>(.*?)</msg>', text, re.DOTALL)[:10]:
                msg = msg.strip().replace('\n', ' ')
                if msg:
                    info['commits'].append(msg[:200])
        except Exception:
            pass
    return info


def main():
    jobs_dir, job, max_builds = _args(sys.argv[1:])
    data = {'job': job, 'jobs_dir': jobs_dir, 'builds': [], 'last_success': None,
            'last_build': None, 'error': ''}
    try:
        if not job:
            data['error'] = '未指定 --job'
            print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))
            return
        builds_root = os.path.join(jobs_dir, job, 'builds')
        if not os.path.isdir(builds_root):
            data['error'] = 'builds 目录不存在: %s' % builds_root
            print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))
            return
        nums = []
        for name in os.listdir(builds_root):
            if name.isdigit():
                nums.append(int(name))
        nums.sort(reverse=True)
        for n in nums[:max_builds]:
            info = parse_build(os.path.join(builds_root, str(n)), n)
            data['builds'].append(info)
        # 最近一次构建 / 最近一次成功
        if data['builds']:
            data['last_build'] = data['builds'][0]
            for b in data['builds']:
                if (b.get('result') or '').upper() == 'SUCCESS':
                    data['last_success'] = b
                    break
    except Exception as e:
        data['error'] = 'jenkins_error: %s' % e
    print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))


if __name__ == '__main__':
    main()
