# -*- coding: utf-8 -*-
"""运维分析——DNS/域名解析只读探测（服务故障排查用）。

红线：只读，仅 nslookup/getent/ping 查询，绝不改 DNS、绝不写任何区域记录。
对指定域名，逐台 DNS 服务器解析，并给出本机解析结果与 ping 可达性，
供上层判断"域名解析是否正确/是否指向预期后端 IP"。

兼容 Python 2.7 / 3.x。用法:
    python probe_dns.py --domain ywops.4307.com [--servers 192.168.2.86,192.168.2.66,192.168.2.105]
作者: AUTO-GENERATED (opsanalysis module)
"""
from __future__ import print_function

import json
import re
import subprocess
import sys

DEFAULT_SERVERS = '192.168.2.86,192.168.2.66,192.168.2.105'
ADDR_RE = re.compile(r'Address(?:es)?:\s*([0-9a-fA-F:.]+)')
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def run(cmd, timeout=8):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if isinstance(out, bytes):
            out = out.decode('utf-8', 'replace')
        if isinstance(err, bytes):
            err = err.decode('utf-8', 'replace')
        return (p.returncode if p.returncode is not None else -1), out, err
    except Exception as e:
        return (-1, '', str(e))


def _args(argv):
    domain = ''
    servers = DEFAULT_SERVERS
    i = 0
    while i < len(argv):
        if argv[i] == '--domain' and i + 1 < len(argv):
            domain = argv[i + 1]; i += 2; continue
        if argv[i] == '--servers' and i + 1 < len(argv):
            servers = argv[i + 1]; i += 2; continue
        i += 1
    return domain, servers


def nslookup(domain, server):
    """向指定 DNS 服务器查询，返回该服务器给出的 A 记录地址列表。"""
    rc, out, err = run(['nslookup', domain, server])
    addrs = []
    text = out or ''
    # 跳过 "Server:/Address: x.x.x.x#53" 这类指向 DNS 服务器自身的行
    body = text
    idx = body.lower().find('name:')
    if idx >= 0:
        body = body[idx:]
    for m in ADDR_RE.finditer(body):
        val = m.group(1)
        if '#' in val:
            continue
        for ip in IPV4_RE.findall(val):
            if ip not in addrs:
                addrs.append(ip)
        if ':' in val and val not in addrs:  # IPv6
            addrs.append(val)
    error = ''
    if rc != 0 or not addrs:
        low = (text + ' ' + (err or '')).lower()
        if 'can' in low and 'find' in low or 'nxdomain' in low or 'failed' in low:
            error = 'NXDOMAIN/解析失败'
        elif not addrs:
            error = '无 A 记录返回'
    return {'server': server, 'addresses': addrs, 'returncode': rc, 'error': error}


def main():
    domain, servers = _args(sys.argv[1:])
    data = {'domain': domain, 'servers': [], 'getent': [], 'ping': {}, 'error': ''}
    if not domain:
        data['error'] = '未指定 --domain'
        print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))
        return
    try:
        for s in [x.strip() for x in servers.split(',') if x.strip()]:
            data['servers'].append(nslookup(domain, s))
        # 本机默认解析
        rc, out, _ = run(['getent', 'hosts', domain])
        if rc == 0:
            data['getent'] = IPV4_RE.findall(out)
        # ping 可达性（只发 1 包，只读探测）
        rc, out, _ = run(['ping', '-c', '1', '-W', '2', domain])
        pip = ''
        m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', out or '')
        if m:
            pip = m.group(1)
        rtt = ''
        m2 = re.search(r'time[=<]([\d.]+)\s*ms', out or '')
        if m2:
            rtt = m2.group(1)
        data['ping'] = {'ok': rc == 0, 'ip': pip, 'rtt_ms': rtt}
        # 各 DNS 是否解析一致
        sets = [sorted(set(s['addresses'])) for s in data['servers'] if s['addresses']]
        data['consistent'] = (len(set(map(tuple, sets))) <= 1) if sets else None
    except Exception as e:
        data['error'] = 'probe_error: %s' % e
    print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))


if __name__ == '__main__':
    main()
