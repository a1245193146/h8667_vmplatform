# -*- coding: utf-8 -*-
"""运维分析——Nginx 配置只读解析（服务关联发现用）。

红线：全程只读，仅读取 nginx.conf 及其 include 的文件，绝不 reload/改写 nginx。
解析出：upstream(域名→ip:port 成员) 与 server(server_name/listen/access_log/
error_log/location.proxy_pass)，输出单行 JSON，供 Django 侧按 ip:port 关联。

兼容 Python 2.7 / 3.x。用法:
    python discover_nginx.py [--conf /usr/lib/nginx/conf/nginx.conf]
作者: AUTO-GENERATED (opsanalysis module)
"""
from __future__ import print_function

import glob
import json
import os
import re
import sys

DEFAULT_CONF = '/usr/lib/nginx/conf/nginx.conf'
MAX_INCLUDE_DEPTH = 5


def _args(argv):
    conf = DEFAULT_CONF
    i = 0
    while i < len(argv):
        if argv[i] == '--conf' and i + 1 < len(argv):
            conf = argv[i + 1]; i += 2; continue
        i += 1
    return conf


def _read_include(path, base_dir, depth):
    """读取 include 的文件（支持 glob），返回去掉注释的文本；深度受限，绝不抛出。"""
    if depth > MAX_INCLUDE_DEPTH:
        return ''
    chunks = []
    candidates = []
    if os.path.isabs(path):
        candidates = [path]
    else:
        candidates = [os.path.join(base_dir, path), path]
    files = []
    for c in candidates:
        matched = sorted(glob.glob(c)) if any(ch in c for ch in '*?[]') else (
            [c] if os.path.isfile(c) else [])
        if matched:
            files = matched
            break
    for fp in files:
        try:
            with open(fp) as f:
                raw = f.read()
        except Exception:
            continue
        raw = _strip_comments(raw)
        # 递归展开被 include 文件里的 include
        raw = _inline_includes(raw, os.path.dirname(fp), depth + 1)
        chunks.append(raw)
    return '\n'.join(chunks)


def _strip_comments(text):
    out = []
    for line in text.splitlines():
        # 去掉 # 注释（nginx 里 # 到行尾），保留原换行以维持结构
        idx = line.find('#')
        if idx >= 0:
            line = line[:idx]
        out.append(line)
    return '\n'.join(out)


def _inline_includes(text, base_dir, depth):
    """把 include xxx; 就地替换为其文件内容（best-effort）。"""
    if depth > MAX_INCLUDE_DEPTH:
        return text

    def repl(m):
        inc_path = m.group(1).strip().strip('"').strip("'")
        if not inc_path:
            return ''
        return _read_include(inc_path, base_dir, depth)

    return re.sub(r'include\s+([^;]+);', repl, text)


def _tokenize(text):
    return re.findall(r'[{};]|[^\s{};]+', text)


def _parse_block(tokens, i):
    """从 tokens[i] == '{' 之后开始解析，返回 (children, next_index)。
    children: list of dict{directive, args, children}。"""
    children = []
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == '}':
            return children, i + 1
        if tok == ';':
            i += 1
            continue
        if tok == '{':
            i += 1
            continue
        # directive
        directive = tok
        args = []
        i += 1
        while i < n and tokens[i] not in ('{', ';', '}'):
            args.append(tokens[i]); i += 1
        if i < n and tokens[i] == '{':
            sub, i = _parse_block(tokens, i + 1)
            children.append({'directive': directive, 'args': args, 'children': sub})
        else:
            children.append({'directive': directive, 'args': args, 'children': []})
            if i < n and tokens[i] == ';':
                i += 1
    return children, i


def _parse(text):
    tokens = _tokenize(text)
    children, _ = _parse_block(tokens, 0)
    return children


def _find(nodes, directive):
    return [n for n in nodes if n['directive'] == directive]


def _first_arg(nodes, directive, default=''):
    for n in nodes:
        if n['directive'] == directive and n['args']:
            return n['args'][0]
    return default


def _split_host_port(s):
    if not s:
        return '', None
    s = s.strip()
    if s.rfind(':') == -1:
        return s, None
    host, _, port = s.rpartition(':')
    host = host.strip('[]')
    try:
        return host, int(port)
    except (ValueError, TypeError):
        return s, None


def _walk_upstreams(nodes, out):
    for n in nodes:
        if n['directive'] == 'upstream':
            name = n['args'][0] if n['args'] else ''
            servers = []
            for s in _find(n['children'], 'server'):
                if not s['args']:
                    continue
                host, port = _split_host_port(s['args'][0])
                servers.append({'ip': host, 'port': port, 'raw': ' '.join(s['args'])})
            out.append({'name': name, 'servers': servers})
        if n['children']:
            _walk_upstreams(n['children'], out)


def _walk_servers(nodes, out):
    for n in nodes:
        if n['directive'] == 'server' and n['children']:
            # 只认块级 server（有 children），upstream 内的 server 是成员不在这里
            server_names = []
            for sn in _find(n['children'], 'server_name'):
                server_names.extend(sn['args'])
            listens = []
            for ls in _find(n['children'], 'listen'):
                if ls['args']:
                    listens.append(ls['args'][0])
            access_log = _first_arg(n['children'], 'access_log')
            error_log = _first_arg(n['children'], 'error_log')
            locations = []
            proxy_upstreams = []
            for loc in _find(n['children'], 'location'):
                path = loc['args'][0] if loc['args'] else ''
                pp = _first_arg(loc['children'], 'proxy_pass')
                locations.append({'path': path, 'proxy_pass': pp})
                if pp:
                    m = re.match(r'https?://([^/;]+)', pp)
                    if m:
                        proxy_upstreams.append(m.group(1))
            # server 级 proxy_pass（少见）
            pp = _first_arg(n['children'], 'proxy_pass')
            if pp:
                m = re.match(r'https?://([^/;]+)', pp)
                if m:
                    proxy_upstreams.append(m.group(1))
            out.append({
                'server_name': [x for x in server_names if x and x != '_'],
                'listen': listens,
                'access_log': access_log,
                'error_log': error_log,
                'proxy_upstreams': sorted(set(proxy_upstreams)),
                'locations': locations,
            })
        if n['children']:
            _walk_servers(n['children'], out)


def main():
    conf = _args(sys.argv[1:])
    data = {'nginx_conf': conf, 'global_access_log': '', 'global_error_log': '',
            'upstreams': [], 'servers': [], 'error': ''}
    try:
        if not os.path.isfile(conf):
            data['error'] = 'nginx.conf 不存在: %s' % conf
            print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))
            return
        with open(conf) as f:
            raw = f.read()
        raw = _strip_comments(raw)
        raw = _inline_includes(raw, os.path.dirname(conf), 0)
        tree = _parse(raw)
        # 全局（顶层或 http/stream 块首层）的 access_log / error_log
        g_err = _first_arg(tree, 'error_log')
        g_acc = _first_arg(tree, 'access_log')
        for blk in ('http', 'stream'):
            for node in _find(tree, blk):
                if not g_err:
                    g_err = _first_arg(node['children'], 'error_log')
                if not g_acc:
                    g_acc = _first_arg(node['children'], 'access_log')
        data['global_error_log'] = g_err
        data['global_access_log'] = g_acc
        ups = []
        _walk_upstreams(tree, ups)
        data['upstreams'] = ups
        srvs = []
        _walk_servers(tree, srvs)
        data['servers'] = srvs
    except Exception as e:
        data['error'] = 'parse_error: %s' % e
    print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))


if __name__ == '__main__':
    main()
