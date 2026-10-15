# -*- coding: utf-8 -*-
"""运维分析——Jenkins job config.xml 只读解析（服务关联发现用）。

红线：全程只读，仅读取 /var/lib/jenkins/jobs/*/config.xml，绝不触发构建/改配置。
从每个 job 的 config.xml 里尽力提取：
  - job 名（目录名）
  - git 项目地址（scm 里的 <url>xxx.git</url>）
  - 部署目标 IP（全文正则抓 IPv4，作为候选）
  - command / execCommand 文本里的 supervisor 程序名与端口
输出单行 JSON，供 Django 侧按 ip:port / job 名关联。

兼容 Python 2.7 / 3.x。用法:
    python discover_jenkins.py [--jobs-dir /var/lib/jenkins/jobs]
作者: AUTO-GENERATED (opsanalysis module)
"""
from __future__ import print_function

import json
import os
import re
import sys

DEFAULT_JOBS_DIR = '/var/lib/jenkins/jobs'
MAX_JOBS = 2000

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
GIT_RE = re.compile(r'<url>\s*([^<]+?\.git)\s*</url>', re.IGNORECASE)
GIT_RE2 = re.compile(r'(?:git@|https?://)[^\s<"\']+?\.git', re.IGNORECASE)
CMD_BLOCK_RE = re.compile(r'<(?:command|execCommand)>(.*?)</(?:command|execCommand)>',
                          re.IGNORECASE | re.DOTALL)
SUP_PROG_RE = re.compile(r'supervisorctl\s+(?:restart|start|stop|reload)\s+([A-Za-z0-9_.\-]+)')
PROG_SEC_RE = re.compile(r'\[program:([A-Za-z0-9_.\-]+)\]')
PORT_RE = re.compile(r'(?:--http\s*:?|0\.0\.0\.0:|127\.0\.0\.1:|:)(\d{2,5})\b')

# <assignedNode> 是 Jenkins 构建节点标签（可能是节点名或调度用的 IP），
# 不是"部署目标"，必须整块剔除后再抓 IP，避免把 192.168.2.188 这类误收。
ASSIGNED_NODE_RE = re.compile(r'<assignedNode>.*?</assignedNode>',
                              re.IGNORECASE | re.DOTALL)
# 部署目标通常在参数化构建的 <values><string>IP</string>...</values> 里，
# 优先只认 <string> 标签内的 IP，最可靠。
STRING_TAG_RE = re.compile(r'<string>\s*([^<]+?)\s*</string>', re.IGNORECASE)

# 明显不是"部署目标"的 IP（本机/回环/组播等）——仅作降噪，不做强判断
_IP_DENY_PREFIX = ('127.', '0.', '255.', '224.', '239.')


def _git_short_name(url):
    """从 git 地址取仓库短名：https://gitlab.com/root/h3_board.git -> h3_board；
    git@gitlab.com:root/h3_board.git -> h3_board。取不到返回空串。"""
    if not url:
        return ''
    s = url.strip().rstrip('/')
    if s.lower().endswith('.git'):
        s = s[:-4]
    # 统一分隔符后取最后一段
    s = s.replace('\\', '/')
    seg = s.rsplit('/', 1)[-1]
    seg = seg.rsplit(':', 1)[-1]
    seg = seg.strip()
    # 短名应是简单标识，含空白/尖括号说明抓错了
    if not seg or re.search(r'[\s<>"\']', seg):
        return ''
    return seg


def _args(argv):
    jobs_dir = DEFAULT_JOBS_DIR
    i = 0
    while i < len(argv):
        if argv[i] == '--jobs-dir' and i + 1 < len(argv):
            jobs_dir = argv[i + 1]; i += 2; continue
        i += 1
    return jobs_dir


def _unescape(s):
    return (s.replace('&lt;', '<').replace('&gt;', '>')
             .replace('&quot;', '"').replace('&apos;', "'").replace('&amp;', '&'))


def _valid_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if n < 0 or n > 255:
            return False
    if ip.startswith(_IP_DENY_PREFIX):
        return False
    return True


def _extract(text):
    # 先剔除 <assignedNode> 块（构建节点标签，非部署目标），避免误收其 IP
    masked = ASSIGNED_NODE_RE.sub(' ', text)

    # 部署 IP：优先只认 <string> 标签内的 IP（参数化构建的目标列表最可靠）
    ips = []
    for m in STRING_TAG_RE.finditer(masked):
        ip = _unescape(m.group(1)).strip()
        if _valid_ip(ip) and ip not in ips:
            ips.append(ip)
    # 回退：<string> 里一个都没抓到时，再从全文抓（此时 assignedNode 已剔除）
    if not ips:
        for m in IP_RE.finditer(masked):
            ip = m.group(0)
            if _valid_ip(ip) and ip not in ips:
                ips.append(ip)

    gits = []
    git_names = []
    for rx in (GIT_RE, GIT_RE2):
        for m in rx.finditer(masked):
            g = m.group(1) if rx is GIT_RE else m.group(0)
            g = _unescape(g).strip()
            if g and g not in gits:
                gits.append(g)
                short = _git_short_name(g)
                if short and short not in git_names:
                    git_names.append(short)
    commands = []
    sup_progs = []
    ports = []
    for m in CMD_BLOCK_RE.finditer(masked):
        cmd = _unescape(m.group(1)).strip()
        if cmd:
            commands.append(cmd[:500])
        for pm in SUP_PROG_RE.finditer(cmd):
            if pm.group(1) not in sup_progs:
                sup_progs.append(pm.group(1))
        for pm in PROG_SEC_RE.finditer(cmd):
            if pm.group(1) not in sup_progs:
                sup_progs.append(pm.group(1))
        for pm in PORT_RE.finditer(cmd):
            try:
                p = int(pm.group(1))
            except (ValueError, TypeError):
                continue
            if 1 <= p <= 65535 and p not in ports:
                ports.append(p)
    return {
        'deploy_ips': ips[:20],
        'git_urls': gits[:10],
        'git_names': git_names[:10],
        'supervisor_programs': sup_progs[:20],
        'ports': ports[:20],
        'commands': commands[:10],
    }


def main():
    jobs_dir = _args(sys.argv[1:])
    data = {'jobs_dir': jobs_dir, 'jobs': [], 'error': ''}
    try:
        if not os.path.isdir(jobs_dir):
            data['error'] = 'jobs 目录不存在: %s' % jobs_dir
            print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))
            return
        names = sorted(os.listdir(jobs_dir))
        count = 0
        for name in names:
            if count >= MAX_JOBS:
                break
            cfg = os.path.join(jobs_dir, name, 'config.xml')
            if not os.path.isfile(cfg):
                continue
            try:
                with open(cfg) as f:
                    text = f.read()
            except Exception:
                continue
            info = _extract(text)
            info['job_name'] = name
            data['jobs'].append(info)
            count += 1
    except Exception as e:
        data['error'] = 'walk_error: %s' % e
    print(json.dumps({'ok': True, 'data': data}, ensure_ascii=False))


if __name__ == '__main__':
    main()
