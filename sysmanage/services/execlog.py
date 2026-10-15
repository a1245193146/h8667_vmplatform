"""执行留痕收口：所有远程命令都从这里落库。

红线：本模块的任何失败都只记 warning，绝不向上抛。
留痕是"锦上添花"，主流程（采集/分析/处置）不能因为写不了一条日志而失败——
尤其是数据库抖动或表还没 migrate 的时候。

埋点位置只有两处，因为全平台的远程执行都必经它们：
  firewall/services/ansible_executor.py: run_playbook  → kind='playbook'
  opsanalysis/services/sync.py:          ssh_exec      → kind 由命令形态判定
新增执行通道时必须同样接入，否则又会出现"任务没有日志"。
"""
import logging
import re

logger = logging.getLogger(__name__)

# 输出留存策略：留头 + 留尾，中间如实标注省略了多少字符。
# 只留尾会丢掉命令回显的开头（看不出跑的是什么），只留头会丢掉报错
# （ansible 的 fatal 几乎总在最后）。头尾各半是两者的平衡。
STDOUT_KEEP = 8192
STDERR_KEEP = 2048
# 命令原文也可能很长（-e 后面挂着一整坨 JSON），同样需要上限
COMMAND_KEEP = 4000

# `bash -lc 'cd /etc/ansible && ansible-inventory ...'` 这种包裹形态很常见，
# 所以不能用 startswith 判定，得在整条命令里找 ansible 可执行名。
# 但要求它后面紧跟空白：否则 `cat /etc/ansible/hosts` 会因为路径里有个叫
# ansible 的目录被误判成"执行了 ansible 命令"。
_ANSIBLE_RE = re.compile(r'\bansible(?:-[a-z]+)?(?=\s)')
# 探活/只读探测类命令：量最大（自动发现每台机器都要探），单独归类才能和
# 真正的运维命令分开看
_PROBE_RE = re.compile(
    r'\b(ping|ping6|fping|nc|netcat|nmap|traceroute|dig|nslookup|host)\b')


def _clip(text, keep):
    """返回 (留存文本, 原始长度, 是否截断)。截断必须显式声明，不能静默丢。"""
    s = text if isinstance(text, str) else ('' if text is None else str(text))
    n = len(s)
    if n <= keep:
        return s, n, False
    half = keep // 2
    return ('%s\n…[中间省略 %d 字符，完整输出未留存]…\n%s'
            % (s[:half], n - half * 2, s[-half:])), n, True


def classify(cmd):
    """按命令形态判定留痕类型，用于列表筛选。

    这是"分类标签"不是安全边界——判定错了顶多是筛选不便，不影响执行。
    """
    c = (cmd or '').strip()
    if not c:
        return 'shell'
    low = c.lower()
    if 'ansible-playbook' in low:
        return 'playbook'
    if _ANSIBLE_RE.search(low):
        return 'ansible'
    m = _PROBE_RE.search(low)
    if m:
        # 只有"整条命令基本就是探测"才算 probe；`systemctl status nginx | grep ping`
        # 这种不能因为出现了 ping 就被归到探活里去
        head = low.split('&&')[-1].split('|')[0].strip()
        if head.startswith(m.group(1)) or head.startswith('timeout'):
            return 'probe'
    return 'shell'


def guess_module(command='', subdir='', playbook=''):
    """尽力判定来源模块，仅用于日志页按模块筛选。

    playbook 名/命令里的脚本名前缀最可靠（av_* / ops_* 是各模块自己的命名约定）；
    退化到 subdir 关键字；再退化到 firewall（ansible 目录默认归它）。
    这是"分类标签"不是安全边界：判错了顶多筛选不便，不影响执行与鉴权。
    """
    for text in (playbook, command):
        for m in re.finditer(r'\b(av|ops)_[a-z0-9_]+\.(?:yml|yaml|py|ps1)\b',
                             (text or '').lower()):
            return 'antivirus' if m.group(1) == 'av' else 'opsanalysis'
    for text in (subdir, command):
        s = (text or '').lower()
        if 'opsanalysis' in s:
            return 'opsanalysis'
        if 'antivirus' in s:
            return 'antivirus'
    return 'firewall'


def record(command, rc=None, status='success', stdout='', stderr='',
           duration_ms=0, kind='', module='', target='', task_ref='',
           initiated_by='system', note=''):
    """写一条执行留痕。永不抛异常，永不返回需要调用方处理的值。

    command 里可能含控制机账号密码吗？不会：ANSIBLE_CONFIG 的凭据只用于
    paramiko.connect，不进命令行；playbook 的 -e 传的是目标主机/路径等业务参数。
    仍做一次兜底脱敏，防止将来有人把密码塞进 extra_vars。

    脱敏用 long_b64=False：命令输出里的长串字母数字（文件哈希、任务 ID、
    base64 编码的 PowerShell）是留痕的正文，不能被打码掉。详见 redact.redact_text。
    """
    try:
        from sysmanage.models import ExecLog
        from sysmanage.services.redact import redact_text

        def _r(t):
            return redact_text(t, long_b64=False)

        cmd_txt, _n, _t = _clip(_r(command or ''), COMMAND_KEEP)
        out_txt, out_len, out_trunc = _clip(_r(stdout), STDOUT_KEEP)
        err_txt, _e, _et = _clip(_r(stderr), STDERR_KEEP)
        ExecLog.objects.create(
            module=(module or guess_module(command=command))[:32],
            kind=(kind or classify(command))[:16],
            target=(target or '')[:255],
            command=cmd_txt,
            rc=rc,
            status=(status or 'success')[:16],
            stdout=out_txt,
            stderr_tail=err_txt,
            stdout_bytes=out_len,
            truncated=bool(out_trunc),
            duration_ms=int(duration_ms or 0),
            task_ref=(task_ref or '')[:64],
            initiated_by=(initiated_by or 'system')[:100],
            note=(note or '')[:255],
        )
    except Exception as exc:
        # 包括 AppRegistryNotReady（migrate 前）、表不存在、字段超长、DB 抖动
        logger.warning('执行留痕写入失败（忽略，不影响主流程）: %s', exc)


def log_sync(target, uploaded=None, error='', duration_ms=0, module='firewall',
             base=''):
    """SFTP 脚本同步的留痕。

    同步不是一条 shell 命令，但它是"平台往控制机推过哪些文件"的唯一记录——
    出问题时靠它回答"控制机上那个 .ps1 是哪次同步推上去的、当时推了哪几个文件"。
    没有这条留痕，控制机上的脚本改动就是完全的黑箱。
    """
    files = list(uploaded or [])
    ok = not error
    record(
        command='SFTP 同步 %d 个文件到 %s' % (len(files), base or target or '?'),
        rc=0 if ok else None,
        status='success' if ok else 'error',
        stdout='\n'.join(files),
        stderr=error or '',
        duration_ms=duration_ms,
        kind='sync', module=module, target=(target or '')[:255],
        initiated_by='system',
        note='脚本同步' if ok else '脚本同步失败',
    )
    return ok


def purge(keep_days_shell=90, keep_days_probe=7):
    """按类型分档清理留痕，返回各类删除条数。

    分档的理由：probe（ping 探活）量最大、事后价值最低，留一周足够排障；
    playbook/ansible/shell 是真正的运维动作，要留三个月供追溯。
    删除本身也写一条留痕——"我们删了什么"必须可查，否则清理就成了黑箱。
    """
    from datetime import timedelta

    from django.utils import timezone

    from sysmanage.models import ExecLog

    now = timezone.now()
    cut_probe = now - timedelta(days=max(1, int(keep_days_probe)))
    cut_shell = now - timedelta(days=max(1, int(keep_days_shell)))
    deleted = {}
    for kinds, cut, label in (
        (['probe'], cut_probe, 'probe'),
        (['playbook', 'ansible', 'shell', 'sync'], cut_shell, 'other'),
    ):
        qs = ExecLog.objects.filter(kind__in=kinds, created_at__lt=cut)
        n = qs.count()
        if n:
            qs.delete()
        deleted[label] = n
    total = sum(deleted.values())
    if total:
        record(command='[系统] 清理执行留痕：probe 保留 %d 天、其余保留 %d 天'
                       % (keep_days_probe, keep_days_shell),
               rc=0, status='success', kind='sync', module='sysmanage',
               target='ExecLog',
               stdout='已删除 %d 条（probe %d 条，其余 %d 条）'
                      % (total, deleted.get('probe', 0), deleted.get('other', 0)),
               initiated_by='system', note='定期清理')
    return deleted
