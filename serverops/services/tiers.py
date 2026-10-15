"""命令判级：把用户输入的一条命令判成 L1 只读 / L2 变更 / L3 危险。

先把定位说清楚，免得后来人误读：这【不是安全边界】，是"要不要多问一句"的
交互边界。本模块允许执行危险命令——隔离内网的生产机上，删文件、停服务、重启
机器本来就是日常运维；一个删不了东西的工具只会逼人回到手敲 SSH，那样连留痕都没有。

真正的控制是另外四条（都在 views.py / runner.py 里）：
  ① L2/L3 仅管理员可提交；
  ② L2/L3 必填执行原因，L3 提交前还要在弹窗里再确认一次；
  ③ 逐台结果 + 控制机执行留痕（sysmanage.ExecLog）全程可查；
  ④ 提交前回显【实际下发的完整命令串】和【全量主机清单】，不让用户在
     "我以为我只跑了一台"的错觉下点确定。

所以判级唯一必须守住的性质是【失败方向朝上】：认不出的命令一律 ≥L2，
带任何重定向/二次解释执行的一律 ≥L2，命中危险模式的一律 L3。宁可多问一句，
也绝不能把 `rm -rf` 判成只读然后让人一键跑掉。反过来，把一条只读命令误判成
L3 的代价只是多填一句原因、多点一次确认——这个不对称是有意为之。

两个正则写法上的约定，改这个文件时别破坏：
  - 多词模式（systemctl/service/supervisorctl 的子命令）里的填充词必须用
    `[^\\s|;&]+` 而不是 `\\S+`，否则 `systemctl list-units | grep stopped`
    会跨过管道把 grep 的参数也算进来，误判成"停止服务"。
  - 判级顺序固定为：危险 → 写类 → 逃逸 → 只读白名单，前三步都对整条原文扫描
    （不是只看每段开头），因为 `find / -name x -exec rm {} \\;` 的危险动作在参数里。
"""
import re

# 判级结果的中文标签（页面直接显示，不再各自翻译一遍）
TIER_LABEL = {'L1': '只读', 'L2': '变更', 'L3': '危险'}
TIER_HELP = {
    'L1': '只读命令，登录用户即可执行',
    'L2': '会改变系统状态：仅管理员可执行，必须填写原因',
    'L3': '可能造成数据丢失或服务中断：仅管理员可执行，必须填写原因并二次确认',
}

# 命令里的"一个词"：不含空白与 ; & |，用于阻止多词模式跨段匹配
_W = r'[^\s|;&]+'


def _c(pattern):
    return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------- L3 危险模式
# 命中任意一条即 L3。标签会原样显示在页面上，故写人话、点明后果。
_DANGER = [
    # --- 删除 / 擦除 ---
    (_c(r'\brm\s+-[a-zA-Z]*[rf]'), 'rm 带 -r/-f：递归或强制删除'),
    (_c(r'\brm\b'), 'rm 删除文件'),
    (_c(r'\brmdir\b'), 'rmdir 删除目录'),
    (_c(r'\bdel\b'), 'del 删除文件'),
    (_c(r'(?<![\w-])rd\s+/'), 'rd /s 删除目录'),
    (_c(r'\berase\b'), 'erase 删除文件'),
    (_c(r'\bremove-(?!host\b)[a-z]+'), 'PowerShell Remove-* 删除类动词'),
    (_c(r'\bshred\b'), 'shred 不可恢复擦除'),
    # --- 磁盘 / 分区 ---
    # `Format-Table/List/Wide/Custom/Hex/Xml` 是 PowerShell 的输出格式化 cmdlet，
    # 只读；`format C:`、`Format-Volume`、`Format-Partition` 才是真格式化。
    # 速查表里几乎每条 Windows 只读命令都带 Format-Table，不排掉就等于把整栏
    # 只读命令判成危险级——那时用户会直接绕过这个模块去手敲 SSH。
    (_c(r'\bmkfs(?:\.\w+)?\b|\bfdisk\b|\bparted\b|\bdiskpart\b'
        r'|\bformat\b(?!\s*-(?:table|list|wide|custom|hex|xml)\b)'),
     '格式化 / 重新分区'),
    (_c(r'\bdd\s+if=|>>?\s*/dev/(?:sd|hd|vd|nvme|xvd)'), 'dd / 重定向裸写块设备'),
    (_c(r'\bchkdsk\b[^|;\n]*?/(?:f|r|b|x)\b'),
     'chkdsk /f 会置脏位，下次重启强制检查系统盘'),
    (_c(r'\bvirsh\s+(?:destroy|undefine|vol-delete)\b'), '销毁虚拟机 / 删除存储卷'),
    # --- 中断 ---
    (_c(r'\b(?:shutdown|reboot|poweroff|halt)\b|\binit\s+[06]\b'),
     '关机 / 重启（业务会中断）'),
    (_c(r'\b(?:stop|restart)-computer\b'), 'PowerShell 关机 / 重启'),
    (_c(r'\bsystemctl\s+(?:%s\s+){0,4}?(?:stop|disable|mask|kill|reset-failed)\b' % _W),
     'systemctl 停止 / 禁用服务'),
    (_c(r'\bservice\s+%s\s+stop\b' % _W), 'service 停止服务'),
    (_c(r'\bsupervisorctl\s+(?:stop|shutdown|remove|clear)\b'),
     'supervisorctl 停止 / 移除程序'),
    (_c(r'\bstop-(?:service|process|transcript)\b'), 'PowerShell 停止服务 / 进程'),
    (_c(r'\b(?:kill|killall|pkill|taskkill)\b|\bterminate-process\b'), '结束进程'),
    (_c(r'\bsc\s+(?:delete|stop|config|create)\b'), 'sc 删除 / 停止 / 改配置 Windows 服务'),
    (_c(r'\bnet\s+(?:stop|start)\b'), 'net stop/start 停启 Windows 服务'),
    (_c(r'\bopenfiles\s+/disconnect\b'), '断开远端打开的文件句柄'),
    # --- 日志 / 痕迹（本平台把"日志被清除"当事故信号，见下方 _LOG_CLEARING） ---
    (_c(r'\bwevtutil\s+cl\b|\bclear-(?:eventlog|content|item|recyclebin)\b'
        r'|\bremove-eventlog\b|\blimit-eventlog\b'), '清除事件日志'),
    (_c(r'\btruncate\s+-s\s*0\b|:\s*>\s*\S|>>?\s*/var/log/\S'), '清空文件内容'),
    (_c(r'\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bexport\s+HISTFILE=/dev/null\b'
        r'|\bset\s+\+o\s+history\b'), '清除 shell 历史（会抹掉操作痕迹）'),
    # --- 数据 ---
    (_c(r'\bdrop\s+(?:database|table|schema)\b|\btruncate\s+table\b'), '删库 / 删表 / 清表'),
    (_c(r'\bcrontab\s+-r\b'), 'crontab -r 清空全部计划任务'),
    (_c(r'\buserdel\b|\bgroupdel\b|\bremove-(?:ad|local)(?:user|group)\b|\bdsrm\b'
        r'|\bnet\s+(?:user|localgroup|share|session)\b[^|;\n]*?/(?:add|delete|del)\b'),
     '删除账号 / 组 / 共享'),
    (_c(r'\breg\s+delete\b|\bremove-itemproperty\b'), '删除注册表项'),
    (_c(r'\biptables\s+-F\b|\bnft\s+flush\b|\bfirewall-cmd\s+--remove'
        r'|\bnetsh\s+advfirewall\s+set\s+%s\s+state\s+off\b' % _W),
     '清空 / 关闭防火墙规则'),
    (_c(r'\bchmod\s+(?:-R\s+)?(?:777|666|000)\b|\bchown\s+-R\b|\bicacls\b[^|;\n]*?/reset'),
     '批量放开权限 / 递归改属主'),
    (_c(r'\bset-executionpolicy\b|\bset-acl\b'), '改 PowerShell 执行策略 / ACL'),
    # --- 可以藏任意命令的构造 ---
    (_c(r'\beval\b|\biex\b|\binvoke-expression\b'), '二次解释执行：可藏任意命令'),
    (_c(r'\b(?:bash|sh|zsh|ksh|python[23]?|perl|ruby|node|php|powershell|pwsh)\s'
        r'+-(?:c|e|enc|encodedcommand)\b'), '解释器内联代码 / 编码命令：可藏任意命令'),
    (_c(r'\bxargs\b'), 'xargs 把输出变成命令执行'),
    (_c(r'\bfind\b[^|;\n]*?-(?:delete|exec|execdir|ok|okdir)\b'), 'find -delete / -exec'),
]

# 大小写敏感的一小撮（【不能】用 _c 编译，_c 带 IGNORECASE）。
# 防火墙命令的开关全是单字母且大小写区分语义：`iptables -L` 列规则是只读，
# `-F` 清空、`-A` 追加、`-P` 改默认策略都是变更，而 `-N`/`-n` 在 IGNORECASE 下
# 根本分不开。误加一条 DROP 规则或改默认策略，能把自己远程锁在生产机外面，
# 所以这类一律按 L3 处理（与上面已有的 `iptables -F` 同级）。
_DANGER_CS = [
    (re.compile(r'\bip6?tables\b[^|;\n]*?\s-(?:A|D|I|R|F|X|N|P|Z)\b'),
     'iptables 规则变更（可能切断远程访问）'),
    (re.compile(r'\bip6?tables-restore\b'), 'iptables-restore 整体覆盖规则'),
    (re.compile(r'\bnft\b[^|;\n]*?\b(?:add|delete|insert|replace|flush)\b'),
     'nftables 规则变更'),
    (re.compile(r'\bfirewall-cmd\b[^|;\n]*?--(?:add|remove|delete|set-|reload|panic-on)'),
     'firewalld 规则变更'),
]

# ---------------------------------------------------------------- L2 写类模式
# 命中即至少 L2（若同时命中 L3 则按 L3）。这些是"确定会改状态、但不至于毁数据"。
_WRITE = [
    (_c(r'\bmv\b|\bmove-item\b|\brename-item\b|\brename\b'), '移动 / 重命名（源文件会消失）'),
    (_c(r'\bcp\b|\bcopy-item\b|\bcopy\b|\bxcopy\b|\brobocopy\b'), '复制文件'),
    (_c(r'\bmkdir\b|\bmd\s|\btouch\b|\bnew-item\b|\bni\s+-|\bmktemp\b'), '新建文件 / 目录'),
    (_c(r'\bsed\s+-i\b|\bset-content\b|\badd-content\b|\bout-file\b|\btee\b'
        r'|\b(?:ac|sc)\s+-'), '写入文件内容'),
    (_c(r'\bwrite-eventlog\b'), '写入事件日志'),
    (_c(r'\bwevtutil\s+(?:sl|set-log|im|install|un|uninstall)\b'), '改事件日志通道配置'),
    # 两个 %s 共用一次 % 运算：相邻字符串字面量先拼成一整条，再做替换。
    # 写成 r'..%s..' % _W r'..%s..' 是语法错误（第一处 % 之后紧跟字面量）。
    (_c(r'\bsystemctl\s+(?:%s\s+){0,4}?(?:start|restart|reload|enable|daemon-reload)\b'
        r'|\bservice\s+%s\s+(?:start|restart|reload)\b'
        r'|\b(?:start|restart)-service\b' % (_W, _W)), '启动 / 重启 / 重载服务'),
    (_c(r'\bsupervisorctl\s+(?:start|restart|reload|reread|update)\b'), 'supervisor 变更'),
    (_c(r'\bnginx\s+-s\b|\bapachectl\s+(?:restart|graceful|stop|start)\b'),
     'Web 服务重载 / 停启'),
    (_c(r'\b(?:yum|dnf|apt|apt-get|zypper)\s+(?:install|remove|erase|update|upgrade'
        r'|downgrade|autoremove|clean)\b'
        r'|\brpm\s+-[iUeF]\b|\bdpkg\s+-[irP]\b'
        r'|\bpip[23]?\s+(?:install|uninstall|download)\b'
        r'|\bnpm\s+(?:i|install|uninstall|ci|update|rm)\b'), '安装 / 卸载软件包'),
    (_c(r'\bchown\b|\bchmod\b|\bchgrp\b|\btakeown\b'), '改权限 / 属主'),
    (_c(r'\bpasswd\b|\buseradd\b|\bgroupadd\b|\bnew-localuser\b|\badd-localgroupmember\b'
        r'|\bnet\s+(?:user|localgroup)\s+\S'), '账号 / 密码变更'),
    (_c(r'\bcrontab\s+(?!-l\b)|\bschtasks\s+/(?:create|change|delete|run|end)\b'
        r'|\b(?:register|unregister|set)-scheduledtask\b'), '计划任务变更'),
    (_c(r'\bsysctl\s+-w\b|\bset-service\b|\bnew-service\b|\bset-itemproperty\b'
        r'|\breg\s+(?:add|import|load|unload|restore)\b|\bsetx\b'),
     '改系统参数 / 注册表 / 环境变量'),
    (_c(r'\bgit\s+(?:pull|push|checkout|reset|merge|rebase|clean|stash)\b'), 'git 变更工作区'),
    (_c(r'\bmount\s+-|\bumount\b|\bmountvol\b|\bnet\s+use\b'), '挂载变更'),
    (_c(r'\bip\s+(?:addr|route|link|neigh)\s+(?:add|del|change|replace|set|flush)\b'
        r'|\bifconfig\s+%s\s+(?:up|down)\b|\bnetsh\b|\bnmcli\b' % _W), '网络配置变更'),
    (_c(r'\bstart-process\b|\bnohup\b|\bat\s+\d'), '启动后台进程'),
    (_c(r'\bdism\b[^|;\n]*?/(?:enable-feature|disable-feature|add-package'
        r'|remove-package|cleanup-image|apply-image|capture-image)\b'), 'DISM 变更系统映像'),
    (_c(r'\bsfc\s+/scannow\b|\bfsutil\s+(?:behavior\s+set|file\s+setzero)\b'
        r'|\bcipher\s+/w'), '系统文件修复 / 擦除空闲空间'),
    (_c(r'\bset-[a-z]+|\bnew-[a-z]+|\badd-[a-z]+|\bupdate-[a-z]+|\binstall-[a-z]+'
        r'|\buninstall-[a-z]+|\bdisable-[a-z]+|\benable-[a-z]+|\bstart-[a-z]+'
        r'|\brestart-[a-z]+|\breset-[a-z]+|\bexport-[a-z]+|\bimport-[a-z]+'
        r'|\binvoke-[a-z]+|\bregister-[a-z]+|\bunregister-[a-z]+|\bgrant-[a-z]+'
        r'|\brevoke-[a-z]+|\bsend-[a-z]+|\bpush-[a-z]+|\bblock-[a-z]+|\bunblock-[a-z]+'),
     'PowerShell 写类动词（Set/New/Add/Update/Invoke/...）'),
]

# ---------------------------------------------------------------- 逃逸构造
# 只读命令一旦带上这些，就可能把任意写操作藏进去，故一律 ≥L2。
_ESCAPE = [
    # `2>&1`、`>/dev/null`、`> $null` 是无害的惯用写法，必须放过；其余重定向都会落地成文件
    (_c(r'>>?\s*(?!&|/dev/null\b|\$null\b)\S'), '重定向到文件'),
    (_c(r'`'), '反引号（命令替换 / 续行）'),
    (_c(r'\$\('), '$() 命令替换'),
    (_c(r'\b(?:sudo|su|doas|runas)\b'), '提权执行'),
]

# 清日志 / 抹痕迹类命令的额外提示。本平台把"事件日志被清除"(事件 ID 104) 当作
# 事故信号，运维分析的 OS 日志证据也全靠这些日志。在这儿清掉，等于把分析层的
# 眼睛蒙上——这个后果必须在下手【之前】告诉用户，而不是事后在报告里发现少了一段。
_LOG_CLEARING = _c(
    r'\bwevtutil\s+cl\b|\bclear-eventlog\b|\bremove-eventlog\b|\blimit-eventlog\b'
    r'|\bclear-(?:content|item)\b|\btruncate\s+-s\s*0\b|:\s*>\s*\S'
    r'|>>?\s*/var/log/\S|\bhistory\s+-c\b|\bunset\s+HISTFILE\b'
    r'|\bexport\s+HISTFILE=/dev/null\b|\bset\s+\+o\s+history\b'
    r'|\brm\b[^|;\n]*?/var/log/')

# ---------------------------------------------------------------- L1 只读白名单
# 段的第一个词命中此表，且整条命令没被上面三张表命中，才判 L1。
# 白名单刻意保守：curl/wget 能上传、mysql/psql 能写库、python/docker/kubectl 能
# 执行任意代码——统统不放进来，让它们落到 L2 去多问一句。
# 带"只读子命令 / 写类子命令"之分的（systemctl、net、sc、reg、schtasks、ip、
# mount、nginx、crontab、dism、wmic 等）之所以敢放进来，是因为它们的写类形态
# 已经被 _DANGER / _WRITE / _AMBIGUOUS_WRITE 三张表逐一拦下了。
_READONLY_HEADS = {
    # 文件 / 文本读取
    'ls', 'll', 'la', 'dir', 'pwd', 'cat', 'zcat', 'xzcat', 'bzcat', 'tac',
    'less', 'more', 'most', 'head', 'tail', 'wc', 'grep', 'egrep', 'fgrep',
    'zgrep', 'rg', 'sort', 'uniq', 'cut', 'tr', 'column', 'nl', 'od', 'xxd',
    'strings', 'awk', 'gawk', 'sed', 'jq', 'yq', 'file', 'stat', 'tree',
    'find', 'locate', 'which', 'whereis', 'type', 'command', 'realpath',
    'readlink', 'basename', 'dirname', 'md5sum', 'sha1sum', 'sha256sum',
    'cksum', 'echo', 'printf', 'true', 'false', 'test', '[', 'diff', 'cmp',
    'tailf',
    # 资源 / 进程
    'ps', 'pstree', 'pgrep', 'pidof', 'top', 'htop', 'uptime', 'free', 'du',
    'df', 'vmstat', 'iostat', 'mpstat', 'sar', 'pidstat', 'nload', 'iftop',
    'nethogs', 'lsof', 'nproc', 'arch', 'uname', 'hostname', 'hostnamectl',
    'lscpu', 'lsmem', 'lspci', 'lsusb', 'lsmod', 'lsblk', 'blkid', 'mount',
    # 会话 / 身份 / 时间
    'whoami', 'id', 'groups', 'who', 'w', 'last', 'lastlog', 'date', 'cal',
    'env', 'printenv', 'getent', 'timedatectl', 'chronyc', 'ntpstat',
    # 网络只读
    'netstat', 'ss', 'ip', 'ifconfig', 'arp', 'route', 'ethtool', 'iwconfig',
    'ping', 'ping6', 'fping', 'traceroute', 'tracepath', 'mtr', 'dig',
    'nslookup', 'host', 'getcap',
    # 防火墙只读查询（写类形态由 _DANGER_CS / _AMBIGUOUS_WRITE 逐一拦下）
    'iptables', 'ip6tables', 'nft', 'firewall-cmd', 'iptables-save',
    # 日志
    'journalctl', 'dmesg', 'get-winevent', 'wevtutil', 'fltmc', 'gpresult',
    # 包 / 服务查询
    'systemctl', 'service', 'chkconfig', 'supervisorctl', 'rpm', 'dpkg',
    'yum', 'dnf', 'apt', 'apt-get', 'pip', 'pip3', 'nginx', 'apachectl',
    'crontab', 'systemd-analyze', 'timeout', 'docker',
    # Windows 原生命令（cmd.exe 下也能跑的只读项）
    'systeminfo', 'tasklist', 'ipconfig', 'tracert', 'pathping', 'where',
    'ver', 'set', 'query', 'sc', 'net', 'powercfg', 'wmic', 'sigcheck',
    'chkdsk', 'sfc', 'dism', 'reg', 'cmdkey', 'schtasks', 'driverquery',
    'openfiles', 'time', 'fsutil', 'bcdedit', 'nltest', 'dsquery', 'klist',
    'cipher', 'getmac', 'logman', 'typeperf', 'winsat',
}

# PowerShell 只读动词：Get-/Select-/Where- 这类不落地、不改状态。
# Out-File / Write-EventLog 确实在写，但判级顺序保证 _WRITE 先扫到它们，
# 轮不到这里放行。
_READONLY_PS_VERBS = {
    'get', 'show', 'test', 'measure', 'select', 'where', 'sort', 'group',
    'format', 'compare', 'convertto', 'convertfrom', 'resolve', 'split',
    'join', 'wait', 'read', 'out', 'write', 'count', 'trace', 'find',
}

# PowerShell 只读别名（不是 Verb-Noun 形态，要单列）
_PS_READONLY_ALIAS = {
    'gc', 'gci', 'gsv', 'gps', 'gcm', 'gm', 'ft', 'fl', 'fw', 'fhx', 'gl',
    'gi', 'gv', 'sls', 'iwr', 'irm', 'cls', 'cd', 'man', 'help', 'history',
    'cat', 'ls', 'dir', 'type', 'echo', 'where', 'select', 'sort', 'measure',
    'compare', 'more', 'pwd',
}

# 白名单里的"多面手"命令：本身只读，但某些参数会改状态。整条原文再过一遍这张表，
# 命中就升到 L2。放在这里而不是 _WRITE 里，是因为它们只有【带特定参数】时才是写。
_AMBIGUOUS_WRITE = _c(
    r'\bwmic\b[^|;\n]*?\bcall\b'
    r'|\breg\s+(?:add|delete|import|load|unload|restore)\b'
    r'|\bschtasks\s+/(?:create|change|delete|run|end)\b'
    r'|\bfsutil\s+(?:behavior\s+set|file\s+setzero|usn\s+deletejournal)\b'
    r'|\bbcdedit\s+/?(?:set|delete|deletevalue|import|copy)\b'
    r'|\bpowercfg\s+/(?:change|setacvalueindex|setdcvalueindex|hibernate)\b'
    r'|\bnet\s+share\b[^|;\n]*?/(?:add|delete|del)\b'
    r'|\bdocker\s+(?:rm|rmi|kill|stop|restart|prune|exec|run|pull|push|update)\b'
    r'|\bip\s+(?:addr|route|link|neigh)\s+(?:add|del|change|replace|set|flush)\b'
    r'|\bmount\s+-|\bumount\b'
)


# ------------------------------------------------------------------ 内部工具

def _head_of(segment):
    """取一个命令段的首词（小写、去掉路径与转义）。

    跳过前导的环境变量赋值和 timeout 包裹：`LANG=C ps aux`、`timeout 5 systemctl
    status x` 的真实首词是后面那个。认不出就返回原样，交给白名单去判——
    判不过即 ≥L2，这就是"失败方向朝上"的落点。
    """
    toks = segment.strip().split()
    i = 0
    while i < len(toks):
        t = toks[i].lstrip('\\').strip('({')
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', t):            # FOO=bar
            i += 1
            continue
        if t.lower() == 'timeout' and i + 1 < len(toks):        # timeout 5 cmd
            i += 2
            continue
        base = t.rsplit('/', 1)[-1].rsplit('\\', 1)[-1].lower()
        if base.endswith('.exe'):
            base = base[:-4]
        return base
    return ''


def _is_readonly_head(head):
    if not head:
        return False
    if head in _READONLY_HEADS or head in _PS_READONLY_ALIAS:
        return True
    if '-' in head:                                             # Verb-Noun
        return head.split('-', 1)[0] in _READONLY_PS_VERBS
    return False


def split_segments(command):
    """按 ; & | 换行 拆段，但【尊重引号与括号嵌套】。返回非空段列表。

    为什么要尊重：PowerShell 的计算属性 `@{n='MB';e={...}}`、FilterHashtable
    `@{LogName='System';Level=1,2}` 里都有分号，`grep ':80|:443'` 的引号里有竖线。
    按裸字符拆会把这些完整的一段切碎，碎出来的"段"首词认不出 → 整条被误判成
    变更级，运维点个只读速查命令还要走管理员确认，很快就会不再用这个模块。

    拆段方式再糟也不会漏判危险命令：危险/写类/逃逸三张表都是对【整条原文】
    扫描的，拆段只影响 L1 只读白名单的判定。也就是说这里的 bug 只会造成
    误升（L1→L2），不会造成误降——正是本模块要求的失败方向。
    """
    text = command or ''
    out, buf = [], []
    quote = ''       # 当前所处引号：' " `
    depth = 0        # ()/[]/{} 嵌套深度
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == '\\' and quote == '"' and i + 1 < n:
                i += 1
                buf.append(text[i])
            elif ch == quote:
                quote = ''
            i += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
        elif ch in '({[':
            depth += 1
        elif ch in ')}]':
            depth = max(0, depth - 1)
        elif depth == 0 and ch in ';&|\n':
            # `2>&1` 里的 `&` 是文件描述符重定向，不是命令分隔符。按分隔符切会把
            # 后面的 `1` 切成独立段，首词认不出 → 只读命令被误升成变更级。
            if ch == '&' and buf and buf[-1] == '>':
                pass
            else:
                seg = ''.join(buf).strip()
                if seg:
                    out.append(seg)
                buf = []
                i += 1
                continue
        buf.append(ch)
        i += 1
    seg = ''.join(buf).strip()
    if seg:
        out.append(seg)
    return [s for s in out if s.strip('&')]


# ------------------------------------------------------------------ 主入口

def classify(command, targets=None, os_type='', mode=''):
    """判级。返回 dict：

        tier          'L1' / 'L2' / 'L3'（命令为空时为 ''）
        label         中文标签
        help          这一级意味着什么（页面提示语）
        needs_admin   是否仅管理员可执行
        needs_reason  是否必填原因
        matched       [{'tier','label'}] 命中的模式，按严重度排序，即"判级依据"
        segments      [{'text','head','readonly'}] 逐段判定明细
        unknown       无法识别为只读的首词列表
        log_clearing  是否含清除日志 / 抹痕迹的动作
        warnings      附加提示语列表
    """
    text = (command or '').strip()
    targets = list(targets or [])
    if not text:
        return {
            'tier': '', 'label': '', 'help': '请输入命令后自动判级',
            'needs_admin': False, 'needs_reason': False,
            'matched': [], 'segments': [], 'unknown': [],
            'log_clearing': False, 'warnings': [], 'empty': True,
        }

    matched = []

    def _scan(table, tier):
        for rx, label in table:
            if rx.search(text):
                matched.append({'tier': tier, 'label': label})

    # 顺序即优先级：L3 → L2 写类 → 逃逸构造 → 多面手参数
    _scan(_DANGER, 'L3')
    _scan(_DANGER_CS, 'L3')
    _scan(_WRITE, 'L2')
    _scan(_ESCAPE, 'L2')
    if _AMBIGUOUS_WRITE.search(text):
        matched.append({'tier': 'L2', 'label': '只读命令带了会改状态的参数'})

    segments = []
    unknown = []
    for seg in split_segments(text):
        head = _head_of(seg)
        ro = _is_readonly_head(head)
        segments.append({'text': seg[:200], 'head': head, 'readonly': ro})
        if not ro:
            unknown.append(head or seg[:30])

    log_clearing = bool(_LOG_CLEARING.search(text))

    if any(m['tier'] == 'L3' for m in matched):
        tier = 'L3'
    elif matched or unknown:
        tier = 'L2'
    else:
        tier = 'L1'

    warnings = []
    if unknown and tier == 'L2':
        warnings.append('以下部分无法识别为只读命令，已按「变更」处理：%s'
                        % '、'.join(sorted(set(unknown))[:8]))
    if log_clearing:
        warnings.append(
            '这条命令会清除日志或操作痕迹。本平台的运维分析把「事件日志被清除」'
            '(事件 ID 104) 当作事故信号，OS 日志证据也全靠这些日志——清完之后，'
            '分析页面上对应时段会出现一段无法解释的证据缺失。')
    if tier == 'L3' and not log_clearing:
        warnings.append('不可逆或有中断风险。建议先在「灰度主机」里勾一台试跑，'
                        '确认无误再全量下发。')
    if len(targets) > 5 and tier != 'L1':
        warnings.append('本次将影响 %d 台机器。命令是一次性批量下发的，'
                        '中途没有逐台确认的机会。' % len(targets))
    if mode == 'win_cmd':
        warnings.append('CMD 模式：命令原文直送目标机 cmd.exe，管道与引号按 CMD 规则'
                        '解析，和 PowerShell 语义不同（PowerShell cmdlet 在这里跑不了）。')
    elif mode == 'powershell':
        warnings.append('PowerShell 模式：命令会被编码成 -EncodedCommand 下发，'
                        '因此支持管道、引号与中文，不受 cmd.exe 转义规则影响。')

    needs_admin = tier in ('L2', 'L3')
    matched.sort(key=lambda m: 0 if m['tier'] == 'L3' else 1)

    return {
        'tier': tier,
        'label': TIER_LABEL.get(tier, ''),
        'help': TIER_HELP.get(tier, ''),
        'needs_admin': needs_admin,
        'needs_reason': needs_admin,
        'matched': matched,
        'segments': segments,
        'unknown': sorted(set(unknown)),
        'log_clearing': log_clearing,
        'warnings': warnings,
        'empty': False,
    }
