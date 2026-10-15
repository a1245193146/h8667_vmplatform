"""常用命令速查：点一下就填进命令框。

为什么要有这个：本模块的需求原话是"我记不住所有运维命令"。大模型问答能解决
"我想干某件事但不知道命令"，可解决不了"我知道命令、只是记不清参数顺序"——
后者查一次模型要等十几秒，而点一下按钮是零秒。所以两份都给。

选命令的口径：
  - 全部是 L1 只读（判级白名单能认出来），点了就能跑，不触发管理员门槛；
  - 只放"排查时真的会反复用"的，不做大而全的 cheat sheet；
  - Windows 侧一律给 PowerShell 5.1 能跑的语法，不用 pwsh 7 独有的写法；
  - 读事件日志必须带 FilterHashtable + MaxEvents——这条是全平台的性能红线，
    速查里给出的示例本身就该是正确示范，否则用户照抄就会把机器拖死。
"""

LINUX = [
    ('磁盘占用', "df -h"),
    ('哪个目录最占地方', "du -xh --max-depth=1 / 2>/dev/null | sort -rh | head -20"),
    ('内存', "free -m"),
    ('负载 / 运行时长', "uptime"),
    ('按名字找服务', "systemctl list-units --type=service --all | grep -i u8"),
    ('某个服务状态', "systemctl status nginx --no-pager"),
    ('某服务最近日志', "journalctl -u nginx -n 200 --no-pager"),
    ('端口是否在监听', "ss -lntp | grep -E ':80|:443|:8878'"),
    ('占 CPU 前 10 的进程', "ps -eo pid,ppid,user,pcpu,pmem,etime,cmd --sort=-pcpu | head -11"),
    ('占内存前 10 的进程', "ps -eo pid,ppid,user,pcpu,pmem,rss,cmd --sort=-rss | head -11"),
    ('时间同步状态', "timedatectl"),
    ('最近的登录记录', "last -n 20"),
    ('最近的系统报错(近一日)', "journalctl -p err -S -1d --no-pager"),
    ('supervisor 状态', "supervisorctl status"),
    ('nginx 配置语法自检', "nginx -t"),
]

WINDOWS = [
    ('磁盘剩余空间', "Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free"),
    ('内存 / 运行时长', "Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize,LastBootUpTime"),
    ('按名字找服务', "Get-Service | Where-Object {$_.Name -like '*u8*' -or $_.DisplayName -like '*u8*'} | Format-Table -AutoSize"),
    ('所有非运行中的服务', "Get-Service | Where-Object {$_.Status -ne 'Running'} | Format-Table Status,Name,DisplayName -AutoSize"),
    ('端口是否在监听', "Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in 80,443,8878} | Format-Table LocalAddress,LocalPort,OwningProcess -AutoSize"),
    ('占 CPU 前 10 的进程', "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,Id,CPU,WS"),
    ('占内存前 10 的进程', "Get-Process | Sort-Object WS -Descending | Select-Object -First 10 Name,Id,@{n='MB';e={[math]::Round($_.WS/1MB,1)}}"),
    ('近一天系统日志的错误与警告',
     "Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2,3;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 200 "
     "| Select-Object TimeCreated,Id,LevelDisplayName,ProviderName | Format-Table -AutoSize"),
    ('近一天应用程序日志的错误',
     "Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 200 "
     "| Select-Object TimeCreated,Id,ProviderName,Message | Format-List"),
    ('某个事件 ID 的详情',
     "Get-WinEvent -FilterHashtable @{LogName='System';Id=1000;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 20 "
     "| Format-List TimeCreated,Id,Message"),
    ('Defender 状态', "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated"),
    ('Defender 最近检测',
     "Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 "
     "InitialDetectionTime,ThreatID,Resources | Format-List"),
    ('最近的重启记录',
     "Get-WinEvent -FilterHashtable @{LogName='System';Id=1074,6005,6006,6008;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 "
     "| Select-Object TimeCreated,Id,Message | Format-List"),
    ('IIS 站点状态', "Get-Website | Format-Table Name,State,PhysicalPath -AutoSize"),
    ('计划任务失败项', "Get-ScheduledTask | Where-Object {$_.State -ne 'Ready'} | Format-Table TaskName,State -AutoSize"),
    ('本机 IP / 网关', "Get-NetIPConfiguration | Format-List InterfaceAlias,IPv4Address,IPv4DefaultGateway,DNSServer"),
]

# 变更类（L2/L3）示例：只放"确实常做"的，且明确标出等级，点了之后页面会照常
# 走判级与确认流程。放在只读示例下面单独一栏，避免误点。
LINUX_CHANGE = [
    ('重启某服务', "systemctl restart nginx", 'L2'),
    ('清理某目录下 30 天前的日志', "find /var/log/myapp -name '*.log' -mtime +30 -delete", 'L3'),
]

WINDOWS_CHANGE = [
    ('重启某服务', "Restart-Service -Name 'u8app' -Force", 'L2'),
    ('清空某目录下的临时文件', "Remove-Item 'D:\\u8\\temp\\*' -Recurse -Force", 'L3'),
    ('重启这台机器', "Restart-Computer -Force", 'L3'),
]
