<#
.SYNOPSIS
    运维分析——服务器操作影响分析（Windows 只读采集）。
.DESCRIPTION
    红线：全程只读，绝不执行关机/重启/停服务等任何改变系统状态的操作。
    采集：基础状态 / 用户与会话 / 网络连接 / 监听端口 / 服务 / 进程 / Supervisor(Windows)。
    每一段独立 try/catch，任何一段失败都不影响其它段，也绝不抛出中断整次采集。
    输出单行 JSON: {"ok":true,"data":{...}}
    兼容 PowerShell 5.1 (.NET Framework)：不使用会在脏数据上抛异常的 API
    （如 [System.IO.Path]::GetFileName 遇非法字符会抛），列表一律限量避免输出过大。
.PARAMETER MaxConn
    ESTABLISHED 连接明细最多输出条数（默认 200）。
.PARAMETER MaxProc
    进程明细最多输出条数（默认 60，按内存降序）。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Collect-OpsImpact.ps1
.AUTHOR
    AUTO-GENERATED (opsanalysis module)
#>
param(
    [int]$MaxConn = 200,
    [int]$MaxProc = 60,
    [string]$AppLogPath = '',
    [int]$OsLogDays = 1,
    # 单个日志（System/Application）最多取多少条 Warning 及以上事件。
    # Get-WinEvent -MaxEvents 取的是"最近 N 条"，所以到上限时丢掉的是最老的那些，
    # 一旦触顶必须回报（见下方 os_logs.errors），否则"只看到 500 条"会被读成"只有 500 条"。
    [int]$MaxOsLogPerLog = 500,
    # 合并后的总上限。1000 条按每条约 300 字算，JSON 体积可控。
    [int]$MaxOsLogTotal = 1000,
    # 非运行状态服务最多回报多少条（服务总数一般几百，运行中的不设上限）
    [int]$MaxSvcOther = 200
)

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

function Safe-Str { param($v) if ($null -eq $v) { return '' } return [string]$v }

# 从任意命令行/字符串里尽力提取监听端口（runserver 0.0.0.0:80 / uwsgi --http :80 / :5858）
function Get-PortFromText {
    param([string]$Text)
    if (-not $Text) { return $null }
    $m = [regex]::Match($Text, '(?:--http\s*:?|0\.0\.0\.0:|127\.0\.0\.1:|:)(\d{2,5})\b')
    if ($m.Success) {
        $p = [int]$m.Groups[1].Value
        if ($p -ge 1 -and $p -le 65535) { return $p }
    }
    return $null
}

function Get-EventLevelName {
    param([int]$Lv)
    switch ($Lv) {
        0 { return 'Always' }
        1 { return 'Critical' }
        2 { return 'Error' }
        3 { return 'Warning' }
        4 { return 'Information' }
        5 { return 'Verbose' }
        default { return "Level$Lv" }
    }
}

# 读取指定日志（近 N 日）的事件，统一成 {ts,log,id,level,source,kind,message}。
# 性能红线：必须 FilterHashtable + StartTime + MaxEvents 上限，
# 绝不用 Get-WinEvent -LogName X | Where-Object（AV 模块曾因此整机采集超时）。
# 级别策略：默认只取 Level 1/2/3（Critical/Error/Warning），Information(4)/Verbose(5)
# 一律不采集——这两级占了系统日志的绝大多数量且几乎全是噪音，还会把 MaxEvents 名额吃光、
# 挤掉真正有价值的错误。过滤条件写在 FilterHashtable 里由事件日志服务侧完成，
# 不额外遍历事件，MaxEvents 因此全部留给 Warning 及以上的事件。
#
# 采集范围：$Ids 传 $null = 不按事件 ID 过滤，该日志里所有 Warning 及以上事件全采。
# 早先用的是"事件 ID 白名单"（只查 7023/1000/6008 等二十几个 ID），实测会整片漏掉
# 没预料到的错误——用户一天大量报错，结果只采到 1 条 Application/1000。
# 代价是事件种类变杂，故 kind 改由 Get-EventKind 按 ID/provider 归类，认不出的归 other
# （归类不出 ≠ 不重要，绝不丢弃，交给分析层和大模型自己看原文）。
# "没有匹配事件"是正常情况，不计入 errors。
$script:OsLogErrors = @()
$script:OsLogLevels = @(1, 2, 3)

# 事件 ID → kind。只列语义明确的；其余交给 provider 兜底，再不行归 other。
$script:EventKindById = @{
    104 = 'log_cleared'
    41 = 'reboot'; 1074 = 'reboot'; 1076 = 'reboot'; 6005 = 'reboot'; 6006 = 'reboot'
    6008 = 'reboot'; 6013 = 'reboot'; 109 = 'reboot'; 27 = 'reboot'
    7000 = 'service'; 7001 = 'service'; 7009 = 'service'; 7011 = 'service'
    7023 = 'service'; 7024 = 'service'; 7031 = 'service'; 7034 = 'service'
    7040 = 'service'; 7043 = 'service'; 7045 = 'service'
    7036 = 'service_state'
    19 = 'update'; 20 = 'update'; 43 = 'update'; 44 = 'update'
    1000 = 'crash'; 1001 = 'crash'; 1002 = 'crash'; 1005 = 'crash'; 1026 = 'crash'
    26 = 'kernel'; 46 = 'kernel'; 51 = 'kernel'; 129 = 'kernel'; 153 = 'kernel'
    4625 = 'auth'; 4624 = 'auth'; 4648 = 'auth'; 4771 = 'auth'; 4776 = 'auth'
}
$script:KernelProviders = 'Disk|Ntfs|volmgr|volsnap|Partmgr|storahci|stornvme|iaStor|iaStorAC|iaStorAVC|Wdf|BugCheck|Kernel-Power|Kernel-Processor-Power|Kernel-Boot|Microsoft-Windows-Kernel'
$script:CrashProviders = 'Application Error|Application Hang|Windows Error Reporting|\.NET Runtime|Application Popup'

function Get-EventKind {
    param([int]$Id, [string]$Provider, [string]$LogName)
    if ($script:EventKindById.ContainsKey($Id)) { return $script:EventKindById[$Id] }
    if ($Provider -match $script:CrashProviders) { return 'crash' }
    if ($Provider -match $script:KernelProviders) { return 'kernel' }
    if ($Provider -match 'Service Control Manager') { return 'service' }
    if ($Provider -match 'WindowsUpdateClient') { return 'update' }
    if ($LogName -eq 'Security') { return 'auth' }
    return 'other'
}

function Get-OsEvents {
    param([string]$LogName, [int[]]$Ids, [string]$Kind, [int]$Limit, [datetime]$Since,
          [int[]]$Levels = $script:OsLogLevels)
    $res = @()
    try {
        $ht = @{ LogName = $LogName; StartTime = $Since }
        if ($Ids) { $ht.Id = $Ids }             # 不传 Id = 不按 ID 过滤，整本日志按级别筛
        if ($Levels) { $ht.Level = $Levels }    # 传空数组 = 这一类不按级别过滤
        $evs = Get-WinEvent -FilterHashtable $ht -MaxEvents $Limit -ErrorAction Stop
        foreach ($e in $evs) {
            $msg = Safe-Str $e.Message
            $msg = $msg -replace '\r?\n', ' | '
            if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
            $eid = [int]$e.Id
            $prov = Safe-Str $e.ProviderName
            $k = $Kind
            if (-not $k -or $k -eq 'auto') { $k = Get-EventKind $eid $prov $LogName }
            $res += [pscustomobject]@{
                ts      = $e.TimeCreated.ToString('o')
                log     = $LogName
                id      = $eid
                level   = (Get-EventLevelName ([int]$e.Level))
                source  = $prov
                kind    = $k
                message = $msg
            }
        }
    } catch {
        $em = Safe-Str $_.Exception.Message
        if ($em -and $em -notmatch 'No events were found|找不到|没有.*事件') {
            $script:OsLogErrors += ("$LogName/$Kind : $em")
        }
    }
    return , $res
}

$data = [ordered]@{}
$data.collected_at = (Get-Date).ToString('o')
$data.os_type = 'windows'

# ---------------- 基础状态 ----------------
$basic = [ordered]@{}
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $basic.hostname = Safe-Str $env:COMPUTERNAME
    $basic.os = Safe-Str $os.Caption
    $basic.os_version = Safe-Str $os.Version
    # 本机 IPv4（排除回环）
    $ips = @()
    try {
        $ips = @(Get-NetIPAddress -AddressFamily IPv4 |
                 Where-Object { $_.IPAddress -ne '127.0.0.1' } |
                 Select-Object -ExpandProperty IPAddress)
    } catch { }
    $basic.ip = ($ips -join ',')
    # CPU 使用率
    try {
        $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        $basic.cpu_percent = [math]::Round([double]$cpu, 1)
    } catch { $basic.cpu_percent = $null }
    # 内存
    try {
        $totKb = [double]$os.TotalVisibleMemorySize
        $freeKb = [double]$os.FreePhysicalMemory
        $basic.mem_total_mb = [math]::Round($totKb / 1024, 0)
        $basic.mem_free_mb = [math]::Round($freeKb / 1024, 0)
        if ($totKb -gt 0) { $basic.mem_percent = [math]::Round((($totKb - $freeKb) / $totKb) * 100, 1) }
    } catch { }
    # 开机时间 / 运行时长
    try {
        $boot = $os.LastBootUpTime
        $basic.boot_time = $boot.ToString('o')
        $basic.uptime_seconds = [math]::Round(((Get-Date) - $boot).TotalSeconds, 0)
    } catch { }
    # 磁盘
    $disks = @()
    try {
        foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3")) {
            $sizeGb = [math]::Round([double]$d.Size / 1GB, 1)
            $freeGb = [math]::Round([double]$d.FreeSpace / 1GB, 1)
            $pct = $null
            if ($d.Size -and [double]$d.Size -gt 0) {
                $pct = [math]::Round(((1 - ([double]$d.FreeSpace / [double]$d.Size)) * 100), 1)
            }
            $disks += [pscustomobject]@{ device = (Safe-Str $d.DeviceID); size_gb = $sizeGb; free_gb = $freeGb; percent = $pct }
        }
    } catch { }
    $basic.disks = $disks
} catch { }
$data.basic = $basic

# ---------------- 用户与会话 ----------------
$users = [ordered]@{}
try {
    # 已登录用户（可靠）：Win32_LoggedOnUser
    $logged = @()
    try {
        $seen = @{}
        foreach ($u in (Get-CimInstance Win32_LoggedOnUser)) {
            $acc = $u.Antecedent
            if ($acc) {
                $nm = Safe-Str $acc.Name
                $dm = Safe-Str $acc.Domain
                $key = "$dm\$nm"
                if ($nm -and -not $seen.ContainsKey($key)) { $seen[$key] = $true; $logged += $key }
            }
        }
    } catch { }
    $users.logged_on = $logged
    $users.logged_on_count = $logged.Count

    # 活跃会话（best-effort）：query user 文本按位置解析，中文/英文系统均按列切
    $sessions = @()
    $rdp = 0
    try {
        $lines = @(query user 2>$null)
        foreach ($ln in $lines) {
            $t = (Safe-Str $ln).TrimStart('>')
            if (-not $t) { continue }
            if ($t -match '^\s*USERNAME|会话名|SessionName') { continue }  # 表头
            # 末两段是 IDLE TIME 和 LOGON TIME；用正则抓状态与 ID
            if ($t -match '(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(.+)$') {
                $st = $matches[4]
                $sessions += [pscustomobject]@{
                    user = $matches[1]; session = $matches[2]; id = [int]$matches[3];
                    state = $st; raw = $t.Trim()
                }
                if ($st -match 'Active|活动' -and $matches[2] -match 'rdp') { $rdp++ }
            }
        }
    } catch { }
    $users.sessions = $sessions
    $users.session_count = $sessions.Count
    $users.rdp_active = $rdp
} catch { }
$data.users = $users

# ---------------- 网络连接 ----------------
$conns = [ordered]@{}
try {
    $procMap = @{}
    try {
        foreach ($p in (Get-Process)) { $procMap[[int]$p.Id] = (Safe-Str $p.ProcessName) }
    } catch { }

    $tcp = @(Get-NetTCPConnection)
    $byState = @{}
    $established = @()
    $remoteAgg = @{}
    foreach ($c in $tcp) {
        $st = Safe-Str $c.State
        if ($st) { if ($byState.ContainsKey($st)) { $byState[$st]++ } else { $byState[$st] = 1 } }
        if ($st -eq 'Established') {
            $rip = Safe-Str $c.RemoteAddress
            if ($rip) { if ($remoteAgg.ContainsKey($rip)) { $remoteAgg[$rip]++ } else { $remoteAgg[$rip] = 1 } }
            if ($established.Count -lt $MaxConn) {
                $pid2 = [int]$c.OwningProcess
                $pname = ''
                if ($procMap.ContainsKey($pid2)) { $pname = $procMap[$pid2] }
                $established += [pscustomobject]@{
                    local_addr = (Safe-Str $c.LocalAddress); local_port = [int]$c.LocalPort
                    remote_addr = $rip; remote_port = [int]$c.RemotePort
                    pid = $pid2; process = $pname
                }
            }
        }
    }
    $conns.tcp_total = $tcp.Count
    $conns.by_state = $byState
    $conns.established = $established
    # established 只保留前 MaxConn 条样本，且不排序（按 Get-NetTCPConnection 返回顺序），
    # 所以真实连接数必须单独回报——否则上层会把 200 当成"这台机只有 200 个活动连接"。
    $estTrue = 0
    if ($byState.ContainsKey('Established')) { $estTrue = [int]$byState['Established'] }
    $conns.established_total = $estTrue
    $conns.established_truncated = ($estTrue -gt @($established).Count)
    # 来源 IP TOP（按连接数降序）
    $conns.remote_ip_top = @($remoteAgg.GetEnumerator() |
        Sort-Object Value -Descending | Select-Object -First 30 |
        ForEach-Object { [pscustomobject]@{ ip = $_.Key; count = $_.Value } })
    try { $conns.udp_total = @(Get-NetUDPEndpoint).Count } catch { $conns.udp_total = 0 }
} catch { }
$data.connections = $conns

# ---------------- 监听端口 ----------------
$listeners = @()
try {
    $svcByPid = @{}
    try {
        foreach ($s in (Get-CimInstance Win32_Service)) {
            if ($s.ProcessId) { $svcByPid[[int]$s.ProcessId] = (Safe-Str $s.Name) }
        }
    } catch { }
    $procMap2 = @{}
    try { foreach ($p in (Get-Process)) { $procMap2[[int]$p.Id] = (Safe-Str $p.ProcessName) } } catch { }

    foreach ($c in (Get-NetTCPConnection -State Listen)) {
        $pid3 = [int]$c.OwningProcess
        $pname = ''; if ($procMap2.ContainsKey($pid3)) { $pname = $procMap2[$pid3] }
        $svc = ''; if ($svcByPid.ContainsKey($pid3)) { $svc = $svcByPid[$pid3] }
        $listeners += [pscustomobject]@{
            proto = 'TCP'; local_addr = (Safe-Str $c.LocalAddress); local_port = [int]$c.LocalPort
            pid = $pid3; process = $pname; service = $svc
        }
    }
    foreach ($u in (Get-NetUDPEndpoint)) {
        $pid4 = [int]$u.OwningProcess
        $pname = ''; if ($procMap2.ContainsKey($pid4)) { $pname = $procMap2[$pid4] }
        $listeners += [pscustomobject]@{
            proto = 'UDP'; local_addr = (Safe-Str $u.LocalAddress); local_port = [int]$u.LocalPort
            pid = $pid4; process = $pname; service = ''
        }
    }

    # 始终用 netstat -ano 兜底补齐：Get-NetTCPConnection -State Listen 在部分环境
    # (受限权限/旧系统/某些绑定) 会漏掉个别监听端口，导致"明明在监听却判为未监听"。
    # 之前只在 $listeners 完全为空时才兜底——但 Windows 机永远有 135/445/5985 等，
    # 列表不会空，兜底形同虚设。改为无条件解析 netstat LISTENING 行，只补
    # Get-NetTCPConnection 没采到的 TCP 端口(按端口去重)，两种来源取并集。
    try {
        $haveTcp = @{}
        foreach ($l in $listeners) {
            if ((Safe-Str $l.proto) -eq 'TCP') { $haveTcp[[int]$l.local_port] = $true }
        }
        foreach ($ln in (netstat -ano -p TCP 2>$null)) {
            $t = (Safe-Str $ln).Trim()
            if ($t -notmatch 'LISTENING') { continue }
            # 形如: TCP    0.0.0.0:8878    0.0.0.0:0    LISTENING    1234
            $parts = $t -split '\s+'
            if ($parts.Count -lt 5) { continue }
            $local = Safe-Str $parts[1]
            $ci = $local.LastIndexOf(':')
            if ($ci -lt 0) { continue }
            $pv = 0
            if (-not [int]::TryParse($local.Substring($ci + 1), [ref]$pv)) { continue }
            if ($pv -lt 1 -or $pv -gt 65535) { continue }
            if ($haveTcp.ContainsKey($pv)) { continue }
            $haveTcp[$pv] = $true
            $pidN = 0
            [void][int]::TryParse($parts[$parts.Count - 1], [ref]$pidN)
            $pname = ''; if ($procMap2.ContainsKey($pidN)) { $pname = $procMap2[$pidN] }
            $svc = ''; if ($svcByPid.ContainsKey($pidN)) { $svc = $svcByPid[$pidN] }
            $listeners += [pscustomobject]@{
                proto = 'TCP'; local_addr = $local.Substring(0, $ci); local_port = [int]$pv
                pid = $pidN; process = $pname; service = $svc
            }
        }
    } catch { }
} catch { }
$data.listeners = $listeners

# ---------------- 服务 ----------------
# 全量采集所有状态的服务，不再只取 Running：只采 Running 会让"已停止的核心业务服务"
# 彻底不可见——U8 一类服务停掉时，页面等于在说"这台机没有 U8"，恰恰把最关键的线索藏了。
# 运行中的服务不设上限（几百条 JSON 体积可控）；非运行状态的上限 MaxSvcOther 并回报丢弃数。
$services = @()
$servicesOther = @()
$svcOtherTotal = 0
$svcError = ''
try {
    foreach ($s in (Get-CimInstance Win32_Service)) {
        $o = [pscustomobject]@{
            name = (Safe-Str $s.Name); display_name = (Safe-Str $s.DisplayName)
            status = (Safe-Str $s.State); start_mode = (Safe-Str $s.StartMode)
        }
        if ((Safe-Str $s.State) -eq 'Running') {
            $services += $o
        } else {
            $svcOtherTotal++
            if ($servicesOther.Count -lt $MaxSvcOther) { $servicesOther += $o }
        }
    }
} catch { $svcError = Safe-Str $_.Exception.Message }
$data.services = $services
$data.services_total = @($services).Count
$data.services_other = $servicesOther
$data.services_other_total = $svcOtherTotal
$data.services_other_dropped = [Math]::Max(0, $svcOtherTotal - @($servicesOther).Count)
if ($svcError) { $data.services_error = $svcError }

# ---------------- 进程（按内存降序，限量） ----------------
# 内存降序意味着"轻量但关键"的守护进程会被切掉，故必须回报进程总数与截断事实。
$procs = @()
$procTotal = 0
try {
    $ci = @{}
    foreach ($w in (Get-CimInstance Win32_Process)) { $ci[[int]$w.ProcessId] = (Safe-Str $w.CommandLine) }
    $idx = 0
    foreach ($p in (Get-Process | Sort-Object -Property WS -Descending)) {
        $procTotal++
        if ($idx -ge $MaxProc) { continue }
        $pid5 = [int]$p.Id
        $cmd = ''; if ($ci.ContainsKey($pid5)) { $cmd = $ci[$pid5] }
        $procs += [pscustomobject]@{
            name = (Safe-Str $p.ProcessName); pid = $pid5
            mem_mb = [math]::Round([double]$p.WorkingSet64 / 1MB, 1)
            command_line = $cmd
        }
        $idx++
    }
} catch { }
$data.processes = $procs
$data.processes_total = $procTotal
$data.processes_truncated = ($procTotal -gt @($procs).Count)

# ---------------- Supervisor(Windows) 尽力识别 ----------------
$sup = [ordered]@{}
$sup.detected = $false
try {
    $supExe = $null
    foreach ($w in (Get-CimInstance Win32_Process -Filter "Name='supervisor_service.exe' OR Name='python.exe' OR Name='pythonw.exe'")) {
        $cmd = Safe-Str $w.CommandLine
        $exe = Safe-Str $w.ExecutablePath
        if ($exe -match 'supervisor_service\.exe') { $supExe = $exe }
        if ($cmd -and ($cmd -match 'runserver' -or $cmd -match 'uwsgi' -or $cmd -match '--http')) {
            $port = Get-PortFromText $cmd
            if (-not $sup.programs) { $sup.programs = @() }
            $sup.programs += [pscustomobject]@{ pid = [int]$w.ProcessId; port = $port; command = $cmd.Substring(0, [Math]::Min(300, $cmd.Length)) }
        }
    }
    if ($supExe) {
        $sup.detected = $true
        $sup.service_exe = $supExe
        # D:\...\Scripts\supervisor_service.exe → etc 目录 D:\...\etc
        try {
            $scriptsDir = Split-Path -Parent $supExe
            $rootDir = Split-Path -Parent $scriptsDir
            $etcDir = Join-Path $rootDir 'etc'
            if (Test-Path -LiteralPath $etcDir) {
                $inis = @()
                # 一个配置文件里可能有多个 [program:x] 段；每遇到新段先把上一段落库，
                # 避免只保留最后一段（Linux 侧 parse_ini 也是按段累积的）。
                # 除 *.ini 外也扫 *.conf（supervisord.conf 里可能直接以 [program:x] 定义服务）。
                $cfgFiles = @(Get-ChildItem -LiteralPath $etcDir -File |
                    Where-Object { $_.Extension -eq '.ini' -or $_.Extension -eq '.conf' })
                foreach ($f in $cfgFiles) {
                    $programName = ''
                    $command = ''; $stdout = ''; $port = $null
                    foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
                        $l = (Safe-Str $line).Trim()
                        if ($l -match '^\[program:(.+)\]$') {
                            # 新段开始：先把上一段（若有）落库，再重置累积变量
                            if ($programName) {
                                $se = $stdout -replace '%\(program_name\)s', $programName
                                $ce = $command -replace '%\(program_name\)s', $programName
                                $inis += [pscustomobject]@{ name = $programName; port = $port; command = $ce.Substring(0, [Math]::Min(300, $ce.Length)); stdout_logfile = $se; ini_file = (Safe-Str $f.Name) }
                            }
                            $programName = $matches[1].Trim(); $command = ''; $stdout = ''; $port = $null
                        }
                        elseif ($l -match '^command\s*=\s*(.+)$') { $command = $matches[1].Trim(); $port = Get-PortFromText $command }
                        elseif ($l -match '^stdout_logfile\s*=\s*(.+)$') { $stdout = $matches[1].Trim() }
                    }
                    # 落库本文件最后一段
                    if ($programName) {
                        # 展开 supervisor 变量：%(program_name)s → 实际程序名
                        # 例：stdout_logfile=D:\logs\%(program_name)s.log → D:\logs\h5858_ywops.log
                        $se = $stdout -replace '%\(program_name\)s', $programName
                        $ce = $command -replace '%\(program_name\)s', $programName
                        $inis += [pscustomobject]@{ name = $programName; port = $port; command = $ce.Substring(0, [Math]::Min(300, $ce.Length)); stdout_logfile = $se; ini_file = (Safe-Str $f.Name) }
                    }
                }
                $sup.ini_programs = $inis
                $sup.etc_dir = $etcDir
            }
        } catch { }
    }
    if (-not $sup.programs) { $sup.programs = @() }
    if (-not $sup.ini_programs) { $sup.ini_programs = @() }
} catch { }
$data.supervisor = $sup

# ---------------- 应用/Supervisor 日志新鲜度（只读，作为"应用是否在跑"的旁证）----------------
# 仅当调用方传入 AppLogPath(登记的 stdout_logfile / 应用日志路径) 时才探测。
# 红线：只读文件属性与尾部若干行，绝不改写/删除/轮转日志。
$appLog = [ordered]@{ path = (Safe-Str $AppLogPath); exists = $false; size = $null
    mtime = ''; mtime_ago_sec = $null; last_lines = @(); error = '' }
if ($AppLogPath) {
    try {
        if (Test-Path -LiteralPath $AppLogPath -ErrorAction SilentlyContinue) {
            $fi = Get-Item -LiteralPath $AppLogPath -ErrorAction Stop
            $appLog.exists = $true
            $appLog.size = [int64]$fi.Length
            $appLog.mtime = $fi.LastWriteTime.ToString('o')
            $appLog.mtime_ago_sec = [int]((Get-Date) - $fi.LastWriteTime).TotalSeconds
            $tail = @(Get-Content -LiteralPath $AppLogPath -Tail 5 -ErrorAction SilentlyContinue)
            $appLog.last_lines = @($tail | ForEach-Object { (Safe-Str $_).Substring(0, [Math]::Min(300, (Safe-Str $_).Length)) })
        } else {
            $appLog.error = '文件不存在'
        }
    } catch { $appLog.error = (Safe-Str $_.Exception.Message) }
}
$data.app_log = $appLog

# ---------------- 近一日操作系统日志（只读）----------------
# 红线：只用 Get-WinEvent 读取，绝不清除/改写/导出后删除任何日志。
# 用途：影响分析回答"这台机近一日有没有异常关机/服务失败或被停"；
#       故障排查把服务失败/崩溃/内核错误等并入时间线，与端口未监听等事实互相印证。
# 范围：System + Application 两本日志里全部 Warning/Error/Critical 事件，不按 ID 白名单挑。
$osLogs = [ordered]@{}
$osLogs.os_type = 'windows'
$osLogs.days = [int]$OsLogDays
$osLogs.logs_scanned = @('System', 'Application')
$osLogs.level_filter = ('System/Application 全量 {0}（不含 Information/Verbose；例外：104 日志被清除）' -f `
                        ((@($script:OsLogLevels | ForEach-Object { Get-EventLevelName ([int]$_) }) -join '/')))
try {
    $days = [Math]::Max(1, [int]$OsLogDays)
    $since = (Get-Date).AddDays(-$days)
    $osLogs.since = $since.ToString('o')
    $perLogLimit = [Math]::Max(1, [int]$MaxOsLogPerLog)
    $all = @()
    # 全量采集：System / Application 里近 N 日所有 Warning 及以上事件，不按事件 ID 过滤。
    # kind 由 Get-EventKind 逐条归类，认不出的归 other——"归类不出"绝不等于"不重要"。
    foreach ($lg in @('System', 'Application')) {
        $one = Get-OsEvents $lg $null 'auto' $perLogLimit $since
        $n = @($one).Count
        if ($n -ge $perLogLimit) {
            # MaxEvents 取的是最近 N 条，触顶说明丢掉的是更老的那些，必须说出来
            $script:OsLogErrors += ("$lg 日志：Warning 及以上事件已达单日志上限 $perLogLimit 条，" +
                                    '更早的事件未采集（不代表那时段没有异常）')
        }
        $all += $one
    }
    # 日志被清除（104）是 Information 级，属"不采 Information"的唯一例外：
    # 漏掉它等于事后察觉不到证据被人清过。
    $all += Get-OsEvents 'System' @(104) 'log_cleared' $perLogLimit $since -Levels @()

    $osLogs.total_matched = @($all).Count
    $counts = [ordered]@{}
    foreach ($e in $all) {
        $k = Safe-Str $e.kind
        if ($counts.Contains($k)) { $counts[$k] = $counts[$k] + 1 } else { $counts[$k] = 1 }
    }
    $osLogs.counts = $counts
    $sorted = @($all | Sort-Object -Property ts -Descending)
    $cap = [Math]::Max(1, [int]$MaxOsLogTotal)
    if ($sorted.Count -gt $cap) {
        $osLogs.truncated = $true
        $osLogs.dropped = $sorted.Count - $cap
        $sorted = @($sorted[0..($cap - 1)])
    } else {
        $osLogs.truncated = $false
        $osLogs.dropped = 0
    }
    $osLogs.events = $sorted
} catch {
    $osLogs.events = @()
    $osLogs.counts = [ordered]@{}
    $osLogs.total_matched = 0
    $osLogs.truncated = $false
    $osLogs.dropped = 0
    $script:OsLogErrors += ('os_logs 采集异常: ' + (Safe-Str $_.Exception.Message))
}
$osLogs.errors = $script:OsLogErrors
$data.os_logs = $osLogs

$out = @{ ok = $true; data = $data }
Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
