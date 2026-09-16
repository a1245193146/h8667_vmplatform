<#
.SYNOPSIS
    读取 Windows 安全日志中的防火墙过滤平台事件（5152/5156/5157）。
.DESCRIPTION
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=5152,5156,5157} 按 -SinceMinutes 过滤。
    5152/5157 -> DROP；5156 -> ALLOW。
    从事件 XML 取 ProcessId、SourceAddress、DestAddress、SourcePort、DestPort、Protocol、Direction。
    Protocol 数值转 TCP/UDP/ICMP；Direction %%2148013/%%2148014 或数值转 inbound/outbound（取不到留空）。
    进程路径由 PID 反查（进程可能已退出，取不到留空）。
    无权限/无日志 -> events=[]，不报错。
    输出单行 JSON: {"ok":true,"data":{"events":[{time,event_id,action,direction,protocol,src_ip,src_port,dst_ip,dst_port,pid,process_path}]}}
.PARAMETER SinceMinutes
    只取最近 N 分钟内的事件，默认 10。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Read-FwSecurityEvents.ps1 -SinceMinutes 10
    => {"ok":true,"data":{"events":[{"time":"2025-01-01 12:00:00","event_id":5157,"action":"DROP","direction":"inbound","protocol":"TCP","src_ip":"1.2.3.4","src_port":"5000","dst_ip":"10.0.0.5","dst_port":"445","pid":0,"process_path":""}]}}
.AUTHOR
    AUTO-GENERATED (Agent B - firewall automation module)
#>
param(
    [Parameter(Mandatory = $false)]
    [int]$SinceMinutes = 10
)

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

function Convert-ProtocolNumber {
    param([string]$Proto)
    switch ($Proto) {
        '6'  { return 'TCP' }
        '17' { return 'UDP' }
        '1'  { return 'ICMP' }
        '58' { return 'ICMPv6' }
        default { return $Proto }
    }
}

function Convert-DirectionValue {
    param([string]$Dir)
    if ([string]::IsNullOrEmpty($Dir)) { return '' }
    # 过滤平台事件 Direction 常见取值：%%14592/%%2148013/1 = 入站，%%14593/%%2148014/2 = 出站
    if ($Dir -match '14592' -or $Dir -match '2148013' -or $Dir -eq '1') { return 'inbound' }
    if ($Dir -match '14593' -or $Dir -match '2148014' -or $Dir -eq '2') { return 'outbound' }
    return ''
}

try {
    $events = @()
    $startTime = (Get-Date).AddMinutes(-1 * [Math]::Abs($SinceMinutes))

    $rawEvents = @()
    try {
        $rawEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5152, 5156, 5157; StartTime = $startTime } -ErrorAction Stop)
    }
    catch {
        # 无匹配事件 / 无权限 -> 空列表，不报错
        $rawEvents = @()
    }

    foreach ($ev in $rawEvents) {
        $xml = $null
        try { $xml = [xml]$ev.ToXml() } catch { $xml = $null }
        if ($null -eq $xml) { continue }

        $dataMap = @{}
        foreach ($d in $xml.Event.EventData.Data) {
            $dataMap[[string]$d.Name] = [string]$d.'#text'
        }

        $eventId = [int]$ev.Id
        $action = 'DROP'
        if ($eventId -eq 5156) { $action = 'ALLOW' }

        $pid_ = 0
        if ($dataMap.ContainsKey('ProcessId')) {
            $tmp = 0
            if ([int]::TryParse([string]$dataMap['ProcessId'], [ref]$tmp)) { $pid_ = $tmp }
        }

        # 进程路径由 PID 反查（可能已退出，取不到留空）
        $procPath = ''
        if ($pid_ -gt 0) {
            try {
                $proc = Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId = {0}" -f $pid_) -ErrorAction SilentlyContinue
                if ($null -ne $proc) { $procPath = [string]$proc.ExecutablePath }
            } catch { $procPath = '' }
        }

        $events += @{
            time         = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            event_id     = $eventId
            action       = $action
            direction    = Convert-DirectionValue $(if ($dataMap.ContainsKey('Direction')) { [string]$dataMap['Direction'] } else { '' })
            protocol     = Convert-ProtocolNumber $(if ($dataMap.ContainsKey('Protocol')) { [string]$dataMap['Protocol'] } else { '' })
            src_ip       = $(if ($dataMap.ContainsKey('SourceAddress')) { [string]$dataMap['SourceAddress'] } else { '' })
            src_port     = $(if ($dataMap.ContainsKey('SourcePort')) { [string]$dataMap['SourcePort'] } else { '' })
            dst_ip       = $(if ($dataMap.ContainsKey('DestAddress')) { [string]$dataMap['DestAddress'] } else { '' })
            dst_port     = $(if ($dataMap.ContainsKey('DestPort')) { [string]$dataMap['DestPort'] } else { '' })
            pid          = $pid_
            process_path = $procPath
        }
    }

    $out = @{ ok = $true; data = @{ events = $events } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
