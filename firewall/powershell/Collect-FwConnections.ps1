<#
.SYNOPSIS
    采集当前活动 TCP/UDP 连接（含进程与服务归属）。
.DESCRIPTION
    Get-NetTCPConnection + Get-NetUDPEndpoint；PID -> Get-CimInstance Win32_Process
    取 ExecutablePath；再按 Win32_Service.ProcessId 匹配服务名。
    所有取不到的字段留空字符串，绝不 throw。
    输出单行 JSON: {"ok":true,"data":{"connections":[{protocol,local_address,local_port,remote_address,remote_port,state,pid,process_name,process_path,service_name}]}}
.PARAMETER 无
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Collect-FwConnections.ps1
    => {"ok":true,"data":{"connections":[{"protocol":"TCP","local_address":"10.0.0.5","local_port":49200,"remote_address":"10.0.0.188","remote_port":8878,"state":"Established","pid":1234,"process_name":"java.exe","process_path":"C:\\app\\java.exe","service_name":""}]}}
.AUTHOR
    AUTO-GENERATED (Agent B - firewall automation module)
#>
param()

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

try {
    # 预取进程表：PID -> (Name, ExecutablePath)
    $procMap = @{}
    try {
        foreach ($p in (Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) {
            $procMap[[int]$p.ProcessId] = @{
                name = [string]$p.Name
                path = [string]$p.ExecutablePath
            }
        }
    } catch { $procMap = @{} }

    # 预取服务表：ProcessId -> 服务名列表
    $svcMap = @{}
    try {
        foreach ($s in (Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) {
            $spid = [int]$s.ProcessId
            if ($spid -gt 0) {
                if (-not $svcMap.ContainsKey($spid)) { $svcMap[$spid] = @() }
                $svcMap[$spid] += [string]$s.Name
            }
        }
    } catch { $svcMap = @{} }

    $connections = @()

    # TCP 连接
    $tcpList = @()
    try { $tcpList = @(Get-NetTCPConnection -ErrorAction SilentlyContinue) } catch { $tcpList = @() }
    foreach ($c in $tcpList) {
        $pid_ = 0
        try { $pid_ = [int]$c.OwningProcess } catch { $pid_ = 0 }
        $procName = ''; $procPath = ''; $svcName = ''
        if ($procMap.ContainsKey($pid_)) {
            $procName = [string]$procMap[$pid_].name
            $procPath = [string]$procMap[$pid_].path
        }
        if ($svcMap.ContainsKey($pid_)) { $svcName = ($svcMap[$pid_] -join ',') }

        $connections += @{
            protocol       = 'TCP'
            local_address  = [string]$c.LocalAddress
            local_port     = [int]$c.LocalPort
            remote_address = [string]$c.RemoteAddress
            remote_port    = [int]$c.RemotePort
            state          = [string]$c.State
            pid            = $pid_
            process_name   = $procName
            process_path   = $procPath
            service_name   = $svcName
        }
    }

    # UDP 端点
    $udpList = @()
    try { $udpList = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue) } catch { $udpList = @() }
    foreach ($u in $udpList) {
        $pid_ = 0
        try { $pid_ = [int]$u.OwningProcess } catch { $pid_ = 0 }
        $procName = ''; $procPath = ''; $svcName = ''
        if ($procMap.ContainsKey($pid_)) {
            $procName = [string]$procMap[$pid_].name
            $procPath = [string]$procMap[$pid_].path
        }
        if ($svcMap.ContainsKey($pid_)) { $svcName = ($svcMap[$pid_] -join ',') }

        $connections += @{
            protocol       = 'UDP'
            local_address  = [string]$u.LocalAddress
            local_port     = [int]$u.LocalPort
            remote_address = ''
            remote_port    = 0
            state          = ''
            pid            = $pid_
            process_name   = $procName
            process_path   = $procPath
            service_name   = $svcName
        }
    }

    $out = @{ ok = $true; data = @{ connections = $connections } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
