<#
.SYNOPSIS
    采集 Windows 防火墙总体状态（服务状态 + 三个 Profile 的启用状态与默认策略）。
.DESCRIPTION
    输出单行 JSON: {"ok":true,"data":{hostname,os,service_running,profiles:{Domain:{enabled,default_inbound,default_outbound},Private:{...},Public:{...}}}}
    任何异常输出 {"ok":false,"error":"..."}，stdout 仅此一行 JSON。
.PARAMETER 无
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Collect-FwStatus.ps1
    => {"ok":true,"data":{"hostname":"WIN-01","os":"Microsoft Windows Server 2019 Standard","service_running":true,"profiles":{"Domain":{"enabled":true,"default_inbound":"Block","default_outbound":"Allow"},...}}}
.AUTHOR
    AUTO-GENERATED (Agent B - firewall automation module)
#>
param()

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $svc = Get-Service -Name 'MpsSvc' -ErrorAction SilentlyContinue
    $serviceRunning = ($null -ne $svc -and $svc.Status -eq 'Running')

    $profiles = @{}
    foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) {
        $profiles[$p.Name] = @{
            enabled          = [bool]$p.Enabled
            default_inbound  = [string]$p.DefaultInboundAction
            default_outbound = [string]$p.DefaultOutboundAction
        }
    }

    $data = @{
        hostname        = [string]$env:COMPUTERNAME
        os              = [string]$osInfo.Caption
        service_running = $serviceRunning
        profiles        = $profiles
    }
    $out = @{ ok = $true; data = $data }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
