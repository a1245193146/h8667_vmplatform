<#
.SYNOPSIS
    采集全部 Windows 防火墙规则明细。
.DESCRIPTION
    逐条 Get-NetFirewallRule 并关联 Get-NetFirewallPortFilter / AddressFilter /
    ApplicationFilter / ServiceFilter 取端口/地址/程序/服务。
    Enabled 转 bool；Profile 数值转名称（Domain,Private,Public / Any）。
    输出单行 JSON: {"ok":true,"data":{"rules":[{name,display_name,direction,action,enabled,profile,protocol,local_port,remote_port,local_address,remote_address,program,service,description}]}}
.PARAMETER 无
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Collect-FwRules.ps1
    => {"ok":true,"data":{"rules":[{"name":"AUTO-ITOPS-O-TCP-188-8878-a1b2c3","display_name":"...","direction":"Outbound","action":"Allow","enabled":true,"profile":"Any","protocol":"TCP","local_port":"","remote_port":"8878","local_address":"Any","remote_address":"10.0.0.188","program":"","service":"","description":""}]}}
.AUTHOR
    AUTO-GENERATED (Agent B - firewall automation module)
#>
param()

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

function Convert-ProfileToName {
    param([object]$Profile)
    # NetSecurity Profile 是 [Flags] 枚举：0=Any, 1=Domain, 2=Private, 4=Public
    $v = [int]$Profile
    if ($v -eq 0) { return 'Any' }
    $names = @()
    if (($v -band 1) -ne 0) { $names += 'Domain' }
    if (($v -band 2) -ne 0) { $names += 'Private' }
    if (($v -band 4) -ne 0) { $names += 'Public' }
    if ($names.Count -eq 0) { return 'Any' }
    return ($names -join ',')
}

function Convert-AddrToString {
    param([object]$Addr)
    if ($null -eq $Addr) { return 'Any' }
    $s = [string]$Addr
    if ($s -eq '' -or $s -eq '*') { return 'Any' }
    return $s
}

try {
    $rules = @()
    $allRules = @(Get-NetFirewallRule -ErrorAction Stop)
    foreach ($r in $allRules) {
        $portFilter = $null; $addrFilter = $null; $appFilter = $null; $svcFilter = $null
        try { $portFilter = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue } catch { $portFilter = $null }
        try { $addrFilter = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue } catch { $addrFilter = $null }
        try { $appFilter  = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue } catch { $appFilter = $null }
        try { $svcFilter  = $r | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue } catch { $svcFilter = $null }

        $protocol   = ''; $localPort = ''; $remotePort = ''
        $localAddr  = 'Any'; $remoteAddr = 'Any'
        $program    = ''; $service = ''

        if ($null -ne $portFilter) {
            $protocol  = [string]$portFilter.Protocol
            $localPort = [string]$portFilter.LocalPort
            $remotePort = [string]$portFilter.RemotePort
            if ($localPort -eq 'Any' -or $localPort -eq '*') { $localPort = '' }
            if ($remotePort -eq 'Any' -or $remotePort -eq '*') { $remotePort = '' }
        }
        if ($null -ne $addrFilter) {
            $localAddr  = Convert-AddrToString $addrFilter.LocalAddress
            $remoteAddr = Convert-AddrToString $addrFilter.RemoteAddress
        }
        if ($null -ne $appFilter) {
            $program = [string]$appFilter.Program
            if ($program -eq 'Any' -or $program -eq '*') { $program = '' }
        }
        if ($null -ne $svcFilter) {
            $service = [string]$svcFilter.Service
            if ($service -eq 'Any' -or $service -eq '*') { $service = '' }
        }

        $rules += @{
            name           = [string]$r.Name
            display_name   = [string]$r.DisplayName
            direction      = [string]$r.Direction
            action         = [string]$r.Action
            enabled        = [bool]([string]$r.Enabled -eq 'True')
            profile        = Convert-ProfileToName $r.Profile
            protocol       = $protocol
            local_port     = $localPort
            remote_port    = $remotePort
            local_address  = $localAddr
            remote_address = $remoteAddr
            program        = $program
            service        = $service
            description    = [string]$r.Description
        }
    }

    $out = @{ ok = $true; data = @{ rules = $rules } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
