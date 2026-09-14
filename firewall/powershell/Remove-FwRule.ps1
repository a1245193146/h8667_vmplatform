<#
.SYNOPSIS
    删除一条 AUTO-ITOPS- 前缀的防火墙规则（安全红线：非本系统规则拒绝删除）。
.DESCRIPTION
    非 AUTO-ITOPS- 前缀规则拒绝删除：removed=false reason=not_managed。
    规则不存在：removed=false reason=not_found。
    输出单行 JSON: {"ok":true,"data":{"name":"...","removed":true,"reason":"removed"}}
.PARAMETER Name
    要删除的规则名。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Remove-FwRule.ps1 -Name AUTO-ITOPS-O-TCP-188-8878-a1b2c3
    => {"ok":true,"data":{"name":"AUTO-ITOPS-O-TCP-188-8878-a1b2c3","removed":true,"reason":"removed"}}
.AUTHOR
    AUTO-GENERATED (Agent B - firewall automation module)
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Name
)

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

try {
    if (-not $Name.StartsWith('AUTO-ITOPS-')) {
        $out = @{ ok = $true; data = @{ name = $Name; removed = $false; reason = 'not_managed' } }
        Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
        exit 0
    }

    $existing = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        $out = @{ ok = $true; data = @{ name = $Name; removed = $false; reason = 'not_found' } }
        Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
        exit 0
    }

    Remove-NetFirewallRule -Name $Name -ErrorAction Stop

    $out = @{ ok = $true; data = @{ name = $Name; removed = $true; reason = 'removed' } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
