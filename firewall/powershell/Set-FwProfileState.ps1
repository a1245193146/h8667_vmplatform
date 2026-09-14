<#
.SYNOPSIS
    设置防火墙 Profile 启用状态（带防自锁保护）。
.DESCRIPTION
    启用防火墙前必须先确保存在允许 -AnsibleIP 访问 TCP 5985/5986 的
    Inbound 规则（AUTO-ITOPS-MGMT-WINRM-TCP，幂等）——防自锁红线。
    然后 Set-NetFirewallProfile 设置指定 Profile 的 Enabled 状态。
    输出单行 JSON: {"ok":true,"data":{"profile":"All","enabled":true,"protected":true}}
.PARAMETER Profile
    Domain | Private | Public | All
.PARAMETER Enabled
    是否启用（true/false）。
.PARAMETER AnsibleIP
    Ansible 管理机 IP（用于防自锁保护规则）。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Set-FwProfileState.ps1 -Profile All -Enabled $true -AnsibleIP 10.0.0.2
    => {"ok":true,"data":{"profile":"All","enabled":true,"protected":true}}
.AUTHOR
    AUTO-GENERATED (Agent B - firewall automation module)
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Domain', 'Private', 'Public', 'All')]
    [string]$Profile,

    [Parameter(Mandatory = $true)]
    [bool]$Enabled,

    [Parameter(Mandatory = $true)]
    [string]$AnsibleIP
)

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

try {
    $protected = $false

    # 防自锁红线：启用防火墙前必须确保 WinRM 管理通道规则存在
    if ($Enabled) {
        $protectScript = Join-Path $PSScriptRoot 'Protect-ManagementAccess.ps1'
        if (-not (Test-Path -Path $protectScript -PathType Leaf)) {
            throw "Protect-ManagementAccess.ps1 not found at $protectScript"
        }
        $protectOut = & $protectScript -AnsibleIP $AnsibleIP
        $protectJson = $protectOut | ConvertFrom-Json
        if (-not $protectJson.ok) {
            throw ("Protect-ManagementAccess failed: {0}" -f [string]$protectJson.error)
        }
        $protected = $true
    }

    if ($Profile -eq 'All') {
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled $Enabled -ErrorAction Stop
    }
    else {
        Set-NetFirewallProfile -Profile $Profile -Enabled $Enabled -ErrorAction Stop
    }

    $out = @{ ok = $true; data = @{ profile = $Profile; enabled = [bool]$Enabled; protected = $protected } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
