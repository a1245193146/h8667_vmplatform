<#
.SYNOPSIS
    防自锁保护：确保存在允许 Ansible 管理机访问 WinRM (TCP 5985/5986) 的入站规则。
.DESCRIPTION
    确保存在名为 AUTO-ITOPS-MGMT-WINRM-TCP 的 Inbound Allow 规则：
    允许 -AnsibleIP 到本机 TCP 5985,5986。已存在且参数一致则跳过；幂等。
    本脚本逻辑在启用防火墙（Set-FwProfileState.ps1）前必须先执行，防止把 Ansible 自己锁在门外。
    输出单行 JSON: {"ok":true,"data":{"created":["AUTO-ITOPS-MGMT-WINRM-TCP"]}}
.PARAMETER AnsibleIP
    Ansible 管理机 IP（允许的来源地址）。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Protect-ManagementAccess.ps1 -AnsibleIP 10.0.0.2
    => {"ok":true,"data":{"created":["AUTO-ITOPS-MGMT-WINRM-TCP"]}}
.AUTHOR
    AUTO-GENERATED (Agent B - firewall automation module)
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$AnsibleIP
)

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

try {
    $ruleName = 'AUTO-ITOPS-MGMT-WINRM-TCP'
    $created = @()

    $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue

    $needCreate = $true
    if ($null -ne $existing) {
        # 校验关键参数是否一致：方向/动作/启用/远程地址/本地端口/协议
        $match = $true
        try {
            if ([string]$existing.Direction -ne 'Inbound') { $match = $false }
            if ([string]$existing.Action -ne 'Allow') { $match = $false }
            if ([string]$existing.Enabled -ne 'True') { $match = $false }

            $portFilter = $existing | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $addrFilter = $existing | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue

            if ($null -eq $portFilter -or [string]$portFilter.Protocol -ne 'TCP') { $match = $false }
            if ($null -ne $portFilter) {
                $lp = @($portFilter.LocalPort | ForEach-Object { [string]$_ })
                if (-not (($lp -contains '5985') -and ($lp -contains '5986'))) { $match = $false }
            }
            if ($null -eq $addrFilter -or [string]$addrFilter.RemoteAddress -ne $AnsibleIP) { $match = $false }
        }
        catch { $match = $false }

        if ($match) {
            $needCreate = $false
        }
        else {
            # 参数不一致：删除后重建（本规则为 AUTO-ITOPS- 前缀，受本系统管理）
            Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
            $needCreate = $true
        }
    }

    if ($needCreate) {
        $null = New-NetFirewallRule -Name $ruleName `
            -DisplayName 'AUTO-ITOPS Management WinRM TCP (Ansible)' `
            -Direction Inbound -Action Allow -Enabled True `
            -Protocol TCP -LocalPort 5985, 5986 `
            -RemoteAddress $AnsibleIP -Profile Any -ErrorAction Stop
        $created += $ruleName
    }

    $out = @{ ok = $true; data = @{ created = $created } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
