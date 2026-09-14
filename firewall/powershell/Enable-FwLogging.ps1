<#
.SYNOPSIS
    开启 Windows 防火墙日志（丢弃/允许连接）与安全审计策略。
.DESCRIPTION
    netsh advfirewall set allprofiles logging droppedconnections/allowedconnections enable；
    auditpol 开启 "Filtering Platform Packet Drop" 与 "Filtering Platform Connection" 审计。
    输出单行 JSON: {"ok":true,"data":{"dropped":bool,"allowed":bool,"audit":bool}}
.PARAMETER 无
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Enable-FwLogging.ps1
    => {"ok":true,"data":{"dropped":true,"allowed":true,"audit":true}}
.AUTHOR
    AUTO-GENERATED (Agent B - firewall automation module)
#>
param()

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

try {
    $dropped = $false; $allowed = $false; $audit = $false

    $null = & netsh advfirewall set allprofiles logging droppedconnections enable 2>&1
    if ($LASTEXITCODE -eq 0) { $dropped = $true }

    $null = & netsh advfirewall set allprofiles logging allowedconnections enable 2>&1
    if ($LASTEXITCODE -eq 0) { $allowed = $true }

    $auditOk1 = $false; $auditOk2 = $false
    $null = & auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) { $auditOk1 = $true }
    $null = & auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) { $auditOk2 = $true }
    $audit = ($auditOk1 -and $auditOk2)

    $out = @{ ok = $true; data = @{ dropped = $dropped; allowed = $allowed; audit = $audit } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
