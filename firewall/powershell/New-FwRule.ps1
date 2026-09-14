<#
.SYNOPSIS
    创建（或幂等更新）一条 AUTO-ITOPS- 前缀的防火墙规则。
.DESCRIPTION
    -RuleJson 为 JSON 字符串，含 rule_name/display_name/direction/action/protocol/
    program/service/local_address/local_port/remote_address/remote_port/profile/enabled。
    rule_name 必须 AUTO-ITOPS- 前缀，否则拒绝（ok:false）。
    同名规则已存在：关键参数一致 -> created=false reason=exists；
    不一致 -> 先 Remove 再 New（仅允许对 AUTO-ITOPS- 前缀规则这么做）。
    New-NetFirewallRule 参数映射：-Program/-Service/-RemoteAddress/-RemotePort/
    -LocalPort/-Protocol/-Direction/-Action/-Profile/-Enabled；空值参数不传。
    输出单行 JSON: {"ok":true,"data":{"name":"...","created":true,"reason":"created"}}
.PARAMETER RuleJson
    规则定义 JSON 字符串。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File New-FwRule.ps1 -RuleJson '{"rule_name":"AUTO-ITOPS-O-TCP-188-8878-a1b2c3","direction":"Outbound","action":"Allow","protocol":"TCP","remote_address":"10.0.0.188","remote_port":"8878","profile":"Any","enabled":true}'
    => {"ok":true,"data":{"name":"AUTO-ITOPS-O-TCP-188-8878-a1b2c3","created":true,"reason":"created"}}
.AUTHOR
    AUTO-GENERATED (Agent B - firewall automation module)
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$RuleJson
)

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

function Get-PropValue {
    param([object]$Obj, [string]$Name, [string]$Default = '')
    if ($null -ne $Obj -and $null -ne $Obj.PSObject.Properties[$Name]) {
        $v = $Obj.$Name
        if ($null -ne $v) { return [string]$v }
    }
    return $Default
}

function Test-RuleParamMatch {
    param([object]$Existing, [object]$Spec)
    try {
        if ([string]$Existing.Direction -ne (Get-PropValue $Spec 'direction' 'Outbound')) { return $false }
        if ([string]$Existing.Action -ne (Get-PropValue $Spec 'action' 'Allow')) { return $false }
        $wantEnabled = 'True'
        if ((Get-PropValue $Spec 'enabled' 'true') -match '^(false|False|0)$') { $wantEnabled = 'False' }
        if ([string]$Existing.Enabled -ne $wantEnabled) { return $false }

        $portFilter = $Existing | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $addrFilter = $Existing | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        $appFilter  = $Existing | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
        $svcFilter  = $Existing | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue

        $wantProto = (Get-PropValue $Spec 'protocol' 'TCP').ToUpper()
        $curProto = ''; if ($null -ne $portFilter) { $curProto = ([string]$portFilter.Protocol).ToUpper() }
        if ($curProto -ne $wantProto) { return $false }

        $wantLP = Get-PropValue $Spec 'local_port' ''
        $curLP = ''; if ($null -ne $portFilter) { $curLP = [string]$portFilter.LocalPort }
        if ($curLP -eq 'Any' -or $curLP -eq '*') { $curLP = '' }
        if ($curLP -ne $wantLP) { return $false }

        $wantRP = Get-PropValue $Spec 'remote_port' ''
        $curRP = ''; if ($null -ne $portFilter) { $curRP = [string]$portFilter.RemotePort }
        if ($curRP -eq 'Any' -or $curRP -eq '*') { $curRP = '' }
        if ($curRP -ne $wantRP) { return $false }

        $wantRA = Get-PropValue $Spec 'remote_address' 'Any'
        $curRA = 'Any'; if ($null -ne $addrFilter) { $curRA = [string]$addrFilter.RemoteAddress }
        if ($curRA -eq '*') { $curRA = 'Any' }
        if ($curRA -ne $wantRA) { return $false }

        $wantLA = Get-PropValue $Spec 'local_address' 'Any'
        $curLA = 'Any'; if ($null -ne $addrFilter) { $curLA = [string]$addrFilter.LocalAddress }
        if ($curLA -eq '*') { $curLA = 'Any' }
        if ($curLA -ne $wantLA) { return $false }

        $wantProg = Get-PropValue $Spec 'program' ''
        $curProg = ''; if ($null -ne $appFilter) { $curProg = [string]$appFilter.Program }
        if ($curProg -eq 'Any' -or $curProg -eq '*') { $curProg = '' }
        if ($curProg -ne $wantProg) { return $false }

        $wantSvc = Get-PropValue $Spec 'service' ''
        $curSvc = ''; if ($null -ne $svcFilter) { $curSvc = [string]$svcFilter.Service }
        if ($curSvc -eq 'Any' -or $curSvc -eq '*') { $curSvc = '' }
        if ($curSvc -ne $wantSvc) { return $false }

        $wantProfile = Get-PropValue $Spec 'profile' 'Any'
        if ([string]$Existing.Profile -ne $wantProfile) { return $false }

        return $true
    }
    catch { return $false }
}

try {
    $spec = $RuleJson | ConvertFrom-Json

    $ruleName = Get-PropValue $spec 'rule_name' ''
    if ([string]::IsNullOrEmpty($ruleName)) {
        $err = @{ ok = $false; error = 'rule_name is required' }
        Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
        exit 0
    }
    if (-not $ruleName.StartsWith('AUTO-ITOPS-')) {
        $err = @{ ok = $false; error = "rule_name must start with AUTO-ITOPS- prefix: $ruleName" }
        Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
        exit 0
    }

    $created = $false
    $reason = 'created'

    $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        if (Test-RuleParamMatch -Existing $existing -Spec $spec) {
            $out = @{ ok = $true; data = @{ name = $ruleName; created = $false; reason = 'exists' } }
            Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
            exit 0
        }
        # 参数不一致：先删后建（仅 AUTO-ITOPS- 前缀规则允许，上面已校验）
        Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
        $reason = 'replaced'
    }

    # 组装 New-NetFirewallRule 参数，空值参数不传
    $newParams = @{
        Name        = $ruleName
        DisplayName = (Get-PropValue $spec 'display_name' $ruleName)
        Direction   = (Get-PropValue $spec 'direction' 'Outbound')
        Action      = (Get-PropValue $spec 'action' 'Allow')
        Protocol    = (Get-PropValue $spec 'protocol' 'TCP')
        Profile     = (Get-PropValue $spec 'profile' 'Any')
    }
    $enabledStr = Get-PropValue $spec 'enabled' 'true'
    if ($enabledStr -match '^(false|False|0)$') { $newParams['Enabled'] = 'False' } else { $newParams['Enabled'] = 'True' }

    $program = Get-PropValue $spec 'program' ''
    if ($program -ne '' -and $program -ne 'Any') { $newParams['Program'] = $program }
    $service = Get-PropValue $spec 'service' ''
    if ($service -ne '' -and $service -ne 'Any') { $newParams['Service'] = $service }
    $localAddr = Get-PropValue $spec 'local_address' ''
    if ($localAddr -ne '' -and $localAddr -ne 'Any') { $newParams['LocalAddress'] = $localAddr }
    $remoteAddr = Get-PropValue $spec 'remote_address' ''
    if ($remoteAddr -ne '' -and $remoteAddr -ne 'Any') { $newParams['RemoteAddress'] = $remoteAddr }
    $localPort = Get-PropValue $spec 'local_port' ''
    if ($localPort -ne '' -and $localPort -ne 'Any') { $newParams['LocalPort'] = $localPort }
    $remotePort = Get-PropValue $spec 'remote_port' ''
    if ($remotePort -ne '' -and $remotePort -ne 'Any') { $newParams['RemotePort'] = $remotePort }

    $null = New-NetFirewallRule @newParams -ErrorAction Stop
    $created = $true

    $out = @{ ok = $true; data = @{ name = $ruleName; created = $created; reason = $reason } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
