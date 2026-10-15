<#
.SYNOPSIS
    读取 Windows Defender 检测事件（Event Log），输出单行 JSON 供 Django 侧入库。
.DESCRIPTION
    数据源：Microsoft-Windows-Windows Defender/Operational 日志。
    事件 ID：1116(检出) / 1117(处置) / 1118,1119(处置失败)。
    断点续采：仅读取 RecordId > -SinceRecordId 的事件，按 RecordId 升序取前 -MaxEvents 条，
              输出 max_record_id（本批已处理的最大 RecordId）供调用方推进水位；
              未处理完的留待下次采集，服务器/程序重启不重不漏。
    合并：同一次检出的 1116 与 1117 按 Detection ID 合并为一条记录（1116 出检测信息，
          1117 出处置结果 Action Name），避免重复。
    安全取值：对仍存在的原始文件用 Get-FileHash 计算 SHA256 与大小；文件已被 Defender
              清除则留空（"能够安全获取时记录"）。
    性能红线：Get-FileHash 会整文件读盘，遇到大容器(ISO/VHD/大压缩包/数据文件)可能单个
              就耗时数分钟，是历史超时的主因。故对哈希设三重预算：单文件字节上限
              (-MaxHashBytes)、本批哈希文件数上限(-MaxHashFiles)、本批累计字节上限
              (-MaxHashTotalBytes)。超限文件【跳过哈希但仍记录该检出】(留 file_size +
              hash_skipped 原因)，绝不因跳过哈希而丢事件——留痕红线优先于取证完整度。
              另用 -FilterXPath 把 EventRecordID>水位 下推到日志查询引擎，避免每次全量
              拉取整段历史；各相位耗时(fetch/parse/hash)随 timings 一并回传供诊断。
    红线：只读事件日志，绝不触碰 Defender 内部隔离目录。
    输出单行 JSON: {"ok":true,"data":{"events":[{...}],"max_record_id":N,"timings":{...},"hash_stats":{...}}}
.PARAMETER SinceRecordId
    只读取 RecordId 大于该值的事件（默认 0，即从头）。
.PARAMETER MaxEvents
    单次最多处理的事件条数（默认 300），用于限制输出体积并保证水位正确推进。
.PARAMETER MaxHashFiles
    本批最多对多少个文件计算 SHA256（默认 50）；超出的记录 hash_skipped=budget_files。
.PARAMETER MaxHashBytes
    单个文件超过此字节数则跳过哈希（默认 100MB）；记录 hash_skipped=oversize，仍留 file_size。
.PARAMETER MaxHashTotalBytes
    本批累计哈希字节预算（默认 300MB）；超出后剩余文件记录 hash_skipped=budget_bytes。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Av-CollectDetections.ps1 -SinceRecordId 0
.AUTHOR
    AUTO-GENERATED (antivirus automation module)
#>
param(
    [long]$SinceRecordId = 0,
    [int]$MaxEvents = 300,
    [int]$MaxHashFiles = 50,
    [long]$MaxHashBytes = 104857600,
    [long]$MaxHashTotalBytes = 314572800
)

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8
$swTotal = [System.Diagnostics.Stopwatch]::StartNew()

$LogName = 'Microsoft-Windows-Windows Defender/Operational'
$EventIds = 1116, 1117, 1118, 1119

# Action ID → 文本（事件通常已带 Action Name，此表仅作 ID 兜底）
$ActionMap = @{
    '1' = 'Clean'; '2' = 'Quarantine'; '3' = 'Remove'; '4' = 'Allow';
    '5' = 'NoAction'; '6' = 'Block'; '8' = 'UserDefined'; '9' = 'NoAction';
    '10' = 'Block'
}

# Defender 消息资源表（%%NNN → 文本）。EventData 里 Action Name / Severity Name /
# Category Name 等存的是未渲染的资源引用（如 %%809），需由 MpEvMsg.dll 渲染，直接读
# 会拿到 %%809。此表就地还原成可读文本；未收录编号保持原样（绝不臆测）。
$ResourceMap = @{
    '800' = 'AntiVirus'; '801' = 'AntiSpyware'; '802' = 'Antimalware';
    '803' = 'Full'; '804' = 'Delta'; '805' = 'Full Scan'; '806' = 'Quick Scan';
    '807' = 'Custom Scan'; '808' = 'Remove'; '809' = 'Quarantine'; '810' = 'Clean';
    '811' = 'Allow'; '812' = 'Unknown'; '813' = 'Suspended'; '814' = 'Allowed';
    '815' = 'User'; '816' = 'Scheduled'; '817' = 'Signature Update Folder';
    '818' = 'Real-Time Protection'; '819' = 'Downloads and attachments'; '820' = 'System';
    '821' = 'Heuristics'; '822' = 'Concrete'; '823' = 'Generic'; '824' = 'Current';
    '825' = 'Backup'; '826' = 'Default'; '827' = 'Windows Defender Antivirus';
    '828' = 'Microsoft Forefront Endpoint Protection';
    '829' = 'Microsoft Standalone System Sweeper'; '830' = 'Crash'; '831' = 'Hang';
    '832' = 'Not Applicable'; '833' = 'IE Downloads and Outlook Express Attachments';
    '834' = 'On Access'; '835' = 'Behavior Monitoring'; '843' = 'Suspicious';
    '844' = 'Unknown'; '845' = 'Local machine'; '846' = 'Network share'; '847' = 'Internet';
    '848' = 'Executing'; '849' = 'Internal Definition Update Server'; '850' = 'File Share';
    '851' = 'Microsoft Malware Protection Center'; '852' = 'Search'; '853' = 'Download';
    '854' = 'Install'; '855' = 'Low'; '856' = 'Medium'; '857' = 'High';
    '859' = 'Microsoft Update Server'; '860' = 'Microsoft Antimalware'
}

function Get-Field {
    param([hashtable]$Map, [string[]]$Names)
    foreach ($n in $Names) { if ($Map.ContainsKey($n) -and $Map[$n]) { return $Map[$n] } }
    return ''
}

# 把字符串里的 %%NNN 资源引用替换成可读文本；未收录编号原样保留。
# 兼容带后缀写法：'%%809 (Failed)' → 'Quarantine (Failed)'。
# 用显式 Matches 循环而非 [regex]::Replace 的 scriptblock 委托——委托在全新作用域执行，
# 读不到脚本级 $ResourceMap；手动拼接在 PS 5.1 下作用域可靠。
function Resolve-Res {
    param([string]$Text)
    if (-not $Text) { return $Text }
    if ($Text.IndexOf('%%') -lt 0) { return $Text }
    $ms = [regex]::Matches($Text, '%%(\d+)')
    if ($ms.Count -eq 0) { return $Text }
    $sb = New-Object System.Text.StringBuilder
    $last = 0
    foreach ($m in $ms) {
        [void]$sb.Append($Text.Substring($last, $m.Index - $last))
        $id = $m.Groups[1].Value
        if ($ResourceMap.ContainsKey($id)) { [void]$sb.Append($ResourceMap[$id]) }
        else { [void]$sb.Append($m.Value) }
        $last = $m.Index + $m.Length
    }
    [void]$sb.Append($Text.Substring($last))
    return $sb.ToString()
}

function Clean-ResourcePath {
    param([string]$P)
    if (-not $P) { return '' }
    $p = $P.Trim()
    # Defender 压缩包嵌套感染格式：<磁盘容器>;file:_<容器>-><内层1>->...-><感染文件>
    # 只有第一个 '->' 之前、且第一个 ';' 之前的部分才是磁盘上真实存在的文件（最外层容器）。
    # '>' 是 Windows 文件名非法字符，真实路径段里不会出现，故 '->' 是可靠的嵌套分隔符。
    $arrow = $p.IndexOf('->')
    if ($arrow -ge 0) { $p = $p.Substring(0, $arrow) }
    $semi = $p.IndexOf(';')
    if ($semi -ge 0) { $p = $p.Substring(0, $semi) }
    $p = $p.Trim()
    # 截到第一个盘符（如 E:\）为止，去掉 file: / containerfile: / 下划线等前缀杂质；
    # UNC(\\server\..) 与无盘符路径不含 [A-Za-z]:\ 模式，保持原样。
    $m = [regex]::Match($p, '[A-Za-z]:[\\/]')
    if ($m.Success -and $m.Index -gt 0) { $p = $p.Substring($m.Index) }
    return $p
}

function Get-SafeFileName {
    param([string]$P)
    if (-not $P) { return '' }
    # 不用 [System.IO.Path]::GetFileName：Defender 事件 Path 偶带非法字符
    # (< > | " ? * 及控制字符)，GetFileName 在 .NET Framework 下会抛
    # "Illegal characters in path" 而中断整次采集。这里手动取叶子名并剔除非法字符。
    $name = $P
    $idx = $name.LastIndexOfAny([char[]]@('\', '/'))
    if ($idx -ge 0) { $name = $name.Substring($idx + 1) }
    foreach ($c in [System.IO.Path]::GetInvalidFileNameChars()) {
        $name = $name.Replace([string]$c, '')
    }
    return $name.Trim()
}

try {
    $maxRecordId = $SinceRecordId
    $events = @()
    # 相位计时与计数器先初始化，保证日志不存在(未装 Defender)时输出结构依然完整
    $swFetch = [System.Diagnostics.Stopwatch]::StartNew(); $swFetch.Stop()
    $swParse = [System.Diagnostics.Stopwatch]::StartNew(); $swParse.Stop()
    $swHash = [System.Diagnostics.Stopwatch]::StartNew(); $swHash.Stop()
    $fetchedCount = 0; $hashedFiles = 0; $hashedBytes = [long]0
    $skippedOversize = 0; $skippedBudget = 0

    # 日志不存在（未装 Defender 等）→ 返回空事件，不视为错误
    $logExists = $true
    try { $null = Get-WinEvent -ListLog $LogName -ErrorAction Stop }
    catch { $logExists = $false }

    if ($logExists) {
        $raw = @()
        $swFetch = [System.Diagnostics.Stopwatch]::StartNew()
        # 把 "RecordId > 水位" 下推到日志查询引擎（FilterXPath 的 EventRecordID），
        # 避免每次都用 FilterHashtable 全量拉取整段 1116-1119 历史再在内存里过滤。
        # 首次(水位=0)仍需拉全量，但之后每次只取新增，fetch 成本随水位推进而收敛。
        $idClause = ($EventIds | ForEach-Object { "EventID=$_" }) -join ' or '
        $xpath = "*[System[($idClause) and (EventRecordID > $SinceRecordId)]]"
        try {
            $raw = @(Get-WinEvent -LogName $LogName -FilterXPath $xpath -ErrorAction Stop)
        }
        catch {
            # XPath 不支持/查询失败 → 回退到 FilterHashtable（功能等价，只是不下推水位）
            try {
                $raw = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $EventIds } -ErrorAction Stop)
            }
            catch { $raw = @() }  # "No events were found" 属正常
        }
        $swFetch.Stop()
        $fetchedCount = @($raw).Count

        # 断点续采：RecordId > 水位，升序取前 MaxEvents 条
        $batch = @($raw | Where-Object { $_.RecordId -gt $SinceRecordId } |
                   Sort-Object RecordId | Select-Object -First $MaxEvents)

        # 解析 EventData 为 Name→Text 哈希
        $swParse = [System.Diagnostics.Stopwatch]::StartNew()
        $parsed = @()
        foreach ($e in $batch) {
            if ($e.RecordId -gt $maxRecordId) { $maxRecordId = $e.RecordId }
            [xml]$xml = $e.ToXml()
            $map = @{}
            $resources = @()
            foreach ($d in @($xml.Event.EventData.Data)) {
                $name = $d.GetAttribute('Name')
                $val = $d.InnerText
                if (-not $name) { continue }
                if ($name -eq 'Resources') {
                    if ($val) { $resources += ($val -split "[\r\n;]+" | Where-Object { $_ }) }
                }
                else { $map[$name] = $val }
            }
            $parsed += [pscustomobject]@{
                RecordId    = $e.RecordId
                Id          = $e.Id
                TimeCreated = $e.TimeCreated
                Map         = $map
                Resources   = $resources
            }
        }

        # 以 Detection ID 为键合并 1116/1117/1118/1119
        $merged = [ordered]@{}
        foreach ($p in $parsed) {
            $detectionId = Get-Field $p.Map @('Detection ID')
            $threatId = Get-Field $p.Map @('Threat ID', 'ThreatID')
            # 原始资源链（含压缩包嵌套 ;file:_...->...）留档；original_path 只取最外层磁盘容器。
            $rawPath = Get-Field $p.Map @('Path')
            if (-not $rawPath -and $p.Resources.Count -gt 0) { $rawPath = $p.Resources[0] }
            $path = Clean-ResourcePath $rawPath
            $key = if ($detectionId) { $detectionId } else { "$threatId|$path|$($p.RecordId)" }

            if (-not $merged.Contains($key)) {
                $merged[$key] = [pscustomobject]@{
                    record_id     = $p.RecordId
                    detection_id  = $detectionId
                    detected_at   = $p.TimeCreated.ToString('o')
                    threat_id     = $threatId
                    threat_name   = Get-Field $p.Map @('Threat Name', 'ThreatName')
                    original_path = $path
                    resource_path = $rawPath
                    file_name     = Get-SafeFileName $path
                    process_name  = Get-Field $p.Map @('Process Name', 'ProcessName')
                    severity      = Resolve-Res (Get-Field $p.Map @('Severity Name', 'Severity'))
                    category      = Resolve-Res (Get-Field $p.Map @('Category Name', 'Category'))
                    threat_type   = Resolve-Res (Get-Field $p.Map @('Category Name', 'Category', 'Type Name'))
                    action_taken  = ''
                    detection_source = 'eventlog'
                }
            }
            else {
                # 保留更早（检出）事件的 RecordId 作为代表
                if ($p.RecordId -lt $merged[$key].record_id) { $merged[$key].record_id = $p.RecordId }
                if (-not $merged[$key].detected_at) { $merged[$key].detected_at = $p.TimeCreated.ToString('o') }
            }

            # 处置结果来自 1117（成功）/1118,1119（失败）
            if ($p.Id -eq 1117 -or $p.Id -eq 1118 -or $p.Id -eq 1119) {
                # Action Name 常是未渲染的资源引用（%%809=Quarantine），先就地还原；
                # 若仍是未收录的 %%NNN 或本就为空，回退到数值 Action ID → $ActionMap。
                $actName = Resolve-Res (Get-Field $p.Map @('Action Name', 'Action'))
                if (-not $actName -or $actName -match '^%%\d+$') {
                    $actId = Get-Field $p.Map @('Action ID', 'ActionID')
                    if ($actId -and $ActionMap.ContainsKey("$actId")) { $actName = $ActionMap["$actId"] }
                    elseif ($actId) { $actName = $actId }
                }
                if ($p.Id -ne 1117 -and $actName) { $actName = "$actName (Failed)" }
                elseif ($p.Id -ne 1117 -and -not $actName) { $actName = 'Failed' }
                if ($actName) { $merged[$key].action_taken = $actName }
                # 补齐可能只在 1117 出现的字段
                if (-not $merged[$key].threat_name) { $merged[$key].threat_name = Get-Field $p.Map @('Threat Name', 'ThreatName') }
                if (-not $merged[$key].severity) { $merged[$key].severity = Resolve-Res (Get-Field $p.Map @('Severity Name', 'Severity')) }
                if (-not $merged[$key].category) { $merged[$key].category = Resolve-Res (Get-Field $p.Map @('Category Name', 'Category')) }
                if (-not $merged[$key].threat_type) { $merged[$key].threat_type = Resolve-Res (Get-Field $p.Map @('Category Name', 'Category', 'Type Name')) }
                if (-not $merged[$key].original_path) {
                    $rp = Get-Field $p.Map @('Path')
                    if (-not $rp -and $p.Resources.Count -gt 0) { $rp = $p.Resources[0] }
                    $pp = Clean-ResourcePath $rp
                    $merged[$key].original_path = $pp
                    if ($pp) { $merged[$key].file_name = Get-SafeFileName $pp }
                    if (-not $merged[$key].resource_path -and $rp) { $merged[$key].resource_path = $rp }
                }
            }
        }
        $swParse.Stop()

        # 对仍存在的原始文件安全计算 SHA256 与大小——带预算，避免大文件拖垮整批。
        # 三重上限：单文件字节(MaxHashBytes) / 本批文件数(MaxHashFiles) / 本批累计字节
        # (MaxHashTotalBytes)。超限文件跳过哈希但仍记录该检出(file_size + hash_skipped)，
        # 绝不丢事件。同一路径哈希结果缓存复用，避免重复读盘。
        $swHash = [System.Diagnostics.Stopwatch]::StartNew()
        $hashCache = @{}
        $hashedFiles = 0
        $hashedBytes = [long]0
        $skippedOversize = 0
        $skippedBudget = 0
        foreach ($key in $merged.Keys) {
            $m = $merged[$key]
            $sha = ''
            $size = $null
            $hashSkipped = ''
            $fp = $m.original_path
            if ($fp -and (Test-Path -LiteralPath $fp -ErrorAction SilentlyContinue)) {
                # 先取大小（便宜），据此判断是否值得哈希；大小取不到则按可哈希处理
                try { $size = (Get-Item -LiteralPath $fp -ErrorAction Stop).Length } catch { $size = $null }
                $cacheKey = $fp.ToLowerInvariant()
                if ($hashCache.ContainsKey($cacheKey)) {
                    $sha = $hashCache[$cacheKey]
                }
                elseif ($MaxHashBytes -gt 0 -and $size -ne $null -and $size -gt $MaxHashBytes) {
                    $hashSkipped = 'oversize'; $skippedOversize++
                }
                elseif ($MaxHashFiles -gt 0 -and $hashedFiles -ge $MaxHashFiles) {
                    $hashSkipped = 'budget_files'; $skippedBudget++
                }
                elseif ($MaxHashTotalBytes -gt 0 -and $size -ne $null -and ($hashedBytes + $size) -gt $MaxHashTotalBytes) {
                    $hashSkipped = 'budget_bytes'; $skippedBudget++
                }
                else {
                    try {
                        $h = Get-FileHash -LiteralPath $fp -Algorithm SHA256 -ErrorAction Stop
                        $sha = $h.Hash.ToLower()
                        $hashCache[$cacheKey] = $sha
                        $hashedFiles++
                        if ($size -ne $null) { $hashedBytes += $size }
                    }
                    catch { $sha = '' }
                }
            }
            $events += [pscustomobject]@{
                record_id     = $m.record_id
                detection_id  = $m.detection_id
                detected_at   = $m.detected_at
                threat_id     = $m.threat_id
                threat_name   = $m.threat_name
                original_path = $m.original_path
                resource_path = $m.resource_path
                file_name     = $m.file_name
                file_size     = $size
                sha256        = $sha
                hash_skipped  = $hashSkipped
                severity      = $m.severity
                category      = $m.category
                threat_type   = $m.threat_type
                action_taken  = $m.action_taken
                process_name  = $m.process_name
                detection_source = $m.detection_source
            }
        }
        $swHash.Stop()
    }

    $swTotal.Stop()
    $timings = @{
        fetch_ms = $swFetch.ElapsedMilliseconds
        parse_ms = $swParse.ElapsedMilliseconds
        hash_ms  = $swHash.ElapsedMilliseconds
        total_ms = $swTotal.ElapsedMilliseconds
    }
    $hashStats = @{
        files_hashed     = $hashedFiles
        bytes_hashed     = $hashedBytes
        skipped_oversize = $skippedOversize
        skipped_budget   = $skippedBudget
    }
    $counts = @{ fetched = $fetchedCount; events = @($events).Count }
    $out = @{ ok = $true; data = @{
        events = @($events); max_record_id = $maxRecordId
        timings = $timings; hash_stats = $hashStats; counts = $counts } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
