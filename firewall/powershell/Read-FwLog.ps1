<#
.SYNOPSIS
    增量读取 Windows 防火墙日志 pfirewall.log 的尾部内容。
.DESCRIPTION
    用 FileStream Seek 到 -Offset 位置，最多读 -MaxBytes 字节（日志可能很大，绝不整文件加载），
    最多解析出 -MaxLines 条事件。解析以空格分隔的行（跳过 # 注释头）。
    pfirewall.log 标准字段顺序: date time action protocol src-ip dst-ip src-port dst-port ...
    若 -Offset 大于当前文件长度，说明日志已轮转，从 0 重读。
    文件不存在/为空 -> log_exists=false、events=[]，不报错。

    偏移只推进到"本次真正消费掉的最后一行之后"，绝不直接跳到文件尾。
    这一点是硬要求：旧实现读到 MaxLines 就 break，却把 offset 设成文件长度，
    中间没读到的行永远不会再被读到，等于静默丢事件，页面上还看不出来。
    现在没读完的部分留给下一次采集，并在 JSON 里用 truncated / skipped_bytes 明确披露。
    partial_tail=true 表示文件尾有一行还没写完，本次扣住没采，等下次写完整再采。
    oversized_skipped=true 表示碰到一整块没有换行符的内容（不是正常日志行），
    已跳过并继续推进偏移——宁可丢一块垃圾，也绝不让偏移卡死导致这台机永久停采。

    红线：只用 FileStream 只读打开，绝不清除/改写/截断/轮转任何日志。

    输出单行 JSON:
    {"ok":true,"data":{"log_exists":bool,"offset":<新偏移>,"events":[{time,action,protocol,src_ip,src_port,dst_ip,dst_port}],
     "truncated":bool,"partial_tail":bool,"oversized_skipped":bool,"skipped_bytes":<本次未读、留给下次的字节数>,"events_returned":int}}
.PARAMETER Offset
    上次读取的文件偏移（字节），首次传 0。
.PARAMETER MaxLines
    本次最多返回的事件行数，默认 2000。超出的部分不丢弃，留给下一次采集。
.PARAMETER MaxBytes
    本次最多读取的字节数，默认 8MB。用于给首次采集（Offset=0）和历史日志很大的机器封顶耗时。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Read-FwLog.ps1 -Offset 0 -MaxLines 2000
    => {"ok":true,"data":{"log_exists":true,"offset":123456,"events":[{"time":"2025-01-01 12:00:00","action":"DROP","protocol":"TCP","src_ip":"1.2.3.4","src_port":"5000","dst_ip":"10.0.0.5","dst_port":"445"}],"truncated":false,"partial_tail":false,"oversized_skipped":false,"skipped_bytes":0,"events_returned":1}}
.AUTHOR
    AUTO-GENERATED (Agent B - firewall automation module)
#>
param(
    [Parameter(Mandatory = $false)]
    [long]$Offset = 0,

    [Parameter(Mandatory = $false)]
    [int]$MaxLines = 2000,

    [Parameter(Mandatory = $false)]
    [long]$MaxBytes = 8388608
)

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

function Write-Result($data) {
    Write-Output (@{ ok = $true; data = $data } | ConvertTo-Json -Compress -Depth 6)
}

try {
    $logPath = Join-Path $env:windir 'system32\LogFiles\Firewall\pfirewall.log'

    if (-not (Test-Path -Path $logPath -PathType Leaf)) {
        Write-Result @{ log_exists = $false; offset = 0; events = @();
                        truncated = $false; partial_tail = $false; oversized_skipped = $false;
                        skipped_bytes = 0; events_returned = 0 }
        exit 0
    }

    $fileLen = (Get-Item -Path $logPath).Length
    if ($fileLen -le 0) {
        Write-Result @{ log_exists = $false; offset = 0; events = @();
                        truncated = $false; partial_tail = $false; oversized_skipped = $false;
                        skipped_bytes = 0; events_returned = 0 }
        exit 0
    }

    # 偏移超过文件尾 -> 日志轮转，从 0 重读
    $startOffset = $Offset
    if ($startOffset -lt 0 -or $startOffset -gt $fileLen) { $startOffset = 0 }

    $remaining = $fileLen - $startOffset
    if ($MaxBytes -lt 1024) { $MaxBytes = 1024 }
    $take = [Math]::Min([long]$MaxBytes, [long]$remaining)

    $events = @()
    $consumed = [long]0      # 本次真正消费掉的字节数，新偏移 = startOffset + consumed
    $truncated = $false      # 还有内容没读完（留给下一次采集），必须如实披露
    $partialTail = $false    # 文件尾有一行还没写完，本次没消费它
    $fs = $null
    try {
        $fs = New-Object System.IO.FileStream($logPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        [void]$fs.Seek($startOffset, [System.IO.SeekOrigin]::Begin)
        $buf = New-Object byte[] $take
        $read = 0
        while ($read -lt $take) {
            $n = $fs.Read($buf, $read, [int]($take - $read))
            if ($n -le 0) { break }
            $read += $n
        }
    }
    finally {
        if ($null -ne $fs) { $fs.Close() }
    }

    $text = [System.Text.Encoding]::UTF8.GetString($buf, 0, $read)

    # 按 MaxBytes 截断时，末尾很可能是半行。退到最后一个换行符，
    # 半行留给下次读，避免解析出残缺事件、也避免把偏移停在多字节字符中间。
    if ($read -lt $remaining) {
        $lastNl = $text.LastIndexOf("`n")
        if ($lastNl -lt 0) {
            # 整块里一个换行符都没有：这不是防火墙日志的正常行，硬解析只会得到垃圾。
            # 必须把这一块消费掉继续往前走——偏移卡在同一位置会让这台机永久停采，
            # 那比丢一块垃圾内容严重得多。用 oversized_skipped 如实报出来。
            $skipTo = $startOffset + $read
            Write-Result @{ log_exists = $true; offset = $skipTo; events = @();
                            truncated = ($skipTo -lt $fileLen); partial_tail = $false;
                            oversized_skipped = $true;
                            skipped_bytes = [long]($fileLen - $skipTo);
                            events_returned = 0 }
            exit 0
        }
        $text = $text.Substring(0, $lastNl + 1)
        $truncated = $true
    }
    elseif ($text -ne '' -and -not $text.EndsWith("`n")) {
        # 读到文件尾但最后一行没有换行符：防火墙可能正写到一半。
        # 这一行本次不消费、偏移不推进，等下次写完整了再采，避免解析出半条事件。
        $lastNl = $text.LastIndexOf("`n")
        if ($lastNl -lt 0) { $text = '' } else { $text = $text.Substring(0, $lastNl + 1) }
        $partialTail = $true
    }

    # 保留换行符切片，逐片累加真实字节数，这样偏移永远精确到行边界。
    $pieces = [regex]::Split($text, "(?<=`n)")
    foreach ($piece in $pieces) {
        if ($piece -eq '') { continue }
        $pieceBytes = [long][System.Text.Encoding]::UTF8.GetByteCount($piece)

        $line = $piece.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) {
            $consumed += $pieceBytes
            continue
        }

        # 够了就停在这里：偏移不推进到这一行，未读部分下次接着采，绝不丢事件
        if ($events.Count -ge $MaxLines) {
            $truncated = $true
            break
        }

        # 字段: date time action protocol src-ip dst-ip src-port dst-port ...
        $f = $line -split '\s+'
        if ($f.Count -ge 8) {
            $events += @{
                time     = ('{0} {1}' -f $f[0], $f[1])
                action   = [string]$f[2]
                protocol = [string]$f[3]
                src_ip   = [string]$f[4]
                dst_ip   = [string]$f[5]
                src_port = [string]$f[6]
                dst_port = [string]$f[7]
            }
        }
        $consumed += $pieceBytes
    }

    $newOffset = $startOffset + $consumed
    if ($newOffset -gt $fileLen) { $newOffset = $fileLen }
    # 只有"整行没读完"才算 truncated；尾部半行单独用 partial_tail 报，
    # 否则一台安静的机器会因为最后一行没换行符而永远显示"未读完"。
    if ($newOffset -lt $fileLen -and -not $partialTail) { $truncated = $true }

    Write-Result @{ log_exists = $true; offset = $newOffset; events = $events;
                    truncated = $truncated; partial_tail = $partialTail; oversized_skipped = $false;
                    skipped_bytes = [long]($fileLen - $newOffset);
                    events_returned = $events.Count }
    exit 0
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
