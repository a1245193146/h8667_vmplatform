<#
.SYNOPSIS
    增量读取 Windows 防火墙日志 pfirewall.log 的尾部内容。
.DESCRIPTION
    用 FileStream Seek 到 -Offset 位置读取（日志可能很大，绝不整文件加载），
    最多解析 -MaxLines 行。解析以空格分隔的行（跳过 # 注释头）。
    pfirewall.log 标准字段顺序: date time action protocol src-ip dst-ip src-port dst-port ...
    若 -Offset 大于当前文件长度，说明日志已轮转，从 0 重读。
    文件不存在/为空 -> log_exists=false、events=[]，不报错。
    输出单行 JSON: {"ok":true,"data":{"log_exists":bool,"offset":<新偏移=当前文件长度>,"events":[{time,action,protocol,src_ip,src_port,dst_ip,dst_port}]}}
.PARAMETER Offset
    上次读取的文件偏移（字节），首次传 0。
.PARAMETER MaxLines
    本次最多返回的事件行数，默认 2000。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Read-FwLog.ps1 -Offset 0 -MaxLines 2000
    => {"ok":true,"data":{"log_exists":true,"offset":123456,"events":[{"time":"2025-01-01 12:00:00","action":"DROP","protocol":"TCP","src_ip":"1.2.3.4","src_port":"5000","dst_ip":"10.0.0.5","dst_port":"445"}]}}
.AUTHOR
    AUTO-GENERATED (Agent B - firewall automation module)
#>
param(
    [Parameter(Mandatory = $false)]
    [long]$Offset = 0,

    [Parameter(Mandatory = $false)]
    [int]$MaxLines = 2000
)

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

try {
    $logPath = Join-Path $env:windir 'system32\LogFiles\Firewall\pfirewall.log'

    if (-not (Test-Path -Path $logPath -PathType Leaf)) {
        $out = @{ ok = $true; data = @{ log_exists = $false; offset = 0; events = @() } }
        Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
        exit 0
    }

    $fileLen = (Get-Item -Path $logPath).Length
    if ($fileLen -le 0) {
        $out = @{ ok = $true; data = @{ log_exists = $false; offset = 0; events = @() } }
        Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
        exit 0
    }

    # 偏移超过文件尾 -> 日志轮转，从 0 重读
    $startOffset = $Offset
    if ($startOffset -lt 0 -or $startOffset -gt $fileLen) { $startOffset = 0 }

    $events = @()
    $fs = $null; $sr = $null
    try {
        $fs = New-Object System.IO.FileStream($logPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        [void]$fs.Seek($startOffset, [System.IO.SeekOrigin]::Begin)
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)

        $lineCount = 0
        while (($line = $sr.ReadLine()) -ne $null) {
            if ($lineCount -ge $MaxLines) { break }
            $line = $line.Trim()
            if ($line -eq '' -or $line.StartsWith('#')) { continue }

            # 字段: date time action protocol src-ip dst-ip src-port dst-port ...
            $f = $line -split '\s+'
            if ($f.Count -lt 8) { continue }

            $time = ('{0} {1}' -f $f[0], $f[1])
            $events += @{
                time     = $time
                action   = [string]$f[2]
                protocol = [string]$f[3]
                src_ip   = [string]$f[4]
                dst_ip   = [string]$f[5]
                src_port = [string]$f[6]
                dst_port = [string]$f[7]
            }
            $lineCount++
        }
    }
    finally {
        if ($null -ne $sr) { $sr.Close() }
        if ($null -ne $fs) { $fs.Close() }
    }

    # 新偏移 = 当前文件长度
    $newOffset = (Get-Item -Path $logPath).Length

    $out = @{ ok = $true; data = @{ log_exists = $true; offset = $newOffset; events = $events } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
