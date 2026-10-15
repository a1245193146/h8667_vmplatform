<#
.SYNOPSIS
    把检出的病毒文件从原始路径安全转存到指定 UNC 隔离目录（证据留存）。
.DESCRIPTION
    红线：
    - 不触碰 Defender 内部隔离目录，只从"原始文件路径"复制（若文件已被 Defender
      清除则 source_exists=false，调用方据此标记"原文件不可得"）；
    - 目标目录按"日期/事件ID"由调用方传入（如 \\fs\AV-Quarantine\2026\09\22\123）；
    - 复制后对目标目录施加严格 NTFS 权限（去除继承，仅授予 Administrators 与 SYSTEM），
      确保普通用户无法访问（共享级权限由基础设施侧另行配置）。
    计算并回传 SHA256 与文件大小（对留存副本取值，保证与存档一致）。
    输出单行 JSON:
      {"ok":true,"data":{"source_exists":bool,"preserved_path":"...","sha256":"...","file_size":N}}
.PARAMETER SourcePath
    检出文件的原始路径（本机或 UNC）。
.PARAMETER DestDir
    隔离目标目录（UNC），不存在则自动创建。
.PARAMETER FileName
    留存文件名（默认取原始路径的文件名）。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Av-PreserveFile.ps1 -SourcePath C:\data\a.exe -DestDir \\fs\AV-Quarantine\2026\09\22\1 -FileName a.exe
.AUTHOR
    AUTO-GENERATED (antivirus automation module)
#>
param(
    [string]$ParamsFile = '',
    [string]$SourcePath = '',
    [string]$DestDir = '',
    [string]$FileName = ''
)

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

function Emit-Error {
    param([string]$Msg)
    Write-Output (@{ ok = $false; error = $Msg } | ConvertTo-Json -Compress -Depth 6)
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

# 参数优先从 ParamsFile(JSON) 读取：由 Ansible win_copy 写入，不经命令行拼接，
# 杜绝路径中空格/引号导致的注入与参数截断。
if ($ParamsFile -and (Test-Path -LiteralPath $ParamsFile -ErrorAction SilentlyContinue)) {
    try {
        $p = Get-Content -LiteralPath $ParamsFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($p.PSObject.Properties['SourcePath']) { $SourcePath = [string]$p.SourcePath }
        if ($p.PSObject.Properties['DestDir']) { $DestDir = [string]$p.DestDir }
        if ($p.PSObject.Properties['FileName']) { $FileName = [string]$p.FileName }
    }
    catch { Emit-Error ("ParamsFile 解析失败: " + [string]$_.Exception.Message); return }
}

try {
    # 兜底清洗：库中 original_path 可能带前缀杂质（file:/逗号/下划线等），
    # 截到第一个盘符为止，避免 Test-Path 因脏路径误判文件不存在。
    $SourcePath = Clean-ResourcePath $SourcePath
    if ([string]::IsNullOrWhiteSpace($SourcePath) -or [string]::IsNullOrWhiteSpace($DestDir)) { Emit-Error 'SourcePath / DestDir 不能为空'; return }

    # 原文件不存在（多已被 Defender 隔离/清除）：不视为错误，回传 source_exists=false
    if (-not (Test-Path -LiteralPath $SourcePath -ErrorAction SilentlyContinue)) {
        $out = @{ ok = $true; data = @{ source_exists = $false; preserved_path = ''; sha256 = ''; file_size = $null } }
        Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
        return
    }

    # 文件名安全化：仅取叶子名，杜绝路径穿越
    $leaf = if ($FileName) { [System.IO.Path]::GetFileName($FileName) } else { [System.IO.Path]::GetFileName($SourcePath) }
    if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = 'quarantine.bin' }

    # 创建目标目录（UNC 亦可）
    if (-not (Test-Path -LiteralPath $DestDir -ErrorAction SilentlyContinue)) {
        $null = New-Item -ItemType Directory -Force -Path $DestDir -ErrorAction Stop
    }
    $destPath = Join-Path $DestDir $leaf

    # 复制留存（-Force 覆盖同名旧副本）
    Copy-Item -LiteralPath $SourcePath -Destination $destPath -Force -ErrorAction Stop

    # 对留存副本计算 SHA256 与大小
    $sha = ''
    $size = $null
    try {
        $h = Get-FileHash -LiteralPath $destPath -Algorithm SHA256 -ErrorAction Stop
        $sha = $h.Hash.ToLower()
        $size = (Get-Item -LiteralPath $destPath -ErrorAction Stop).Length
    }
    catch { }

    # 严格 NTFS 权限：去除继承，仅授予 Administrators 与 SYSTEM（best-effort，不影响留存结果）
    try {
        $null = icacls $DestDir /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" 2>&1
    }
    catch { }

    $out = @{ ok = $true; data = @{ source_exists = $true; preserved_path = $destPath; sha256 = $sha; file_size = $size } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    Emit-Error ([string]$_.Exception.Message)
}
