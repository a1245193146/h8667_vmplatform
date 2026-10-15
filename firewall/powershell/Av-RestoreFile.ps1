<#
.SYNOPSIS
    从本系统留存的 UNC 隔离副本恢复文件到原始路径（用于误报恢复）。
.DESCRIPTION
    红线：
    - 只操作本系统留存到 UNC 的副本，绝不触碰 Defender 内部隔离目录；
    - 恢复即把留存副本写回 -DestPath（原始路径）；若 Defender 仍判定为威胁，
      可能再次被隔离，这是预期行为（本脚本不自动添加排除项）。
    输出单行 JSON:
      {"ok":true,"data":{"restored":bool,"dest_path":"...","error":"..."}}
.PARAMETER SourcePath
    本系统留存的隔离副本路径（UNC）。
.PARAMETER DestPath
    恢复目标（原始文件路径）。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Av-RestoreFile.ps1 -SourcePath \\fs\AV-Quarantine\2026\09\22\1\a.exe -DestPath C:\data\a.exe
.AUTHOR
    AUTO-GENERATED (antivirus automation module)
#>
param(
    [string]$ParamsFile = '',
    [string]$SourcePath = '',
    [string]$DestPath = ''
)

$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8

function Emit-Error {
    param([string]$Msg)
    Write-Output (@{ ok = $false; error = $Msg } | ConvertTo-Json -Compress -Depth 6)
}

# 参数优先从 ParamsFile(JSON) 读取：由 Ansible win_copy 写入，不经命令行拼接，
# 杜绝路径中空格/引号导致的注入与参数截断。
if ($ParamsFile -and (Test-Path -LiteralPath $ParamsFile -ErrorAction SilentlyContinue)) {
    try {
        $p = Get-Content -LiteralPath $ParamsFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($p.PSObject.Properties['SourcePath']) { $SourcePath = [string]$p.SourcePath }
        if ($p.PSObject.Properties['DestPath']) { $DestPath = [string]$p.DestPath }
    }
    catch { Emit-Error ("ParamsFile 解析失败: " + [string]$_.Exception.Message); return }
}

try {
    if ([string]::IsNullOrWhiteSpace($SourcePath) -or [string]::IsNullOrWhiteSpace($DestPath)) { Emit-Error 'SourcePath / DestPath 不能为空'; return }

    if (-not (Test-Path -LiteralPath $SourcePath -ErrorAction SilentlyContinue)) {
        $out = @{ ok = $true; data = @{ restored = $false; dest_path = $DestPath; error = 'preserved copy not found' } }
        Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
        return
    }

    # 确保目标父目录存在
    $parent = Split-Path -Path $DestPath -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent -ErrorAction SilentlyContinue)) {
        $null = New-Item -ItemType Directory -Force -Path $parent -ErrorAction Stop
    }

    Copy-Item -LiteralPath $SourcePath -Destination $DestPath -Force -ErrorAction Stop

    $out = @{ ok = $true; data = @{ restored = $true; dest_path = $DestPath; error = '' } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
