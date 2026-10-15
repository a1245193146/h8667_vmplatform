<#
.SYNOPSIS
    最终清理：删除本系统留存到 UNC 的隔离副本（不动 Defender 内部隔离目录）。
.DESCRIPTION
    红线：
    - 只删除本系统留存的副本（-Path 指向 UNC 隔离目录下的文件），
      绝不触碰 Defender 内部隔离目录，也不删除业务原始文件；
    - 幂等：副本已不存在时同样返回 cleaned=true。
    删除文件后，若其所在的"事件ID"目录已空，则一并清理该空目录（best-effort）。
    输出单行 JSON:
      {"ok":true,"data":{"cleaned":bool,"path":"...","note":"..."}}
.PARAMETER Path
    本系统留存的隔离副本路径（UNC）。
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Av-CleanupFile.ps1 -Path \\fs\AV-Quarantine\2026\09\22\1\a.exe
.AUTHOR
    AUTO-GENERATED (antivirus automation module)
#>
param(
    [string]$ParamsFile = '',
    [string]$Path = ''
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
        if ($p.PSObject.Properties['Path']) { $Path = [string]$p.Path }
    }
    catch { Emit-Error ("ParamsFile 解析失败: " + [string]$_.Exception.Message); return }
}

try {
    if ([string]::IsNullOrWhiteSpace($Path)) { Emit-Error 'Path 不能为空'; return }
    $note = ''
    if (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    else {
        $note = 'already gone'
    }

    # 事件目录若已空则清理（best-effort，不影响主结果）
    try {
        $dir = Split-Path -Path $Path -Parent
        if ($dir -and (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue)) {
            $remaining = @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)
            if ($remaining.Count -eq 0) { Remove-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue }
        }
    }
    catch { }

    $out = @{ ok = $true; data = @{ cleaned = $true; path = $Path; note = $note } }
    Write-Output ($out | ConvertTo-Json -Compress -Depth 6)
}
catch {
    $err = @{ ok = $false; error = [string]$_.Exception.Message }
    Write-Output ($err | ConvertTo-Json -Compress -Depth 6)
}
