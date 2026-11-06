#requires -Version 5.1
<#
.SYNOPSIS
    使用本地开发证书为目录或文件中的 PE 产物添加 Authenticode 签名。

.DESCRIPTION
    默认只签名没有有效签名的 .exe/.dll，避免覆盖第三方或系统已有的有效签名。
    证书默认从 .signing/bcontrol-dev-codesign.json 读取指纹，也可以显式传 -Thumbprint。

    本地开发证书没有可信时间戳；证书过期后需要重新签名。需要时间戳时可传
    -TimestampUrl，例如 http://timestamp.digicert.com（需要网络）。

.EXAMPLE
    .\Sign-Artifacts.ps1 -Path ..\..\frontends\desktop\src\BControl.Desktop\bin\Debug\net10.0 -Recurse

.EXAMPLE
    .\Sign-Artifacts.ps1 -Path ..\..\build-windows-desktop\Release -Recurse -TimestampUrl http://timestamp.digicert.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$Path,
    [string]$Thumbprint,
    [string]$MetadataPath,
    [switch]$Recurse,
    [switch]$Force,
    [string]$TimestampUrl,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

if (-not $MetadataPath) {
    $MetadataPath = Join-Path $PSScriptRoot '..\..\.signing\bcontrol-dev-codesign.json'
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Authenticode 签名只能在 Windows 上执行。'
}

function Get-SignToolPath {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $roots = @()
    if (${env:ProgramFiles(x86)}) {
        $roots += (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin')
    }
    if ($env:ProgramFiles) {
        $roots += (Join-Path $env:ProgramFiles 'Windows Kits\10\bin')
    }

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }
        $versions = Get-ChildItem -LiteralPath $root -Directory | Sort-Object Name -Descending
        foreach ($version in $versions) {
            foreach ($arch in @('x64', 'x86', 'arm64')) {
                $candidate = Join-Path $version.FullName "$arch\signtool.exe"
                if (Test-Path -LiteralPath $candidate) {
                    return $candidate
                }
            }
        }
    }

    throw '找不到 signtool.exe。请安装 Windows SDK，或把 signtool.exe 加入 PATH。'
}

function Test-PeFile {
    param([string]$FilePath)
    try {
        $stream = [IO.File]::Open($FilePath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite)
        try {
            $reader = New-Object IO.BinaryReader($stream)
            return ($reader.ReadUInt16() -eq 0x5A4D)
        } finally {
            $stream.Dispose()
        }
    } catch {
        return $false
    }
}

if (-not $Thumbprint) {
    if (-not (Test-Path -LiteralPath $MetadataPath)) {
        throw "未指定 -Thumbprint，且找不到证书元数据: $MetadataPath。请先运行 New-DevCodeSigningCert.ps1。"
    }
    $metadata = Get-Content -LiteralPath $MetadataPath -Raw | ConvertFrom-Json
    $Thumbprint = [string]$metadata.thumbprint
}

if (-not $Thumbprint) {
    throw "证书元数据中没有 thumbprint: $MetadataPath"
}
$Thumbprint = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $Thumbprint } |
    Select-Object -First 1
$useMachineStore = $false
if (-not $cert) {
    $cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumbprint } |
        Select-Object -First 1
    if ($cert) {
        $useMachineStore = $true
    }
}

if (-not $cert) {
    throw "找不到代码签名证书 $Thumbprint。请先运行 New-DevCodeSigningCert.ps1。"
}
if (-not $cert.HasPrivateKey) {
    throw "证书 $Thumbprint 没有可用的私钥。"
}

$signtool = Get-SignToolPath

$files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
foreach ($item in $Path) {
    if (Test-Path -LiteralPath $item -PathType Container) {
        Get-ChildItem -LiteralPath $item -File -Recurse:$Recurse |
            Where-Object { $_.Extension -eq '.exe' -or $_.Extension -eq '.dll' } |
            ForEach-Object { $files.Add($_) }
    } elseif (Test-Path -LiteralPath $item -PathType Leaf) {
        $files.Add((Get-Item -LiteralPath $item))
    } else {
        throw "路径不存在: $item"
    }
}

$files = @($files | Sort-Object FullName -Unique)
if ($files.Count -eq 0) {
    Write-Warning '没有找到 .exe/.dll 文件。'
    return
}

$signedCount = 0
$skippedCount = 0
$untrustedCount = 0
$failureCount = 0

foreach ($file in $files) {
    if (-not (Test-PeFile -FilePath $file.FullName)) {
        continue
    }

    if (-not $Force) {
        try {
            $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
            if ($signature.Status -eq 'Valid') {
                $skippedCount++
                if (-not $Quiet) {
                    Write-Verbose "已跳过（已有有效签名）: $($file.FullName)"
                }
                continue
            }
        } catch {
            # 读取签名失败时按未签名处理。
        }
    }

    $arguments = @('sign', '/sha1', $Thumbprint, '/fd', 'SHA256')
    if ($useMachineStore) {
        $arguments += '/sm'
    }
    if ($TimestampUrl) {
        $arguments += @('/tr', $TimestampUrl, '/td', 'SHA256')
    }
    $arguments += $file.FullName

    $output = & $signtool @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $failureCount++
        Write-Warning "签名失败: $($file.FullName)`n$($output -join [Environment]::NewLine)"
        continue
    }

    $signedCount++
    if (-not $Quiet) {
        Write-Host "已签名: $($file.FullName)"
    }

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        if ($signature.Status -ne 'Valid') {
            $untrustedCount++
        }
    } catch {
        $untrustedCount++
    }
}

$summary = "完成: 新签名 $signedCount，跳过 $skippedCount，失败 $failureCount"
if ($untrustedCount -gt 0) {
    $summary += "；$untrustedCount 个文件的证书链尚未受信任（安装 Root/TrustedPublisher 后可消除）"
}
Write-Host $summary

if ($failureCount -gt 0) {
    throw "有 $failureCount 个文件签名失败。"
}
