#requires -Version 5.1
<#
.SYNOPSIS
    为当前工作区常见的 Windows 构建输出签名。

.DESCRIPTION
    覆盖 CMake 的 build-windows-desktop（Release/Debug）以及
    frontends/desktop 下所有 net10.0 输出目录。frontends/desktop 的构建也会
    通过 Directory.Build.targets 自动签名；此脚本用于补签原生构建目录或手动重签。

.EXAMPLE
    .\Sign-WindowsBuild.ps1
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [switch]$Force,
    [string]$TimestampUrl
)

$ErrorActionPreference = 'Stop'
if (-not $RepositoryRoot) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..\..'
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)

$targets = New-Object System.Collections.Generic.List[string]

foreach ($configuration in @('Release', 'Debug')) {
    $native = Join-Path $RepositoryRoot "build-windows-desktop\$configuration"
    if (Test-Path -LiteralPath $native) {
        $targets.Add($native)
    }
}

$desktopRoot = Join-Path $RepositoryRoot 'frontends\desktop'
if (Test-Path -LiteralPath $desktopRoot) {
    Get-ChildItem -LiteralPath $desktopRoot -Directory -Recurse -Filter 'net10.0' |
        Where-Object { $_.FullName -match '\\bin\\' } |
        ForEach-Object { $targets.Add($_.FullName) }
}

$targets = @($targets | Sort-Object -Unique)
if ($targets.Count -eq 0) {
    throw '没有找到可签名的 Windows 构建输出。'
}

$arguments = @{
    Path = $targets
    Recurse = $true
}
if ($Force) {
    $arguments.Force = $true
}
if ($TimestampUrl) {
    $arguments.TimestampUrl = $TimestampUrl
}

& (Join-Path $PSScriptRoot 'Sign-Artifacts.ps1') @arguments
