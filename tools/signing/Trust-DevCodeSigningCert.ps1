#requires -Version 5.1
<#
.SYNOPSIS
    将本地开发代码签名证书安装到 Root / TrustedPublisher 存储，或从中移除。

.DESCRIPTION
    仅安装公钥证书，私钥仍保留在 CurrentUser\My。CurrentUser 范围不需要管理员；
    LocalMachine 范围会影响整台机器，需要管理员权限。

.EXAMPLE
    .\Trust-DevCodeSigningCert.ps1 -Scope CurrentUser

.EXAMPLE
    .\Trust-DevCodeSigningCert.ps1 -Scope LocalMachine

.EXAMPLE
    .\Trust-DevCodeSigningCert.ps1 -Scope CurrentUser -Remove
#>
[CmdletBinding()]
param(
    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string]$Scope = 'CurrentUser',
    [string]$MetadataPath,
    [string]$Thumbprint,
    [string]$CertificatePath,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

if (-not $MetadataPath) {
    $MetadataPath = Join-Path $PSScriptRoot '..\..\.signing\bcontrol-dev-codesign.json'
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw '证书信任存储只能在 Windows 上修改。'
}

if ($Scope -eq 'LocalMachine') {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw 'LocalMachine 范围需要管理员权限。请以管理员身份运行，或改用 -Scope CurrentUser。'
    }
}

if (-not $Thumbprint -and (Test-Path -LiteralPath $MetadataPath)) {
    $metadata = Get-Content -LiteralPath $MetadataPath -Raw | ConvertFrom-Json
    $Thumbprint = [string]$metadata.thumbprint
    if (-not $CertificatePath -and $metadata.certificate) {
        $candidate = Join-Path (Split-Path -Parent $MetadataPath) ([string]$metadata.certificate)
        if (Test-Path -LiteralPath $candidate) {
            $CertificatePath = $candidate
        }
    }
}

if (-not $Thumbprint) {
    throw "未指定 Thumbprint，且找不到证书元数据: $MetadataPath"
}
$Thumbprint = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()

$certificate = $null
$temporaryCertificate = $null
if (-not $Remove) {
    if (-not $CertificatePath) {
        $certificate = Get-ChildItem "Cert:\$Scope\My" -CodeSigningCert -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $Thumbprint } |
            Select-Object -First 1
    } else {
        if (-not (Test-Path -LiteralPath $CertificatePath)) {
            throw "找不到公钥证书: $CertificatePath"
        }
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
    }

    if (-not $certificate) {
        throw "找不到证书 $Thumbprint。请先运行 New-DevCodeSigningCert.ps1。"
    }
    if ($certificate.Thumbprint -ne $Thumbprint) {
        throw "证书指纹不匹配: 期望 $Thumbprint，实际 $($certificate.Thumbprint)"
    }

    if (-not $CertificatePath) {
        $temporaryCertificate = Join-Path ([IO.Path]::GetTempPath()) "bcontrol-codesign-$Thumbprint.cer"
        Export-Certificate -Cert $certificate -FilePath $temporaryCertificate -Type CERT -Force | Out-Null
        $CertificatePath = $temporaryCertificate
    }
}

$certutil = Join-Path $env:SystemRoot 'System32\certutil.exe'
if (-not (Test-Path -LiteralPath $certutil)) {
    throw '找不到 certutil.exe。'
}

function Invoke-CertUtil {
    param([string[]]$Arguments)
    $output = & $certutil @Arguments 2>&1
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output   = @($output)
    }
}

foreach ($storeName in @('Root', 'TrustedPublisher')) {
    $storePath = "Cert:\$Scope\$storeName"
    $existing = @(Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumbprint })

    if ($Remove) {
        if ($existing.Count -eq 0) {
            Write-Host "证书不在 $Scope\$storeName"
            continue
        }
        $arguments = @('-delstore')
        if ($Scope -eq 'CurrentUser') {
            $arguments += '-user'
        }
        $arguments += @($storeName, $Thumbprint)
    } else {
        if ($existing.Count -gt 0) {
            Write-Host "证书已存在于 $Scope\$storeName"
            continue
        }
        $arguments = @('-addstore', '-f')
        if ($Scope -eq 'CurrentUser') {
            $arguments += '-user'
        }
        $arguments += @($storeName, $CertificatePath)
    }

    $result = Invoke-CertUtil -Arguments $arguments
    if ($result.ExitCode -ne 0) {
        throw "修改 $Scope\$storeName 失败:`n$($result.Output -join [Environment]::NewLine)"
    }

    if ($Remove) {
        Write-Host "已从 $Scope\$storeName 移除证书 $Thumbprint"
    } else {
        Write-Host "已添加证书到 $Scope\$storeName"
    }
}

if (-not $Remove) {
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $ok = $chain.Build($certificate)
    if ($ok) {
        Write-Host "证书链验证: 通过"
    } else {
        Write-Warning "证书链验证未通过（$($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() } | Select-Object -First 1)）"
    }
}

if ($temporaryCertificate) {
    Remove-Item -LiteralPath $temporaryCertificate -Force -ErrorAction SilentlyContinue
}
