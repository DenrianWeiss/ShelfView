#requires -Version 5.1
<#
.SYNOPSIS
    创建仅用于本机开发/测试的代码签名证书。

.DESCRIPTION
    证书保存在 CurrentUser\My，私钥默认不可导出；公钥证书导出到 .signing/
    供 signtool 验证与安装信任使用。私钥、公钥证书和元数据都不会进入 Git。

    如需让本机 Code Integrity / Smart App Control 信任该证书，请使用
    -Trust CurrentUser（当前用户）或 -Trust LocalMachine（需要管理员）。

.EXAMPLE
    .\New-DevCodeSigningCert.ps1 -Trust CurrentUser

.EXAMPLE
    .\New-DevCodeSigningCert.ps1 -Force -Trust LocalMachine
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$Subject = 'CN=bControl Local Development Code Signing',
    [int]$ValidYears = 3,
    [switch]$Force,
    [ValidateSet('None', 'CurrentUser', 'LocalMachine')]
    [string]$Trust = 'None',
    [switch]$ExportPfx,
    [string]$PfxPassword
)

$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw '代码签名证书只能在 Windows 上创建。'
}

if ($Trust -eq 'LocalMachine') {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw 'Trust=LocalMachine 需要管理员权限。请以管理员身份运行，或使用 -Trust CurrentUser。'
    }
}

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $PSScriptRoot '..\..\.signing'
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory

$baseName = 'bcontrol-dev-codesign'
$cerPath = Join-Path $OutputDirectory "$baseName.cer"
$jsonPath = Join-Path $OutputDirectory "$baseName.json"
$pfxPath = Join-Path $OutputDirectory "$baseName.pfx"

function Read-Metadata {
    if (-not (Test-Path -LiteralPath $jsonPath)) {
        return $null
    }
    try {
        return (Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json)
    } catch {
        Write-Warning "忽略无法解析的证书元数据: $jsonPath"
        return $null
    }
}

$metadata = Read-Metadata
$cert = $null

if (-not $Force) {
    if ($metadata -and $metadata.thumbprint) {
        $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $metadata.thumbprint } |
            Select-Object -First 1
    }
    if (-not $cert) {
        $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1
    }
}

if ($Force -and $metadata -and $metadata.thumbprint) {
    $oldThumbprint = [string]$metadata.thumbprint
    $certutil = Join-Path $env:SystemRoot 'System32\certutil.exe'
    foreach ($storeName in @('My', 'Root', 'TrustedPublisher')) {
        $storePath = "Cert:\CurrentUser\$storeName"
        $existing = @(Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $oldThumbprint })
        if ($existing.Count -eq 0) {
            continue
        }
        $output = & $certutil '-delstore' '-user' $storeName $oldThumbprint 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "无法从 CurrentUser\$storeName 移除旧证书 ${oldThumbprint}: $($output -join ' ')"
        }
    }
}

if (-not $cert) {
    if ($ValidYears -lt 1 -or $ValidYears -gt 10) {
        throw 'ValidYears 必须在 1 到 10 之间。'
    }
    if (-not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
        throw '找不到 New-SelfSignedCertificate；请使用 Windows PowerShell 5.1 (powershell.exe) 运行。'
    }

    $keyExportPolicy = 'NonExportable'
    if ($ExportPfx) {
        $keyExportPolicy = 'Exportable'
    }

    Write-Host "创建代码签名证书: $Subject"
    $cert = New-SelfSignedCertificate `
        -Subject $Subject `
        -FriendlyName 'bControl Local Development Code Signing' `
        -Type CodeSigningCert `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeySpec Signature `
        -KeyExportPolicy $keyExportPolicy `
        -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddYears($ValidYears) `
        -CertStoreLocation 'Cert:\CurrentUser\My'
} else {
    Write-Host "复用已有代码签名证书: $($cert.Thumbprint)"
}

Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT -Force | Out-Null

if ($ExportPfx) {
    if (-not $PfxPassword) {
        $bytes = New-Object byte[] 24
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $rng.GetBytes($bytes)
        } finally {
            $rng.Dispose()
        }
        $PfxPassword = [Convert]::ToBase64String($bytes)
        $passwordPath = Join-Path $OutputDirectory "$baseName.password.txt"
        [IO.File]::WriteAllText($passwordPath, $PfxPassword + [Environment]::NewLine,
            (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "PFX 密码已写入: $passwordPath"
    }
    $securePassword = ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force
    try {
        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePassword -Force | Out-Null
    } catch {
        throw "无法导出 PFX（当前证书私钥可能不可导出）。请使用 -Force -ExportPfx 重新创建。$($_.Exception.Message)"
    }
    Write-Host "PFX 已导出: $pfxPath"
}

$metadata = [ordered]@{
    subject      = $cert.Subject
    friendlyName = $cert.FriendlyName
    thumbprint   = $cert.Thumbprint
    notBefore    = $cert.NotBefore.ToUniversalTime().ToString('o')
    notAfter     = $cert.NotAfter.ToUniversalTime().ToString('o')
    store        = 'Cert:\CurrentUser\My'
    certificate  = [IO.Path]::GetFileName($cerPath)
    created      = (Get-Date).ToUniversalTime().ToString('o')
}
$json = $metadata | ConvertTo-Json
[IO.File]::WriteAllText($jsonPath, $json + [Environment]::NewLine,
    (New-Object System.Text.UTF8Encoding($false)))

Write-Host "公钥证书: $cerPath"
Write-Host "元数据:   $jsonPath"
Write-Host "指纹:     $($cert.Thumbprint)"
Write-Host "有效期至: $($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))"

if ($Trust -ne 'None') {
    & (Join-Path $PSScriptRoot 'Trust-DevCodeSigningCert.ps1') `
        -Scope $Trust `
        -MetadataPath $jsonPath
}
