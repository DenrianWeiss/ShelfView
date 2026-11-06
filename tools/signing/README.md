# 本地代码签名工具

仅用于本机开发/测试。私钥保存在当前用户证书存储（`Cert:\CurrentUser\My`，
默认不可导出），公钥证书和元数据写入仓库根目录的 `.signing/`。`.signing/`
以及 `*.pfx`、`*.p12`、`*.pvk`、`*.snk`、`*.key` 已在 `.gitignore` 中忽略。

## 快速开始

```powershell
# 1. 创建证书并信任到当前用户（不需要管理员）
powershell -NoProfile -ExecutionPolicy Bypass -File tools\signing\New-DevCodeSigningCert.ps1 -Trust CurrentUser

# 2. 正常构建；frontends/desktop 下的项目会在构建后自动签名输出目录
dotnet build frontends\desktop\src\BControl.Desktop\BControl.Desktop.csproj

# 3. 可选：补签原生 CMake 构建目录和所有桌面输出
powershell -NoProfile -ExecutionPolicy Bypass -File tools\signing\Sign-WindowsBuild.ps1

# 4. 验证
Get-AuthenticodeSignature frontends\desktop\src\BControl.Desktop\bin\Debug\net10.0\bcontrol-desktop.exe |
    Format-List Status, SignerCertificate
```

需要整机信任时，以管理员身份运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\signing\Trust-DevCodeSigningCert.ps1 -Scope LocalMachine
```

## 脚本

| 脚本 | 用途 |
| --- | --- |
| `New-DevCodeSigningCert.ps1` | 创建 RSA-3072/SHA-256 代码签名证书，导出 `.cer` 和 `.json`；`-Trust CurrentUser`/`LocalMachine` 可同时安装信任 |
| `Trust-DevCodeSigningCert.ps1` | 将公钥证书加入/移出 `Root`、`TrustedPublisher`；`-Scope CurrentUser` 或 `LocalMachine` |
| `Sign-Artifacts.ps1` | 对目录或文件中的 `.exe`/`.dll` 签名；默认跳过已有有效签名，`-Force` 强制重签 |
| `Sign-WindowsBuild.ps1` | 对 `build-windows-desktop/{Release,Debug}` 和所有桌面 `net10.0` 输出签名 |

证书默认不可导出；如确实需要 PFX 备份，用 `-ExportPfx`，密码会写入
`.signing/bcontrol-dev-codesign.password.txt`（同样被忽略）。不要把 PFX
或密码复制到仓库其他位置。证书有效期默认 3 年；到期后用 `-Force` 重新生成，
并重新构建/签名输出。

`frontends/desktop/Directory.Build.targets` 会在检测到
`.signing/bcontrol-dev-codesign.json` 时自动签名，可用
`dotnet build -p:BControlSignBuildOutput=false` 关闭。

## 移除信任

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\signing\Trust-DevCodeSigningCert.ps1 -Scope CurrentUser -Remove
```

整机信任需加管理员权限并指定 `-Scope LocalMachine`。如需同时删除证书私钥：

```powershell
certutil -user -delstore My <证书指纹>
```

该证书只用于本机开发/测试，完成后建议移除信任并删除私钥，不要用于对外分发。

## 与 Smart App Control 的关系

自签名证书只能让本机信任该证书并让 Authenticode 签名通过验证；Smart App
Control 仍按云端信誉/策略判断是否放行，不保证接受本地自签名产物。若签名后
仍被拦截，需要改用受信任 CA 签发的代码签名证书，或在 WSLg/虚拟机中完成
测试；不要为测试关闭 SAC 或修改安全策略。

签名会为构建输出目录中的第三方 DLL 添加本地证书签名（仅在 `bin/` 副本上，
不修改 NuGet 缓存）；这只是本机测试用途，不能作为对外分发物。
