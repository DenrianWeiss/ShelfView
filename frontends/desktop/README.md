# Windows/Linux 桌面端（Avalonia + 进程内 C 核心）

进程内直接 P/Invoke 调用 C 核心（不经本地 Agent）。Windows 10/11 与
Linux（Ubuntu 22.04/24.04、Debian 12/13，x86_64）共享 Avalonia UI 与 C# 绑定。

## 结构

- `src/BControl.Core` — 薄 P/Invoke 绑定与安全封装（Redfish/RMCP+/SOL/KVM/清单导入），
  业务协议仍在 C 核心；后台线程执行所有阻塞 C 调用。
- `src/BControl.Desktop` — Avalonia 应用：服务器清单、添加向导、首页概况、
  KVM/SOL/媒体工作区标签。
- `tests/BControl.Desktop.Tests` — 清单原子持久化、凭据库回退、向导解析/多系统选择、
  刷新并发/取消/隔离、标签唯一、媒体关闭决策。
- `tests/BControl.Core.Tests` — C 绑定单元测试（KVM 编解码、清单导入解析）。
- `tests/BControl.Integration.Tests` — 状态化夹具集成测试：HTTPS Redfish、
  IPMI UDP/RMCP+ 与 SOL（复用 `tests/ipmi_integration.py` 的独立 BMC 实现）、
  本地 RFB/KVM。
- `tests/fixtures` — 集成/验收用 Python 夹具（Redfish HTTPS、RMCP+ SOL BMC、RFB）。
- `tests/acceptance` — 真实窗口验收驱动与证据（截图）。

## 依赖与版本（固定于 `Directory.Packages.props`）

| 包 | 版本 | 许可证 | 说明 |
| --- | --- | --- | --- |
| Avalonia / Avalonia.Desktop / Avalonia.Themes.Fluent | 12.0.4 | MIT | UI 框架（仅桌面） |
| Iciclecreek.Avalonia.Terminal | 4.1.0 | MIT | SOL 终端控件；`AttachConnection` 接 SOL 字节流，不启动本地进程 |
| Porta.Pty（传递） | 2.2.3 | MIT | 仅 `IPtyConnection` 接口 |
| XTerm.NET（传递） | 3.0.0 | MIT | 终端模拟 |
| SkiaSharp.HarfBuzz（传递） | 3.119.4 | MIT | 渲染 |
| Unicode.net（传递） | 2.0.0 | MIT | 宽度数据 |
| Wcwidth（传递） | 4.0.1 | MIT | 宽度数据 |
| xunit / xunit.runner.visualstudio / Microsoft.NET.Test.Sdk | 2.9.2 / 2.8.2 / 17.11.1 | Apache-2.0 / Apache-2.0 / MIT | 测试 |

.NET SDK：10.0.x。原生 C 库：libbcontrol 系列（仓库 CMake 构建）。

## 构建

发布脚本位于 `packaging/`：macOS 的 `macos/package.sh` 调用 Apple 前端的完整 `.app`/DMG 打包流程；
Windows 使用 `windows/package.ps1 x64` 或 `windows/package.ps1 arm64`。Windows 脚本需要 Visual Studio 2022 C++ 工具、CMake、.NET 10 SDK 和 `VCPKG_ROOT`，会构建对应架构的原生库、发布自包含应用并收集原生运行库。发布目录可整体复制到干净机器运行；`ShelfView.exe` 合并托管运行时，原生 P/Invoke DLL 与它放在同一目录。

先构建 C 库（独立目录，避免与其他构建并发冲突）：

```sh
# Windows（需 vcpkg 提供 curl/openssl，见下）
cmake -S . -B build-windows-desktop -G "Visual Studio 17 2022" -A x64 \
  -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-windows -DBC_BUILD_AGENT=OFF -DBUILD_TESTING=OFF
cmake --build build-windows-desktop --config Release

# Linux/WSL
cmake -S . -B build-wsl-desktop -G Ninja -DBC_BUILD_AGENT=OFF -DBUILD_TESTING=OFF
cmake --build build-wsl-desktop
```

再构建桌面（原生库自动复制到输出目录，可用 `-p:BControlNativeDir=` 覆盖）：

```sh
cd frontends/desktop
dotnet build src/BControl.Desktop/BControl.Desktop.csproj
```

## 测试

```sh
cd frontends/desktop/tests
dotnet test BControl.Desktop.Tests
dotnet test BControl.Core.Tests
# 集成测试需要 python3（夹具复用仓库 tests/ 下的独立实现）
dotnet test BControl.Integration.Tests
```

## 本地化

界面文案来自仓库共享词表 `frontends/i18n/catalog.json`，以嵌入资源方式打进
`BControl.Core`；不要在 XAML 或 ViewModel 中新增中英文字面量。XAML 使用
`{loc:Tr key}`，代码使用 `Loc.T` / `Loc.F`（命名占位符）。首页工具栏的语言下拉框
切换中英并写入用户配置目录；新增语言只需在词表追加语言字段。

## 凭据存储

清单文件只保存元数据与凭据引用（`%AppData%\bControl\servers.json` /
`~/.config/bControl/servers.json`）。密码存系统凭据库：Windows 为系统凭据管理器
（advapi32），Linux 经 libsecret 走 Secret Service（LGPL-2.1+ 系统库，运行时动态加载）。
凭据库不可用时只保留当前进程内存，绝不回退明文文件。

## 电源与启动管理

首页每行的“管理”打开单台服务器的分页窗口（电源/启动、传感器、FRU、网络，IPMI 还包括 SEL）：

- 电源动作来自设备公布的 Reset ActionInfo，只列出实际支持的动作；执行前再次确认。
- 启动设置只写入一次性覆盖（`BootSourceOverrideEnabled=Once`），可读回时显示读回结果，
  不修改持久启动顺序；设备未声明一次性覆盖时不提供写入。
- 每次操作独立登录、执行并注销，不长期占用设备会话；IPMI 记录使用 RMCP+ Chassis Control 与核心一次性启动接口，并按能力门控。

## 媒体能力边界

- Redfish VirtualMedia：已接入（发现、状态、挂载 URL、弹出；弹出失败/结果未知保留挂载状态）。
- MegaRAC/Huawei 本地 ISO：进程内原生媒体通道，能力与清理分别门控。
- iDRAC 本地 ISO：独立网页会话、票据引导与媒体 WebSocket，不依赖查看器。
- IPMI/RMCP+ 本身不提供本地 ISO；可根据独立网页协议证据使用厂商媒体通道。

## Windows Smart App Control 说明

本机 SAC 可能按云端信誉拦截新编译的未签名程序集。仓库提供本地开发签名工具
（`tools/signing/`）：生成本机自签名证书、安装到当前用户或整机信任存储，并在
`Directory.Build.targets` 中于构建后自动为输出 PE 签名。自签名证书不保证被
SAC 的云端策略接受；被拦截时仍按环境限制记录，不关闭/不绕过 SAC。
具体用法见 [`tools/signing/README.md`](../../tools/signing/README.md)。

## 功能对齐

Windows/Linux 统一 Fluent 并跟随系统主题，使用系统标题栏和文件选择器。
管理页支持 Redfish/IPMI 电源与一次性启动、传感器阈值、FRU、网络及 IPMI SEL；
控制台支持 MegaRAC、Huawei、iDRAC，媒体支持 Redfish URL 与只读本地 ISO。
本地供盘、控制台恢复、显式协议与 TLS 兼容选项、组合键、SOL 编辑和诊断导出规则见
[对齐设计](../../docs/desktop-parity.zh-CN.md)。

iDRAC 独立媒体夹具（仅 localhost，需要 openssl、Python 和本机原生库）：

```sh
python3 tests/apple_idrac_media_integration.py --c-build <native-build> --desktop-dotnet <dotnet-path>
```

共享夹具分别检查正常挂载/弹出、权限拒绝、繁忙及截断响应；不向实际 BMC 写入。

## 名称与图标

Windows/Linux 产品名称、可执行文件和窗口名称统一为 **ShelfView**，复用 macOS 的服务器机架图标。
Windows EXE 内嵌多分辨率 ICO；Linux 设置 `WM_CLASS=ShelfView`，发布目录的 `packaging/linux/`
提供 `work.permutation.shelfview.desktop` 与同名 SVG，可安装到应用菜单及 hicolor 图标目录。
Linux 启动项的 `Exec=ShelfView` 要求可执行文件位于 PATH。

现有 `bControl` 数据目录、凭据引用和原生库 ABI 名称保留，以兼容已有记录与系统凭据。

使用 curl 8.22.0 自行构建 Windows/Linux 依赖时，先应用
`third_party/curl/location-1xx.patch`（Apple 依赖脚本也使用此补丁），再构建/安装 curl。
否则带 Location 的 HTTP 103 与最终响应组合会被误判为重复头；原生 `redfish-discovery` 会检测该问题。
