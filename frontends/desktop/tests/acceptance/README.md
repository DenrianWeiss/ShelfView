# 真实窗口验收说明

- `windows/`：Windows 证据（PrintWindow 截图 PNG）。
- `linux-wslg/`：WSLg/Linux 证据。
- `capture-window.ps1`：按进程名捕获窗口（PW_RENDERFULLCONTENT）。
- `windows-drive.ps1`：UIAutomation 驱动（刷新、添加向导、KVM/SOL/媒体标签）。

环境约束：本机 Smart App Control 开启，按云端信誉拦截新编译的无签名程序集
（apphost 与 `dotnet *.dll` 均可能报 0x800711C7）。不关闭/不绕过安全策略；
被拦截时对应证据标记为“受 SAC 阻塞”。可用 `tools/signing/` 生成本地开发证书
并为构建产物签名后再验收；自签名不保证被 SAC 的云端策略接受。
