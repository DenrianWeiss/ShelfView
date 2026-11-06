# 共享 i18n 词表

`catalog.json` 是桌面、Web、Apple 三个前端共用的唯一文案来源。C 核心与 Agent
只输出稳定的英文 token（状态码、单位、健康/状态等），不承载展示文案；前端负责
把 token 映射为本地化文本。

## 结构

```json
{
  "version": 1,
  "default": "zh-CN",
  "languages": [{ "tag": "zh-CN", "name": "简体中文" }, { "tag": "en", "name": "English" }],
  "messages": {
    "common.cancel": { "zh-CN": "取消", "en": "Cancel" }
  }
}
```

- `languages` 决定加载器暴露的可选语言；新增语言时在这里追加一项，并给每条消息
  补上对应字段即可。
- `default` 是缺失翻译时的回退语言，也是首次启动无法判断系统语言时的默认值。
- 键名使用 `域.语义` 的点分形式；同一概念跨端复用同一个键，禁止为某个平台复制一份。
- 占位符统一使用 `{name}`，由各平台加载器做简单替换；不要在文案里写 `%s`、`%@`
  或 `.NET` 的 `{0}`。占位符在各语言中必须保持一致（测试会校验）。
- 中文使用全角标点；英文使用半角标点。句子的语序交给各语言的译文，不要在前端
  拼接“前缀 + 值 + 后缀”；需要组合时用带占位符的完整句子键。

## 术语（首版，待正式术语表替换）

| 概念 | 中文 | English |
| --- | --- | --- |
| 电源状态 | 开机 / 关机 / 正在开机 / 正在关机 | On / Off / Powering on / Powering off |
| 未验证 | 未验证 | Unverified |
| 虚拟媒体 | 虚拟媒体 | Virtual media |
| 传感器健康 | 正常 / 警告 / 严重 | OK / Warning / Critical |
| 连接状态 | 未连接 / 连接中 / 已连接 / 已断开 | Not connected / Connecting / Connected / Disconnected |
| 缓存 | 缓存 | Cached |
| 正常最高 | 正常最高 | Normal max |

产品名、协议名（Redfish、IPMI、SOL、KVM、MegaRAC、UEFI、PXE、USB）保留原文，
不翻译；需要出现在句子中时也直接写在译文里。

## 生成物

Web 和 Apple 不能直接引用仓库根下的 JSON，因此由 `sync.mjs` 生成：

- `frontends/web/i18n-catalog.mjs`：供 `frontends/web/i18n.mjs` 静态导入。
- `frontends/apple/Sources/BControlCore/Resources/catalog.json`：SwiftPM 资源。

桌面端通过 `BControl.Core.csproj` 的 `EmbeddedResource` 直接嵌入
`frontends/i18n/catalog.json`，不生成副本。

修改 `catalog.json` 后运行：

```sh
node frontends/i18n/sync.mjs
node frontends/i18n/sync.mjs --check   # CI/测试用，检查生成物是否过期
```

## 各平台入口

- 桌面：`BControl.Core.Localization.Loc`（嵌入资源，`Loc.T` / `Loc.F`，
  XAML 用 `{loc:Tr key}`）。
- Web：`frontends/web/i18n.mjs`（`t` / `apply` / `setLanguage`，静态 HTML 用
  `data-i18n`、`data-i18n-placeholder`、`data-i18n-title`、`data-i18n-aria-label`）。
- Apple：`BControlCore.Localization`（`Bundle.module` 资源，`t` / `setLanguage`）。

## 语言选择与回退

三端都按“已保存的用户选择 → 系统语言（zh* → `zh-CN`，其余 → `en`）→ `default`”
的顺序决定初始语言。加载器在目标语言缺少某个键时回退到 `default`，再缺则显示键名，
便于发现遗漏。

## 输入

KVM/SOL 的键盘输入按裸机键盘处理，不做 IME 组合输入：Web 使用物理键
（`KeyboardEvent.code`）映射，桌面使用 Avalonia `Key`，Apple 使用 `NSEvent.keyCode`
与键位字符。输入法组合文本不进入远端。
