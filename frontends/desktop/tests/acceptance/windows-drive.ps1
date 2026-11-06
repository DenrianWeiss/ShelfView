# 桌面端 Windows 真实窗口验收驱动（UIAutomation）。
# 依赖：应用已启动；Redfish/IPMI/RFB 夹具已在指定端口运行。
param(
    [int]$RedfishPort,
    [int]$IpmiPort,
    [int]$RfbPort,
    [string]$EvidenceDir,
    [int]$AppPid
)
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = 'Stop'

function Log([string]$m) { Write-Output "[drive] $m" }

function Get-Root([int]$targetPid) {
    $tries = 0
    while ($tries -lt 40) {
        $element = [System.Windows.Automation.AutomationElement]::FromHandle((Get-Process -Id $targetPid).MainWindowHandle)
        if ($null -ne $element) { return $element }
        Start-Sleep -Milliseconds 500
        $tries++
    }
    throw "未找到应用窗口"
}

function Find-All($root, [string]$name, [string]$type = 'Button') {
    $condition = New-Object System.Windows.Automation.AndCondition(
        (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::$type)),
        (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $name))
    )
    return $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
}

function Invoke-Named($root, [string]$name, [int]$index = 0) {
    $items = Find-All $root $name
    if ($items.Count -le $index) { throw "未找到按钮 $name (index $index, count $($items.Count))" }
    $pattern = $items[$index].GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
    $pattern.Invoke()
    Start-Sleep -Milliseconds 800
}

function Set-FirstText($root, [string]$value) {
    $condition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)
    $edit = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
    if ($null -eq $edit) { throw '未找到文本框' }
    $pattern = $edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $pattern.SetValue($value)
    Start-Sleep -Milliseconds 300
}

function Set-TextByIndex($root, [int]$index, [string]$value) {
    $condition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)
    $edits = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
    if ($edits.Count -le $index) { throw "未找到第 $index 个文本框 (count $($edits.Count))" }
    $pattern = $edits[$index].GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    $pattern.SetValue($value)
    Start-Sleep -Milliseconds 300
}

function Capture($name) {
    & "C:\Users\Catball\Workspace\bControl\frontends\desktop\tests\acceptance\capture-window.ps1" -ProcessName bcontrol-desktop -OutputPath (Join-Path $EvidenceDir $name) | Out-Null
    Log "截图 $name"
}

$root = Get-Root $AppPid
Log "窗口就绪"

# 1) 首页刷新（种子服务器 → 概况）
Invoke-Named $root '刷新'
Start-Sleep -Seconds 4
Capture '02-home-overview.png'

# 2) 添加向导
Invoke-Named $root '添加服务器'
Start-Sleep -Milliseconds 800
$wizard = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Children,
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, '添加服务器')))
if ($null -eq $wizard) { throw '未找到添加向导窗口' }
Set-TextByIndex $wizard 0 "https://127.0.0.1:$RedfishPort"
Set-TextByIndex $wizard 1 'fixture-user'
Set-TextByIndex $wizard 2 'fixture-password'
# TLS 验证选择“跳过全部验证”（自签夹具证书；验收用途）
try {
    $comboCondition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::ComboBox)
    $combo = $wizard.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $comboCondition)
    $combo.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern).Expand()
    Start-Sleep -Milliseconds 300
    $items = $combo.FindAll([System.Windows.Automation.TreeScope]::Descendants,
        (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::ListItem)))
    $items[2].GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
    Start-Sleep -Milliseconds 300
} catch { Log "TLS 下拉选择失败（继续）" }
Invoke-Named $wizard '开始探测'
Start-Sleep -Seconds 8
Capture '03-wizard-results.png'
Invoke-Named $wizard '取消'
Start-Sleep -Milliseconds 500

$root = Get-Root $AppPid

# 3) KVM 标签
$kvmButtons = Find-All $root 'KVM'
if ($kvmButtons.Count -gt 0) {
    Invoke-Named $root 'KVM' 0
    Start-Sleep -Milliseconds 800
    Set-FirstText $root "tcp://127.0.0.1:$RfbPort"
    Invoke-Named $root '连接'
    Start-Sleep -Seconds 5
    Capture '04-kvm.png'
} else { Log '未找到 KVM 按钮' }

# 4) SOL 标签
$root = Get-Root $AppPid
$solButtons = Find-All $root 'SOL'
if ($solButtons.Count -gt 0) {
    Invoke-Named $root 'SOL' 0
    Start-Sleep -Milliseconds 800
    try { Set-TextByIndex $root 1 "$IpmiPort" } catch { Log "SOL 端口设置失败（继续）" }
    Invoke-Named $root '连接'
    Start-Sleep -Seconds 6
    Capture '05-sol.png'
} else { Log '未找到 SOL 按钮' }

# 5) 媒体标签
$root = Get-Root $AppPid
$mediaButtons = Find-All $root '媒体'
if ($mediaButtons.Count -gt 0) {
    Invoke-Named $root '媒体' 0
    Start-Sleep -Milliseconds 800
    Invoke-Named $root '连接'
    Start-Sleep -Seconds 5
    Capture '06-media.png'
} else { Log '未找到媒体按钮' }

# 6) 标签栏总览
Capture '07-tabs.png'
Log '完成'
