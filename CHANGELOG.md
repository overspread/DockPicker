# Changelog

## 1.0.2-preview.1 — 2026-11-26

面向下一正式版 1.0.2 的测试版本，GitHub 标记为 Pre-release，不替换 1.0.1 的 Latest 正式版标记。

### 新增功能

- 长期保存应用隐藏规则，目标应用退出后保留选择。
- 监听应用启动，对重开的应用自动再次隐藏；DockPicker 自身重开后继续应用保存的规则。
- 每 3 秒在后台检查一次，在应用启动时序、操作忙碌或 Dock 图标复现时补做隐藏；同一应用的重试至少间隔 5 秒。

### 功能调整

- 控制面板收起后仍继续后台检查，需要 DockPicker 保持运行并具备辅助功能权限。
- 开启列表开关或菜单勾选会恢复显示并取消对应规则；“全部恢复”和“恢复并退出”成功后清除全部规则，包括未运行应用。
- 开关反映持续隐藏选择，文字与数量仍反映实际 Dock 核验状态；等待自动隐藏时明确提示。
- 后台自动操作不弹授权框，失败时保留规则并稍后重试。

### 移除功能

- 无。

### Bug 修复

- 修复应用退出或 PID 变化后误删隐藏记录，导致重开后无法继续自动隐藏的问题。
- 修复图标重新出现时直接丢弃隐藏选择，而没有重新执行隐藏的问题。
- 修复控制面板不可见时停止定时处理，无法维持后台自动隐藏的问题。
- 修复存在未运行应用的隐藏规则时“全部恢复”按钮不可用，无法通过该按钮清除这些规则的问题。

### 预览版限制与安装

- 发布附件为 `DockPicker-1.0.2-preview.1.pkg`，应用版本 `1.0.2`（build `3`），界面标注 Preview 1。
- 使用 ad-hoc 临时签名，未使用 Developer ID 签名或 Apple 公证；原固定签名材料不可用，本次未修改默认签名配置。升级后可能需要移除旧辅助功能条目并重新添加应用，后续临时签名更新也可能需要重新授权。
- 目标应用刚启动时图标仍可能短暂出现；直接退出 DockPicker 后，不再处理新启动的应用。
- 仅完成编译、临时代码签名及安装包结构核验；新增自动隐藏场景尚未完成实际运行验证，Intel Mac 未经测试。

## 1.0.1

- 退出行为拆分：默认「退出」保持隐藏状态，另设独立的「恢复并退出」。
- 恢复失败时不再退出，错误信息保留在面板上；操作进行中点退出会给出明确提示。
- 按实际运行列表与原生 Dock 状态回收陈旧的隐藏记录（图标已复现或应用已退出）。
- 读取不到 Dock 层级时不再判定为「全部已隐藏」。
- `lsappinfo` 调用加超时，固定 0.8 秒睡眠改为轮询核验；核验失败的条目不再写入隐藏记录。
- 辅助功能取值加类型防御，避免 Dock 层级变化时崩溃。
- 新增最小主菜单，恢复 ⌘Q 与搜索框的剪切/复制/粘贴/全选。
- 窗口最小宽度提高到 700 点，状态行可显示 4 行错误信息；面板不可见时不再定时刷新。
- 未授权时禁用显示/隐藏筛选，避免把本地选择当成真实状态。
- 清理 1.0.0 遗留的旧偏好键。

## 1.0.0

- First official release of the DockPicker UI.
- Search and filter running applications by All, Visible, and Hidden.
- Show native Dock state when Accessibility inspection is available; explicitly distinguish saved choices when it is unavailable.
- Add a per-application confirmation and a Restore All action.
- Keep target bundles, signatures, ownership, and running processes unchanged.
- Use the launch-panel activation fallback required by the LSUIElement menu-bar app on the verified system.
