# Changelog

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
