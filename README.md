# DockPicker 1.0.0

DockPicker 1.0 is a macOS menu-bar utility for requesting per-application visibility changes in the **native macOS Dock** for currently running applications.

The user-facing application is the first release. Its LaunchServices notification mechanism remains undocumented by Apple and may change in future macOS versions.

## Status and Compatibility

This project relies on undocumented LaunchServices notification behavior. It is not an Apple-supported API and may stop working or behave differently after a macOS update.

Verified locally on macOS 27.2.1 (build 26B131, Apple Silicon). Other macOS releases and Intel Macs are unverified. The app bundle declares macOS 27.0 as its minimum version; this is a conservative compatibility gate, not a claim that every 27.x release was tested.

## Features

- Search currently running regular applications.
- Filter the list by **All**, **Visible**, or **Hidden**.
- Show app icons, process IDs, and visible/hidden counts.
- Toggle an app's Dock tile and verify the result through Accessibility when available.
- Restore all choices before quitting.

Only running applications can be controlled by this runtime approach. Apps that are not running are not listed.

## Important Risks

The notification is not a documented per-tile visibility API. The Dock handles a visibility change through internal application-exit bookkeeping. The target process remains alive with its normal activation policy, but the Dock also updates internal minimized-window and Spaces records. This may affect minimized windows, App Exposé, Spaces, drag state, or other Dock-managed behavior.

The independent test app passed visibility round-trips, same-PID checks, window input, activation, menu commands, full-screen transitions, and additional-window checks. The maintainer reports an actual-use test without noticeable side effects on this Mac; this does not guarantee every target app is unaffected. The test environment's native minimize action did not work in the control case, so minimization compatibility is **not verified**.

A per-app confirmation appears the first time you hide each app during a DockPicker session. Test non-critical apps first. Use **Restore All** if behavior is unexpected. The target app or Dock can restart and make a tile reappear. If Accessibility permission is unavailable, the app falls back to saved choices; check the native Dock to confirm the actual state.

Do not rely on this for critical work without testing that specific app and workflow. Chat, proxy, development, and production-critical apps may have app-specific behavior. The project has not automatically changed WeChat or any other installed target application.

## Permissions

Accessibility permission is used only to read native Dock items for state verification:

**System Settings → Privacy & Security → Accessibility**

Hiding does not require administrator privileges, App Management permission, target-bundle write access, code signing changes to the target app, or Keychain access.

## Release

Version: **1.0.0**. This release has been built and verified locally. The local source repository is version-controlled; publishing or pushing it to a remote repository is a separate, explicit action.

The app bundle uses version `1.0.0` (build `1`).

```sh
make build
open build/DockPicker.app
```

The local build is ad-hoc signed. For redistribution, use your own Developer ID signing and notarization workflow. This repository does not include a prebuilt binary.

## Project Safety

- Never edit or re-sign target application bundles as part of this project.
- Never add application `Info.plist` backups, private application data, screenshots containing user data, signing keys, or certificates to the repository.
- Treat LaunchServices behavior as undocumented and version-specific.
- The bundled `Resources/Info.plist` uses the neutral identifier `org.dockpicker.app`.

## License

MIT. See [LICENSE](LICENSE).

DockPicker is not affiliated with, endorsed by, or supported by Apple.
