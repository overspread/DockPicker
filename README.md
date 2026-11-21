# DockPicker 1.0.0

DockPicker is a macOS menu-bar utility for controlling whether the icons of **currently running applications** appear in the native macOS Dock.

The first release is now available. It works through an undocumented LaunchServices notification, so Apple may change this behavior in a future macOS update.

## Features

- Search running regular applications.
- Filter by **All**, **Visible**, or **Hidden**.
- Show app icons, process IDs, and visibility counts.
- Toggle an app’s Dock tile and verify the result through Accessibility when available.
- Restore all choices before quitting.

Only running applications can be controlled. Applications that are not running are not listed.

## Compatibility

Verified locally on macOS 27.2.1 (build 26B131, Apple Silicon). The bundle declares macOS 27.0 as its minimum version. Other macOS releases and Intel Macs are unverified.

## Usage Notes

The notification is not a documented per-tile visibility API. The target process remains alive with its normal activation policy, but the Dock may update internal minimized-window, Spaces, App Exposé, and drag-state records.

An independent test app passed visibility round-trips, same-PID checks, window input, activation, menu commands, full-screen transitions, and additional-window checks. The maintainer also tested actual use on this Mac without noticing side effects. These checks do not guarantee that every app or workflow is unaffected. Minimize compatibility is **not verified** because the control case did not respond to the native minimize action.

DockPicker asks for confirmation the first time each app is hidden during a session. Test non-critical apps first. Use **Restore All** if behavior is unexpected. The target app or Dock may restart and make a tile reappear. Without Accessibility permission, the app shows saved choices instead of the verified Dock state.

Do not rely on this for critical work without testing that specific app and workflow. Chat, proxy, development, and production-critical apps may behave differently. The project has not automatically changed WeChat or any other installed target application.

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
