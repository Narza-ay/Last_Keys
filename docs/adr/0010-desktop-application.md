# ADR-0010: Desktop application stack and security model

* Status: Accepted
* Date: 2026-11-25

## Context
Milestone M4 delivers the desktop application for Windows 11+, macOS 14+
and maintained Linux distributions (decision 10): unlock, vault browsing and
editing, generator, TOTP, devices, settings, French and English, light, dark
and system themes. The specification fixes Tauri for the desktop and React +
TypeScript for the web application (spec §4). The desktop handles the most
sensitive data of the product in a process that also runs a web view, whose
JavaScript heap cannot be zeroized.

## Decision

### Stack (dependencies reviewed on 2026-11-25 per ADR-0003)

| Concern | Choice |
|---------|--------|
| Shell | Tauri 2.12 (`tauri` 2.12.5, `tauri-build` 2.7.4, CLI and `@tauri-apps/api` 2.12.4): system web view (WebView2, WKWebView, WebKitGTK), Rust back end |
| Shared logic | New crate `lk-client`: the application layer (create, enroll, unlock, items, TOTP, account, sync, devices) used by the CLI and the desktop, and later by `lk-ffi` and `lk-wasm` |
| UI | React 19.3 + TypeScript 6.0, built with Vite 8.3; no UI component library, no CSS framework, no web fonts (system font stack): fewer dependencies, offline, no third-party requests |
| Clipboard | `arboard` 3.7, used from Rust only |
| Tests | Rust unit and integration tests; Vitest 5.1 + Testing Library + jsdom for components; Playwright (pre-installed Chromium in development, `@playwright/test` in CI) against the built UI with a scripted back end; a smoke run of the real application on Linux |
| Lint | ESLint 9 with typescript-eslint and the React plugins; `react/jsx-no-literals` forbids hard-coded UI text (criterion V-U1) |
| Packages | npm with a committed `package-lock.json`, `npm ci`, install scripts disabled (`ignore-scripts=true`); every version pinned exactly and at least two weeks old when adopted |

React is chosen over other front-end frameworks because the web application
(spec §4) uses it: one UI skill set, and components can later be shared.

### Security model
1. **Secrets stay in Rust.** The web view never holds keys. It receives item
   summaries and detail views in which every secret field is replaced by a
   flag ("present"); a secret value crosses to the web view only when the
   user explicitly reveals that one field, and the UI drops it when hidden,
   when the item is closed and on lock.
2. **Copy without exposure.** "Copy" asks Rust to put the value on the
   clipboard directly; the value never enters JavaScript. Rust clears the
   clipboard after a delay (default 30 s) if it still holds that value, marks
   the content as excluded from clipboard history where the platform
   supports it, and clears it on lock and exit.
3. **Edits send only what changed.** Editors send each secret field as
   "keep", "set to …" or "remove", so opening an editor does not load the
   secrets into the web view.
4. **Master password.** It must be typed in the web view and therefore
   exists briefly as a JavaScript string; the UI clears its state right
   after sending it, Rust converts it to a zeroizing type at once. This
   residual risk is documented (KNOWN_LIMITATIONS).
5. **Locking.** Locking drops the unlocked vault in Rust (keys zeroized on
   drop) and resets the UI. Auto-lock after inactivity (default 5 minutes,
   configurable), measured in Rust from user activity reported by the UI;
   the vault also locks when the last window closes. Locking on system sleep
   or session lock needs platform hooks (V-A4) and is a later step.
6. **Least privilege for the web view.** Only the application's own
   commands are exposed (Tauri capabilities); no file-system, shell, HTTP or
   clipboard plugin is granted to JavaScript. Strict Content Security Policy
   (`default-src 'self'`, no remote scripts, styles or connections); the
   synchronization server is contacted by Rust only. Developer tools are
   disabled in release builds. No remote content is ever loaded.
7. **Errors** reach the UI as a stable code plus a secret-free message; the
   UI translates the code.

### Settings and data
Non-secret settings (language, theme, auto-lock and clipboard delays) are a
JSON file in the platform configuration directory. The vault is the same
`lk-store` file as the CLI's, in the platform data directory.

## Consequences
* Every platform gets the same audited Rust logic; the UI is a thin,
  testable layer.
* The UI cannot show a secret without a round trip to Rust, which keeps the
  web view's exposure minimal at a small latency cost.
* Building the desktop crate on Linux requires WebKitGTK development
  packages (installed in CI).
* Installers (MSI/MSIX, DMG, AppImage/deb/rpm) and their signing are
  produced by the release pipeline; M4 verifies Linux bundles locally.

## Alternatives considered
* Electron: ships its own Chromium (larger, separate update cadence),
  Node.js in the main process; rejected by the specification.
* Decrypting in the web view (WebAssembly): would put keys in the JavaScript
  heap of the desktop app for no benefit; reserved for the web application
  (ADR-0006), where no native layer exists.
* `tauri-plugin-clipboard-manager`: exposes clipboard access to JavaScript
  unless carefully restricted; direct `arboard` use from Rust is simpler.
