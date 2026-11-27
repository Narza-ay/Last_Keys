# Platform compatibility

No compatibility is claimed without a test on the platform (spec §1, §21).
Legend: ✅ tested · 🧪 tested in CI only · 🔧 compile-checked only · ⬜ not built yet · ⛔ impossible on this platform (see limitation).

## Minimum versions (decision 10)

Windows 11+, macOS 14+, Android 10+ (API 29), iOS 17+, maintained Linux
distributions (glibc-based x86_64 and arm64 first).

## Rust core (`lk-crypto`, `lk-core`, `lk-generator`, `lk-totp`, `lk-vault`, `lk-store`) and `lk` CLI

| Target | Status | Evidence |
|--------|--------|----------|
| Linux x86_64 | ✅ | Local test suite + CI (`ubuntu-latest`) |
| Windows x86_64 | 🧪 | CI (`windows-latest`): all tests pass, dev and release profiles (first verified in run 45630834635, commit `dc25306`) |
| macOS arm64 | 🧪 | CI (`macos-latest`): all tests pass, dev and release profiles (first verified in run 45630834635, commit `dc25306`) |
| WebAssembly (`wasm32-unknown-unknown`) | 🔧 | CI `cargo check` of `lk-crypto`, `lk-core`, `lk-generator`, `lk-totp`, `lk-autofill`; not executed in a browser yet. `lk-store` (SQLite) is not used on the web (IndexedDB, ciphertext only) |
| Android (arm64, armv7, x86_64) | ⬜ | Cross-compilation added with `lk-ffi` |
| iOS (arm64, simulator) | ⬜ | Requires macOS runner with Xcode, added with `lk-ffi` |
| Linux arm64 | ⬜ | Not built yet (server images and CI runner planned before v0.1) |

## Synchronization server (`lk-server`)

| Target | Status | Evidence |
|--------|--------|----------|
| Linux x86_64, Docker image (`infra/Dockerfile`, Debian trixie) with PostgreSQL 16 | ✅ | Server test suite against PostgreSQL 16 (local and CI `server-tests`); Compose smoke test (local and CI `compose-smoke`) |
| Linux arm64 image | ⬜ | Not built yet |
| PostgreSQL versions other than 16 | ⬜ | Not tested (the Compose stack pins 16) |

## Desktop application (`apps/desktop`)

| Target | Status | Evidence |
|--------|--------|----------|
| Linux x86_64 (Ubuntu 24.04, WebKitGTK 2.52, X11) | ✅ | Real application driven end to end through WebDriver (debug build and release `.deb`), including clipboard clearing and synchronization with a real server; `.deb`, `.rpm` and AppImage built locally |
| Linux, Wayland session | ⬜ | Not tested; the clipboard goes through XWayland (arboard without the Wayland data-control feature) |
| Windows 11 x86_64 | 🧪 | CI compiles and runs the Rust tests, and builds the MSI and NSIS installers (`desktop-bundle`); not run on a physical machine |
| macOS 14+ arm64 | 🧪 | CI compiles and runs the Rust tests, and builds the app and DMG (`desktop-bundle`); not run on a physical machine |

## Browser extension (`apps/extension`, with the desktop application)

| Target | Status | Evidence |
|--------|--------|----------|
| Chromium on Linux x86_64 (the Chrome for Testing build of Playwright 1.63), desktop application on X11 | ✅ | `e2e/run.mjs`: the real desktop application registers the native host, the browser starts the relay; pairing, fill, refusal on another site, cross-origin frame confirmation, generate, save into the vault, lock, revocation |
| Google Chrome (Linux, Windows, macOS) | ⬜ | Same build as Chromium (`dist/chrome`); not tested |
| Brave | ⬜ | Same build as Chromium; not tested |
| Firefox 128+ | 🔧 | `dist/firefox` built by CI, covered by unit tests and manifest checks; not loaded in Firefox by a test |
| Native host registration, Linux | ✅ / 🔧 | Chromium directory exercised end to end; Chrome, Brave and Firefox directories unit-tested |
| Native host registration, Windows (registry) and macOS | 🧪 | Compiled and unit-tested by CI; never run |
| Browsers installed as Flatpak or Snap | ⛔ | Sandboxed browsers cannot start native messaging hosts |

## Features by platform (target state)

| Feature | Windows | macOS | Linux | Android | iOS | Chrome | Firefox | Brave | Web |
|---------|---------|-------|-------|---------|-----|--------|---------|-------|-----|
| Vault, generator, TOTP | 🧪 (built, not run) | 🧪 (built, not run) | ✅ desktop app | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Offline use | 🧪 | 🧪 | ✅ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⛔ (session only) |
| Password autofill | 🧪 via extension (built, not run) | 🧪 via extension (built, not run); ⬜ native extension | ✅ via extension (Chromium) | ⬜ Autofill Framework (10+) | ⬜ Credential Provider (17+) | ✅ Linux (Chromium build) | 🔧 built | ⬜ untested (Chromium build) | — |
| Passkey provider | ⬜ recent Win 11 builds **[verify]** | ⬜ (14+) | ⛔ (extension only) | ⬜ Android 14+ only | ⬜ (17+) | ⬜ | ⬜ | ⬜ | — |
| Biometric / PIN unlock | ⬜ Windows Hello | ⬜ Touch ID | ⛔ (no key-bound biometrics) | ⬜ BiometricPrompt | ⬜ Face ID / Touch ID | — | — | — | — |
| Hardware-backed device key | ⬜ TPM | ⬜ Secure Enclave | ⬜ TPM (optional, later) | ⬜ Keystore / StrongBox | ⬜ Secure Enclave | ⛔ | ⛔ | ⛔ | ⛔ |

This table is updated with real test evidence as each milestone lands.
