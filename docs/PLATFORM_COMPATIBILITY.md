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
| WebAssembly (`wasm32-unknown-unknown`) | 🔧 | CI `cargo check` of `lk-crypto`, `lk-core`, `lk-generator`, `lk-totp`; not executed in a browser yet. `lk-store` (SQLite) is not used on the web (IndexedDB, ciphertext only) |
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

## Features by platform (target state)

| Feature | Windows | macOS | Linux | Android | iOS | Chrome | Firefox | Brave | Web |
|---------|---------|-------|-------|---------|-----|--------|---------|-------|-----|
| Vault, generator, TOTP | 🧪 (built, not run) | 🧪 (built, not run) | ✅ desktop app | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Offline use | 🧪 | 🧪 | ✅ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⛔ (session only) |
| Password autofill | via extension | ⬜ native ext. + extension | via extension | ⬜ Autofill Framework (10+) | ⬜ Credential Provider (17+) | ⬜ | ⬜ | ⬜ | — |
| Passkey provider | ⬜ recent Win 11 builds **[verify]** | ⬜ (14+) | ⛔ (extension only) | ⬜ Android 14+ only | ⬜ (17+) | ⬜ | ⬜ | ⬜ | — |
| Biometric / PIN unlock | ⬜ Windows Hello | ⬜ Touch ID | ⛔ (no key-bound biometrics) | ⬜ BiometricPrompt | ⬜ Face ID / Touch ID | — | — | — | — |
| Hardware-backed device key | ⬜ TPM | ⬜ Secure Enclave | ⬜ TPM (optional, later) | ⬜ Keystore / StrongBox | ⬜ Secure Enclave | ⛔ | ⛔ | ⛔ | ⛔ |

This table is updated with real test evidence as each milestone lands.
