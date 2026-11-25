# Platform compatibility

No compatibility is claimed without a test on the platform (spec §1, §21).
Legend: ✅ tested · 🧪 tested in CI only · 🔧 compile-checked only · ⬜ not built yet · ⛔ impossible on this platform (see limitation).

## Minimum versions (decision 10)

Windows 11+, macOS 14+, Android 10+ (API 29), iOS 17+, maintained Linux
distributions (glibc-based x86_64 and arm64 first).

## Rust core (`lk-crypto`, `lk-core`)

| Target | Status | Evidence |
|--------|--------|----------|
| Linux x86_64 | ✅ | Local test suite + CI (`ubuntu-latest`) |
| Windows x86_64 | 🧪 | CI (`windows-latest`): all tests pass, dev and release profiles (first verified in run 45630834635, commit `dc25306`) |
| macOS arm64 | 🧪 | CI (`macos-latest`): all tests pass, dev and release profiles (first verified in run 45630834635, commit `dc25306`) |
| WebAssembly (`wasm32-unknown-unknown`) | 🔧 | CI `cargo check`; not executed in a browser yet |
| Android (arm64, armv7, x86_64) | ⬜ | Cross-compilation added with `lk-ffi` |
| iOS (arm64, simulator) | ⬜ | Requires macOS runner with Xcode, added with `lk-ffi` |
| Linux arm64 | ⬜ | Added with the server images (M3) |

## Features by platform (target state)

| Feature | Windows | macOS | Linux | Android | iOS | Chrome | Firefox | Brave | Web |
|---------|---------|-------|-------|---------|-----|--------|---------|-------|-----|
| Vault, generator, TOTP | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Offline use | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⛔ (session only) |
| Password autofill | via extension | ⬜ native ext. + extension | via extension | ⬜ Autofill Framework (10+) | ⬜ Credential Provider (17+) | ⬜ | ⬜ | ⬜ | — |
| Passkey provider | ⬜ recent Win 11 builds **[verify]** | ⬜ (14+) | ⛔ (extension only) | ⬜ Android 14+ only | ⬜ (17+) | ⬜ | ⬜ | ⬜ | — |
| Biometric / PIN unlock | ⬜ Windows Hello | ⬜ Touch ID | ⛔ (no key-bound biometrics) | ⬜ BiometricPrompt | ⬜ Face ID / Touch ID | — | — | — | — |
| Hardware-backed device key | ⬜ TPM | ⬜ Secure Enclave | ⬜ TPM (optional, later) | ⬜ Keystore / StrongBox | ⬜ Secure Enclave | ⛔ | ⛔ | ⛔ | ⛔ |

This table is updated with real test evidence as each milestone lands.
