# Desktop application (Windows, macOS, Linux)

**Status: not started — milestone M4.** Nothing in this directory is functional yet.

Planned stack: Tauri 2 (Rust backend linking the core crates directly),
TypeScript UI, French/English resources, light/dark/system themes.

Platform integrations (behind core adapter interfaces):
* Windows 11+: Windows Hello / TPM for the device-local key (M7).
* macOS 14+: Keychain / Secure Enclave, Touch ID (M7); system AutoFill and
  passkeys require a Swift Credential Provider extension embedded in the app
  bundle (AUDIT P-4).
* Linux: Secret Service (software protection, reported as such) (AUDIT P-3).
* Autofill through the browser extension on all three systems.
