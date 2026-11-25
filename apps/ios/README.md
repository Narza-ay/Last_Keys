# iOS application

**Status: not started — milestone M8 (after the MVP).** Nothing in this directory is functional yet.

Planned: Swift, core through UniFFI (`lk-ffi`), iOS 17+. Keychain and Secure
Enclave for the device-local key, LocalAuthentication (Face ID / Touch ID),
Password AutoFill Credential Provider extension with passkey support. The
extension never runs Argon2id; it unlocks with the Keychain-held
device-local key (AUDIT P-5). Building requires macOS with Xcode and an Apple
Developer account.
