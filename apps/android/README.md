# Android application

**Status: not started — milestone M8 (after the MVP).** Nothing in this directory is functional yet.

Planned: Kotlin, core through UniFFI (`lk-ffi`), Android 10+ (API 29).
Android Keystore (StrongBox when available) for the device-local key,
BiometricPrompt, Autofill Framework for passwords (API 26+), Credential
Manager provider for passkeys on Android 14+ only (AUDIT P-1).
Building requires the Android SDK/NDK, not available in the current
development container; CI configuration will be provided with the milestone.
