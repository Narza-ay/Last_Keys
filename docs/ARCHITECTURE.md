# Architecture

Status legend: ✅ implemented and tested · 🔜 next milestone · 📐 designed, not implemented · ⬜ not started.

## 1. Principles

1. **One cryptographic core.** Every client links the same Rust crates
   (`lk-crypto`, `lk-core`). Formats are produced and parsed by one
   implementation, so a vault written on Android opens byte-for-byte on Linux,
   in the browser or on iOS.
2. **The server is untrusted.** It stores ciphertext and the minimum metadata
   needed to synchronize. It authorizes requests but never decrypts.
3. **The core performs no I/O and reads no clock.** Storage, network, time and
   platform key stores are supplied by adapters. This keeps the core portable
   (including WebAssembly), deterministic under test and easy to audit.
4. **Native integrations at the edges.** Autofill, biometrics, hardware key
   stores and passkey providers are implemented natively per platform, behind
   narrow interfaces to the core.
5. **Fail closed.** Any malformed, unexpected or unverifiable input is an error,
   never a silent fallback.

## 2. Component overview

```text
                 ┌──────────────────────────── clients ─────────────────────────────┐
                 │ Desktop (Tauri 2)  Android (Kotlin)  iOS (Swift)  Web (React)  Ext │
                 │      │ direct         │ UniFFI          │ UniFFI     │ WASM   │WASM│
                 │      └───────────────┴──────┬──────────┴────────────┴────────┘    │
                 │                             ▼                                     │
                 │   lk-core (keys, vault, devices, sync state) ── lk-crypto         │
                 │   lk-store (local encrypted store, offline queue)                 │
                 └──────────────┬───────────────────────────────┬────────────────────┘
                                │ HTTPS REST + WebSocket        │ P2P (authenticated)
                                ▼                               ▼
                 ┌──────────── server (cloud or self-hosted) ───────────┐
                 │ API (Rust) ─ auth (OPAQUE) ─ device registry ─ sync   │
                 │ PostgreSQL (metadata + ciphertext) ─ object storage   │
                 │ relay (P2P fallback) ─ background jobs                │
                 └──────────────────────────────────────────────────────┘
```

## 3. Repository layout

```text
Cargo.toml            Rust workspace (pinned dependencies, strict lints)
rust-toolchain.toml   Pinned compiler (1.97.0)
deny.toml             Dependency policy (licenses, advisories, sources)
crates/
  lk-crypto/          ✅ primitives: KDF, envelope, HPKE, signatures, recovery key
  lk-core/            ✅ key hierarchy, vault/item keys, device identities
fuzz/                 ✅ libFuzzer targets (nightly)
apps/                 ⬜ one directory per application, each with a status README
docs/                 specification, architecture, security, ADRs, audit
.github/workflows/    ✅ CI
```

### Crate map (current and planned)

| Crate | Milestone | Responsibility | Status |
|-------|-----------|----------------|--------|
| `lk-crypto` | M1 | Argon2id, HKDF labels, XChaCha20-Poly1305 envelope, HPKE, Ed25519, recovery key, OS RNG | ✅ |
| `lk-core` | M1 | Account key bundle, password change, recovery-key rotation, vault keys, item encryption, device identity, certificates, revocations, account-key transfer | ✅ |
| `lk-vault` | M2 | Item schema (logins, notes, cards, identities, documents, TOTP, passkeys), history, in-memory search | 🔜 |
| `lk-generator` | M2 | Passwords, passphrases, strength estimation | 🔜 |
| `lk-totp` | M2 | RFC 6238 TOTP, `otpauth://` parsing | 🔜 |
| `lk-store` | M2 | Local encrypted store (SQLite), migrations, offline change queue | 🔜 |
| `lk-protocol` | M3 | Versioned API data types shared by server and clients | 📐 |
| `lk-sync` | M3 | Change log, conflict detection, merge, sync state machine | 📐 |
| `lk-import` | M6 | NordPass (then Bitwarden, 1Password, CSV) | 📐 |
| `lk-wasm` | M4/M5 | `wasm-bindgen` bindings for web app and extension | 📐 |
| `lk-ffi` | Phase 6 | UniFFI bindings for Kotlin and Swift | 📐 |

| Application | Milestone | Stack | Status |
|-------------|-----------|-------|--------|
| `apps/cli` | M2 | Rust (`lk` command) for end-to-end verification and power users | 🔜 |
| `apps/server` | M3 | Rust, PostgreSQL, REST + WebSocket, Docker | 📐 |
| `apps/desktop` | M4 | Tauri 2 + TypeScript | 📐 |
| `apps/extension` | M5 | TypeScript, MV3, `lk-wasm` | 📐 |
| `apps/web` | Phase 6 | React + TypeScript + `lk-wasm` | 📐 |
| `apps/android` | Phase 6 | Kotlin + `lk-ffi` | 📐 |
| `apps/ios` | Phase 6 | Swift + `lk-ffi` | 📐 |

Library choices for future components (web framework, database driver,
P2P stack, UI toolkit details) are made in ADRs at the start of their
milestone, after the maintenance/licensing review of [ADR-0003](adr/0003-dependency-policy.md).

## 4. Cryptographic design (summary)

The normative description, with byte layouts, is in
[CRYPTOGRAPHY.md](CRYPTOGRAPHY.md). Key hierarchy ([ADR-0002](adr/0002-key-hierarchy.md)):

```text
master password ─Argon2id─► master key ─HKDF─┬─► password wrapping key ──┐
                                             └─► server auth key          │
recovery key (256-bit) ─────────HKDF─────────┬─► recovery wrapping key ──┤ wrap
                                             └─► recovery auth key        ▼
trusted device ──HPKE(account key)──────────────────────────────► ACCOUNT KEY (random 256-bit)
                                                                    │ wraps
          ┌──────────────────────────┬──────────────────────────────┤
          ▼                          ▼                              ▼
 account signing key (Ed25519)  account encryption key (X25519)  vault keys ─► item keys ─► item content
          │ certifies / revokes
          ▼
 device identities (one per installation: Ed25519 + X25519, never copied)
```

* Changing the master password or the recovery key re-wraps the account key
  only; no vault data is re-encrypted and the server decrypts nothing.
* Every ciphertext is an envelope naming its version, suite, purpose and key,
  bound to a context that encodes *where* it belongs (account, vault, item).
* The trusted device list is computed by clients from account-signed
  certificates and revocations; the server cannot inject a device.

## 5. Data flows

### Account creation (implemented in `lk-core::create_account`)
1. Client normalizes the password (NFC) and runs Argon2id with a fresh salt.
2. Client generates the account key, account key pairs and recovery key.
3. Client builds the `AccountKeyBundle` (everything encrypted) and obtains the
   server auth secret; the recovery key is shown once.
4. (M3) Client registers with the server via OPAQUE and uploads the bundle.

### Unlock on a provisioned device
Local bundle + master password (Argon2id) — or, from Phase 5, the device-local
key released by biometrics/PIN — yields the account key. No network needed.

### New device enrollment by a trusted device (implemented primitives)
1. New device generates its `DeviceIdentity` and publishes `DevicePublicInfo`.
2. User confirms the pairing on the trusted device (out-of-band check, Phase 5).
3. Trusted device certifies the new device and sends an `AccountKeyTransfer`
   (account key sealed with HPKE to the new device, signed by the trusted
   device). Transfers to uncertified or revoked devices are refused.
4. New device verifies the signature, decrypts the account key, unlocks the
   bundle (which proves the key belongs to the account) and verifies that the
   sender is certified and not revoked.

### Synchronization (📐 M3)
Encrypted items carry `(vault_id, item_id, format_version)`; the sync layer
adds a per-item revision and a client-generated change ID. Clients push and
pull change batches; the server orders them per vault, enforces
authorization and stores tombstones. Concurrent edits produce conflict
copies, never silent overwrites. Details in a dedicated ADR at M3.

## 6. Platform adapters (📐)

The core exposes interfaces the platforms implement:

| Interface | Desktop | Android | iOS | Web/extension |
|-----------|---------|---------|-----|---------------|
| Secure key store (device-local key, device identity) | Windows Hello/TPM, macOS Keychain, Linux Secret Service | Android Keystore (StrongBox when present) | Keychain + Secure Enclave | Non-extractable WebCrypto key / session memory only |
| User presence | Windows Hello, Touch ID | BiometricPrompt | LocalAuthentication | WebAuthn |
| Local storage | SQLite file | SQLite | SQLite (App Group) | IndexedDB (ciphertext only) |
| Autofill | Browser extension | Autofill Framework, Credential Manager | Credential Provider extension | Content scripts |

Each adapter reports the protection level it actually provides
(software, OS key store, hardware-backed, hardware-backed with user presence).

## 7. Cross-cutting concerns

* **Errors** never contain secrets; user-facing messages are mapped from typed
  errors.
* **Time**: the core receives Unix timestamps from the caller.
* **Internationalization**: UI strings live in the applications (FR/EN
  resource files); the core returns typed errors, not text.
* **Versioning**: every persisted or transmitted structure carries a format
  version; readers reject unknown versions instead of guessing.
