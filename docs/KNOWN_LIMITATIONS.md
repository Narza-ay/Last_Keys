# Known limitations

Maintained continuously (spec §19). Each entry links to its analysis in
[AUDIT.md](AUDIT.md). "Current" limitations exist in the code today;
"platform/design" limitations are permanent consequences of a platform or of
the security model.

## Current (M3)

| Limitation | Planned resolution |
|------------|--------------------|
| No graphical application yet: the `lk` CLI is the only client (synchronization included). | M4–M6 |
| Server: no e-mail verification at registration (registering reveals whether an e-mail is already taken), no WebSocket notifications (clients synchronize on demand), no account deletion, plain (non-TLS) connection to PostgreSQL (intended for the internal Docker network only). | Before v0.1 (notifications, account deletion), before the official cloud (e-mail verification) |
| Self-hosting: `linux/amd64` image only, built locally (no published or signed image); upgrade from a previous release untested (there is none yet). | arm64 and published images before v0.1; upgrade test with the first release |
| After a server restore, every device must run `lk sync --reset`; versions written after the backup come back as conflict copies and deletions made after the backup reappear (nothing is lost). | Finer resynchronization (ADR-0008, "Restore") |
| Synchronization is verified by deterministic multi-device scenarios only; the randomized simulation (≥ 5 devices, ≥ 10 000 operations, V-Y3) is not written yet. | Before v0.1 |
| Revoking a device does not rotate vault keys (a revoked device keeps the keys it held; the server refuses it). | M7 |
| The `lk` CLI is English-only, notes are entered on a single line, and every command asks for the master password (no session caching). | Graphical apps (M4) provide FR/EN and sessions |
| Store crash-safety relies on SQLite transactions; process-kill injection tests are not written yet (V-S2). | Before v0.1 |
| Argon2id default parameters measured only on a server vCPU (≈ 147 ms); not yet on mobile or in WebAssembly. | KDF campaign (V-C8): needs the physical devices and the WASM harness (M4/M5) |
| WebAssembly build is compile-checked in CI but not executed in a browser. | M4/M5 (`lk-wasm` + browser tests) |
| Device-identity and private-key storage use a caller-supplied wrapping key; platform key-store adapters (hardware protection) do not exist yet. | Phase 5 / M7 |
| Pairing verification between a new device and a trusted device (out-of-band code) is not designed yet. | Phase 5 / M7 |
| Windows and macOS: the Rust core is tested by the CI matrix (GitHub-hosted runners) only, not on physical user machines. | Platform testing with the desktop app (M4) |
| Strength estimation exists only for generated secrets (exact entropy); passwords chosen by users are not yet scored. | Onboarding screen (M4), security center (Phase 7) |
| Passphrases use the English EFF wordlist only. | French wordlist with a compatible license (before v0.1) |
| `opaque-ke` 4 depends on `crypto-bigint` 0.5 (RUSTSEC-2026-0387). The affected code is not linked with our cipher suite (verified in CI); the exception disappears with `opaque-ke` 5. | Migrate when `opaque-ke` 5 is stable |
| GitHub Actions in CI are pinned to major version tags, not commit SHAs. | Pin to SHAs when the release pipeline is set up (Phase 8) |

## Platform and design

* Data already decrypted by a revoked device or a share recipient cannot be erased remotely (AUDIT K-4).
* Losing the master password, the recovery key and every trusted device makes the vault unrecoverable, by design (K-5).
* An offline device keeps working with the state it last synchronized, including an old password, until it reconnects (K-6).
* Android 10–13: no system-wide third-party passkey provider (API 34+ required) (P-1).
* Windows: native passkey provider only on recent Windows 11 builds; elsewhere via the browser extension (P-2).
* Linux: no system autofill or passkey provider, no standard hardware-backed key store; local protection is software (OS keyring) (P-3).
* macOS/iOS system AutoFill requires a native Swift extension and an Apple Developer account (P-4).
* Passkey login to a self-hosted server requires a domain name and a valid TLS certificate (P-6).
* The web application trusts the server that delivers its code (P-7).
* Browser extension: automatic form detection needs optional broad host access; without it, click-to-fill only (P-9).
* Peer-to-peer sync works while apps are active; a relay is needed across NATs (P-10).
* Browser extension can only lock on idle/locked state, not on every system sleep (P-11).
* Breach detection only knows publicly known breaches (SEC-2).
* Memory zeroization is best effort, and impossible to guarantee in garbage-collected UI layers (Kotlin, Swift, JavaScript).
