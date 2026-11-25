# Roadmap

Updated after every milestone. Last update: **2026-11-25 — M1 completed.**

The specification defines 8 phases (spec §18). At the owner's request the
product is delivered **MVP-first**: milestones cut a vertical slice through
the phases. Nothing is skipped — every phase keeps its validation gate
([AUDIT.md §3](docs/AUDIT.md#3-technical-validation-criteria)); only the
delivery order changes.

## MVP definition (v0.1, confirmed by the owner on 2026-11-25)

A single user can create an account, keep an end-to-end encrypted vault of
logins, secure notes and TOTP codes, generate passwords, import from NordPass,
use it offline, and synchronize it between a desktop app (Windows, macOS,
Linux) and a self-hostable server, with autofill through the browser
extension (Chrome, Brave, Firefox), device enrollment, revocation and a
recovery key.

Out of the MVP (later milestones): mobile apps, passkey manager and
authenticator, sharing and temporary links, security center and breach
monitoring, P2P sync, documents/attachments, web application, telemetry.

## Milestones

| # | Milestone | Spec phases | Status |
|---|-----------|-------------|--------|
| M0 | Audit, architecture, documentation, monorepo, CI | 1 | ✅ Done |
| M1 | Cryptographic core: KDF, envelopes, HPKE, signatures, recovery key, key hierarchy, device identities, certificates, revocation, trusted-device transfer | 2 | ✅ Done |
| M2 | Vault model (logins, notes, cards, identities, TOTP), password/passphrase generator, local encrypted store (SQLite) with offline queue, `lk` CLI for end-to-end verification, HPKE cross-implementation vector, KDF benchmark campaign | 2, 4 | 🚧 In progress |
| M3 | Server: OPAQUE authentication, device registry, encrypted sync with change log and conflict handling, revocation enforcement, PostgreSQL, Docker Compose self-hosting, backup/restore | 3 | ⬜ |
| M4 | Desktop app (Tauri 2): unlock, vault browsing/editing, generator, TOTP, devices, settings, FR/EN, light/dark/system | 6 | ⬜ |
| M5 | Browser extension (Chrome, Brave, Firefox): login-form detection, safe domain matching, fill, save, generate | 6 | ⬜ |
| M6 | NordPass importer (local file, preview, duplicates, report) | 4 | ⬜ |
| **v0.1** | **MVP release candidate**: regression suite, security review of M1–M6, deployment docs | 8 (partial) | ⬜ |
| M7 | Device security: biometrics/PIN local unlock, hardware key stores, pairing verification, key rotation on revocation | 5 | ⬜ |
| M8 | Mobile apps: Android (Autofill Framework, Credential Manager) and iOS (Credential Provider extension) | 6 | ⬜ |
| M9 | Passkeys: WebAuthn authenticator in extension and native providers (Android 14+, iOS 17+, macOS 14+, Windows where supported) | 5 | ⬜ |
| M10 | Sharing with users, encrypted temporary links | 7 | ⬜ |
| M11 | Security center, privacy-preserving breach monitoring, suspicious activity | 7 | ⬜ |
| M12 | Documents and attachments (chunked encryption), password history UI | 4 | ⬜ |
| M13 | Web application | 6 | ⬜ |
| M14 | Peer-to-peer sync with relay fallback | 3 | ⬜ |
| M15 | Telemetry (after the legal decision, AUDIT A-1) | 7 | ⬜ |
| v1.0 | Production readiness: independent audit, accessibility audit, performance, signed release builds, update mechanism, backup/recovery verification | 8 | ⬜ |

## Milestone log

### M0 + M1 — 2026-11-25
Delivered: workspace, pinned toolchain and dependencies, strict lints, CI,
dependency policy, documentation set, ADRs 0001–0006, coherence audit,
`lk-crypto` and `lk-core` with unit, integration, property and fuzz tests.
See [CHANGELOG.md](CHANGELOG.md) and [docs/TESTING.md](docs/TESTING.md).

Remaining risks: OPAQUE integration not yet prototyped; KDF defaults not yet
measured on mobile/WASM; pairing verification protocol not yet designed;
platform claims marked **[verify]** in the audit are unconfirmed.

CI run 1 (commit `dc25306`): all 7 jobs green, including the 90 tests on
Windows and macOS. MVP scope confirmed by the owner; M2 started.
