# Roadmap

Updated after every milestone. Last update: **2026-11-25 — M3 completed.**

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
| M2 | Vault model (logins, notes, cards, identities, TOTP), password/passphrase generator, local encrypted store (SQLite) with offline queue, `lk` CLI for end-to-end verification, HPKE cross-implementation vector | 2, 4 | ✅ Done (KDF device campaign carried over: needs physical devices) |
| M3 | Server: OPAQUE authentication, device registry, encrypted sync with change log and conflict handling, revocation enforcement, PostgreSQL, Docker Compose self-hosting, backup/restore | 3 | ✅ Done (phase gate partial: V-Y2, V-Y3, V-Y5, V-Y7 carried over, see the log) |
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

### M2 — 2026-11-25
Delivered: `lk-generator` (passwords, passphrases, exact entropy),
`lk-totp` (RFC 4226/6238, otpauth URIs), `lk-vault` (item schema v1 with
validation and password history), `lk-store` (SQLite local store with
offline change queue), `lk` CLI (end-to-end local stack), HPKE
interoperability with an independent implementation (V-C3), canary test
proving no plaintext on disk (V-S1), χ² generator test (V-S5). 162 tests.

Carried over: KDF benchmark on the minimum supported Android/iOS devices and
in browsers (V-C8) — requires hardware and the WASM harness of M4/M5.
Remaining risks: OPAQUE not yet prototyped; crash-injection tests of the
store (V-S2) partial (rollback tested, power-loss simulation pending).

### M3 — 2026-11-25
Owner approved OPAQUE (ADR-0005) and the backup destination policy
(configured sync server only).
Delivered: ADR-0008 (sync protocol), ADR-0009 (server stack), `lk-auth`
(OPAQUE, RFC 9807), `lk-protocol` (API v1), `lk-server` (accounts, OPAQUE
login, device-bound sessions, device registry and revocation, vault keys,
push/pull synchronization with server revisions, conflicts and tombstones,
rate limits, body limits), `lk-sync` (client engine with conflict copies,
rollback detection and full resynchronization after a restore), `lk-store`
schema v3 with tested migrations, CLI commands `register`, `login`, `sync`
(`--reset`), `devices`, `revoke`, Docker Compose
self-hosting (Caddy TLS, PostgreSQL 16, Docker secrets, unprivileged
read-only server container, health checks) with backup/restore scripts, and
a CI smoke test that destroys every volume, restores an older backup,
resynchronizes and enrolls a new device. V-Y1, V-Y4 and V-Y6 met. 223 tests
plus the smoke scenario.

Carried over (tracked in [AUDIT.md §3.3](docs/AUDIT.md#33-server-and-synchronization-phase-3)):
* V-Y3 randomized simulation (≥ 5 devices, ≥ 10 000 operations) and the
  V-Y2 property test — recommended before the v0.1 release candidate;
* V-Y5 systematic per-endpoint negative matrix;
* V-Y7 timed clean-host run, upgrade from a previous release (needs a first
  release), arm64 images;
* finer resynchronization after a server restore (fast-forward instead of
  conflict copies, ADR-0008 "Restore");
* push notifications (WebSocket) — clients synchronize on demand for now;
* e-mail verification; vault-key rotation after revocation (M7);
* free-tier quotas (AUDIT D-1) before the official cloud opens.

Remaining risks: RUSTSEC-2026-0387 accepted as unlinked (guarded in CI) until
`opaque-ke` 5 is stable; the sync engine is exercised by deterministic
scenarios only until the V-Y3 simulation exists.
