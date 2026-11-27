# Roadmap

Updated after every milestone. Last update: **2026-11-26 — M4 completed.**

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
| M4 | Desktop app (Tauri 2): unlock, vault browsing/editing, generator, TOTP, devices, settings, FR/EN, light/dark/system | 6 | ✅ Done (Linux tested end to end; Windows/macOS built by CI, not yet run on devices) |
| M5 | Browser extension (Chrome, Brave, Firefox): login-form detection, safe domain matching, fill, save, generate | 6 | ✅ Done (Linux + Chromium tested end to end; Firefox built, not driven end to end; Brave and Windows/macOS not run) |
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
in browsers (V-C8) — requires hardware and the WASM harness (now M13).
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

### M4 — 2026-11-26
Owner validated M4. Delivered: ADR-0010 (desktop stack and security model),
`lk-client` (application layer shared by the CLI and the desktop; the CLI
now runs on it), the desktop application (`apps/desktop`): Rust back end
(`lk-desktop`: commands, auto-lock, clipboard clearing, settings) and a
React interface in French and English with light, dark and system themes —
onboarding (new vault or new device), unlock (password or recovery key),
logins with TOTP, notes, cards, identities, editor that never loads secrets,
explicit reveal, generator, password history, registration and automatic
synchronization, full resynchronization, devices and revocation, settings.
Tests: 19 new Rust tests, 57 Vitest tests (including WCAG contrast of every
text colour), 10 Playwright tests, and a WebDriver scenario of the real
application on Linux (clipboard clearing, sync with a real server, no
plaintext on disk) passing on the debug build and the installed `.deb`.
Linux installers (deb, rpm, AppImage) built locally; CI builds installers
for the three systems.

Carried over: run the Windows and macOS builds on real devices; lock on
system sleep/session lock (V-A4); automated accessibility audit (V-U2);
network calls outside the vault lock; signed installers and updates
(Phase 8); bundle identifier to confirm with the product domain.

### M5 — 2026-11-27
Owner validated M4 and chose the extension mode "connected to the desktop"
(2026-11-26): no key and no vault in the browser; a standalone mode moves
to M13. Delivered: ADR-0011, `lk-autofill` (origin matching with the Public
Suffix List including private suffixes, punycode, ports, no https→http
downgrade), origin-checked autofill operations in `lk-client`, `lk-bridge`
(frames, requests, pairing material, mutual HMAC challenge-response,
endpoint names, native messaging manifests), the desktop bridge (local
socket or named pipe, pairing dialog, paired-browser list and revocation,
native host registration for Chrome, Chromium, Brave and Firefox, relay mode
of the executable) and the extension (`apps/extension`, Manifest V3 for
Chromium and Firefox): popup in French and English, form detection,
click-to-fill with cross-origin frame confirmation, copy through the
desktop, save and update proposals, password generation, optional access to
every site (AUDIT P-9). V-A1 and V-A2 met; V-A3 partial (Chromium on Linux
automated; Firefox, Brave, Windows and macOS remain).

Fixed during the end-to-end work: a notification loop that closed the
pairing connection, and a race that lost frame reports (both covered by new
tests).

Carried over: Firefox driven end to end (needs a WebExtension-capable
automation), Brave and the Windows/macOS hosts on real machines (manual
matrix in [TESTING.md](docs/TESTING.md)), store publication and final
extension IDs (owner decision), in-field suggestions.
Next: M6 (NordPass importer).
