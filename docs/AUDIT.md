# Coherence audit, open decisions and technical validation criteria

Status: **v1 — 2026-11-25**, written at the start of the project (milestone M1).
Inputs: the master development prompt (v1.0) and the 14 product decisions that
lock it (restated in [SPECIFICATION.md](SPECIFICATION.md#2-locked-product-decisions)).

This document answers three questions:

1. Do the specification and the 14 decisions contradict each other or the
   platforms they target? (§1)
2. Which decisions are still required, and which phase does each one block? (§2)
3. What objective criteria must each component meet to be considered
   technically validated? (§3)

Statements about third-party platforms that could not be verified from this
environment are marked **[verify]**: each must be confirmed on a real device
or against current vendor documentation before the related phase starts.

---

## 1. Incompatibilities and tensions

Severity legend:

* **Decision** — the specification cannot be implemented as written without a
  product or legal choice. Listed again in §2.
* **Limitation** — a platform makes part of the requirement impossible; the
  best secure alternative is adopted and the limitation is documented
  ([KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md)).
* **Resolved** — the tension is removed by an architectural choice already
  recorded in this repository.

### 1.1 Legal and privacy

| ID | Tension | Severity | Resolution / recommendation |
|----|---------|----------|-----------------------------|
| A-1 | **Telemetry on by default** (decision 14) vs **EU/France hosting** (decision 4). The ePrivacy rules (art. 82 of the French *Loi Informatique et Libertés*) require prior consent to read or store information on a user's device unless strictly necessary. Pre-ticked consent is invalid (CJEU, *Planet49*, C-673/17). A per-installation identifier is *pseudonymous*, not anonymous, so GDPR applies to it. The CNIL accepts a consent exemption for strictly limited audience measurement, under conditions. | Decision (blocks Phase 7) | Recommended: default-on only for metrics that satisfy the CNIL exemption conditions (aggregated counters, no stable identifier, no cross-referencing, bounded retention), crash reports **opt-in** at onboarding, a single switch to disable everything. **Requires review by legal counsel / DPO** before implementation. |
| A-2 | EU residency vs third-party services that the features imply: breach checking (the public Pwned Passwords API is not EU-operated), crash reporting SaaS, transactional e-mail, mobile push (APNs/FCM are US services and unavoidable for push). | Decision (blocks Phases 3 and 7) | Recommended: mirror the Pwned Passwords range dataset on EU infrastructure (the client still uses k-anonymity); self-host crash collection in the EU; choose an EU e-mail provider; send push notifications that carry **no** content ("sync available"). |
| A-3 | Automatic encrypted cloud backup (decision 13) vs users who chose self-hosting or peer-to-peer only. | Decision (blocks Phase 3) | Recommended: backups go to the **configured** sync server (official or self-hosted) — never silently to the official cloud. P2P-only users rely on the manual encrypted export. |

### 1.2 Authentication, recovery and key management

| ID | Tension | Severity | Resolution / recommendation |
|----|---------|----------|-----------------------------|
| K-1 | "Email + master password + **device passkeys**" (decision 3) vs end-to-end encryption: a WebAuthn passkey proves identity to the server but carries no key material, so it cannot decrypt the vault on its own. The WebAuthn PRF extension can derive a key, but it is not available on iOS 17 (minimum in decision 10) **[verify]** and varies by authenticator. | Decision (confirm; blocks Phase 5) | Recommended: passkeys authenticate *server sessions* (and act as a second factor). On a provisioned device, the vault is unlocked by the device-local key protected by biometrics/PIN. On a **new** device or the web app, the master password, the recovery key or a trusted-device transfer is always required; PRF-based unlock is an optional enhancement where supported. This matches spec §6 ("biometrics and PIN must not replace the key hierarchy"). |
| K-2 | "Never transmit the master password" + "separate server authentication from vault encryption" requires a precise authentication protocol. | Decision (approve; blocks Phase 3) | Recommended: OPAQUE (aPAKE, RFC 9807) fed with the HKDF-derived *server auth key* (not the password itself), so Argon2id runs once and the server never sees a password-equivalent. Already prepared in code: `MasterKey::server_auth_key()` is domain-separated from every encryption key. See [ADR-0005](adr/0005-server-authentication-opaque.md) (*Proposed*). |
| K-3 | Recovery by **trusted secondary device** (decision 2) for a user who **forgot** the master password: the trusted device can only help if it can be unlocked *without* that password. | Resolved (design constraint) | Trusted-device recovery requires that the trusted device has local unlock (biometrics or PIN) configured. The onboarding must state it. The cryptographic transfer itself (`AccountKeyTransfer`, HPKE + device signature, recipient must be certified and not revoked) is implemented and tested in M1. |
| K-4 | Device **revocation** + "rotate affected shared secrets": the revoked device knew the account key, vault keys and item keys. Re-wrapping keys alone does not protect future edits from a revoked device that later obtains ciphertext (e.g. through a compromised server). | Decision (confirm; blocks Phase 5) | Recommended: on revocation, rotate the account key and the vault keys and **eagerly re-encrypt** items with new item keys (client-side, O(number of items)). Data already decrypted by the revoked device cannot be recalled (documented). |
| K-5 | Total loss scenario: master password + recovery key + every trusted device lost ⇒ data is unrecoverable, by design (no hidden recovery, spec §6–7). | Resolved (documented) | Must be stated explicitly during onboarding and in the emergency kit. |
| K-6 | Offline unlock (decision 9) vs changes made elsewhere: an offline device keeps unlocking with the *old* password until it syncs; a revoked device that never reconnects keeps its local copy. | Limitation | Inherent to offline-first E2EE; documented. Revocation takes effect at the next contact with the server. |

### 1.3 Platforms

| ID | Tension | Severity | Resolution / recommendation |
|----|---------|----------|-----------------------------|
| P-1 | **Android 10+** (decision 10) vs **third-party passkey provider** (decision 1): Android's Credential Manager provider API (`CredentialProviderService`) requires Android 14 (API 34). | Limitation (accept) | Passwords: Autofill Framework on Android 10+. Passkeys as a system provider: Android 14+ only. On Android 10–13, passkeys stored in Last Keys are viewable but not offered to other apps. |
| P-2 | **Windows 11+** vs passkey provider: Windows only recently opened a plug-in API for third-party passkey managers, on recent Windows 11 builds **[verify build and API status]**. | Limitation | Passkeys through the browser extension everywhere; native Windows provider where the OS supports it. |
| P-3 | **Linux**: no system autofill or credential-provider API, no standard hardware-backed key store for applications (Secret Service is software-protected), biometrics not tied to key protection. | Limitation | Autofill and passkeys through the browser extension. Local protection is reported to the user as *software (OS keyring)*. Optional TPM 2.0 support may be evaluated later. Never displayed as hardware protection (spec §5.3). |
| P-4 | **macOS / iOS** system AutoFill and passkeys require a native Credential Provider **app extension** (Swift). Tauri cannot produce it. | Limitation (architecture) | macOS: a Swift extension target embedded and signed inside the Tauri app bundle, sharing the core through the Rust FFI. iOS: native Swift app + extension. Requires an Apple Developer Program account (entitlements, App Groups, shared Keychain). |
| P-5 | **iOS AutoFill extension memory ceiling** vs Argon2id with ≥ 64 MiB: credential-provider extensions run under a much lower memory limit than apps **[verify the current limit]**. | Resolved (design constraint) | The extension never runs Argon2id: it unlocks with the Keychain-held device-local key (Face ID / Touch ID). Master-password unlock happens in the main app. Peak extension memory becomes a validation criterion (§3.6). |
| P-6 | **WebAuthn requires a domain name and HTTPS** (RP IDs cannot be IP addresses; secure context required) vs self-hosting on a NAS reached by IP (decision 6). | Limitation | Passkey login to a self-hosted server requires a domain name and a valid TLS certificate; password login works without. Documented in [SELF_HOSTING.md](SELF_HOSTING.md). |
| P-7 | Web application (spec §3) + "the server never receives keys": the server delivers the web app's JavaScript, so a compromised server could deliver code that captures the master password. Inherent to every web vault. | Limitation | Strict CSP, Subresource Integrity, no third-party scripts, no persistent decrypted storage, web app can be disabled in self-hosted deployments, native apps and extension recommended for highest assurance. Documented in the threat model. |
| P-8 | WebCrypto has neither Argon2id nor XChaCha20-Poly1305. | Resolved | The web app and extension use `lk-crypto` compiled to WebAssembly: one implementation, identical formats on every platform ([ADR-0006](adr/0006-web-crypto-via-wasm.md)). `lk-core` already compiles for `wasm32-unknown-unknown` (CI job). The CSP must allow `'wasm-unsafe-eval'`. |
| P-9 | Browser extension: "avoid broad host permissions" vs automatic form detection and passkey interception on every site (both need content scripts on all pages; passkey interception needs a main-world script that wraps `navigator.credentials`). | Limitation | Host access requested as an **optional** permission at onboarding with a clear explanation; if declined, fall back to click-to-fill (`activeTab`). Store-review justifications prepared. Firefox MV3 differs from Chromium (event pages, `browser.*`); covered by the compatibility adapter and per-browser tests. |
| P-10 | Peer-to-peer sync (spec §11.2) on mobile: background execution limits prevent always-listening peers; NAT traversal needs a relay. | Limitation | P2P works while the apps are active; relay fallback runs on the official or self-hosted server; peers exchange addresses only after mutual device authentication. |
| P-11 | "Lock on system sleep" in the browser extension: only the `idle` API's *locked* state is observable. | Limitation | Lock on idle/locked state plus inactivity timeout; documented. |
| P-12 | Device passkey login from the **Linux desktop** app: no platform authenticator API. | Limitation | FIDO2 security keys (via libfido2) or master password. |

### 1.4 Product and data

| ID | Tension | Severity | Resolution / recommendation |
|----|---------|----------|-----------------------------|
| D-1 | Free cloud (decision 5) + unlimited devices (decision 8) + documents/attachments + automatic backups ⇒ unbounded storage and abuse cost. | Decision (blocks cloud launch, Phase 3) | Define free-tier quotas (attachment storage, item count, enrollment rate limits) before opening the official cloud. Unlimited **devices** remains compatible with rate limiting. |
| D-2 | NordPass importer (decision 12): the exact export schema must be validated against a real export. | Input required (blocks M6) | Provide a NordPass CSV export containing **fake** entries of every type (login, note, card, identity, folder). Never a real export. |
| D-3 | Self-hosting "simple on a NAS" vs PostgreSQL requirement: small ARM NAS have limited RAM. | Resolved | Multi-architecture images (amd64, arm64), documented minimum resources; PostgreSQL stays the only database (one schema for cloud and self-hosted, spec §11.3). |
| D-4 | Crash reports vs "never collect vault contents": native crash dumps may contain heap memory. | Resolved (design constraint) | Only symbolicated stack traces and error codes; no heap minidumps; scrubbing tests (§3.7). |

### 1.5 Delivery

| ID | Tension | Severity | Resolution / recommendation |
|----|---------|----------|-----------------------------|
| R-1 | MVP-first delivery (owner's instruction) vs "never skip phases" (spec §18). | Resolved | The MVP is a vertical slice through phases 1–4 and 6; every phase keeps its own validation gate, nothing is skipped, only reordered. See [ROADMAP.md](../ROADMAP.md). |
| R-2 | Apple and Android release builds cannot be produced or tested in this Linux environment. | Limitation | Exact CI configuration (macOS and Windows runners already in the CI matrix for the Rust core) and commands will be provided per platform; no compatibility is claimed until a test has run on that platform. |

---

## 2. Decisions still required

None of these blocks the current work (Phase 1–2: core cryptography, local
vault). Each blocks a later phase, as indicated. Recommended options are
listed first.

| # | Decision | Recommended option | Blocks |
|---|----------|--------------------|--------|
| 1 | Telemetry legal basis (A-1) | Exempt anonymous metrics on by default, crash reports opt-in; legal review | Phase 7 |
| 2 | Third-party services for EU residency (A-2) | EU-mirrored breach data, self-hosted crash collection, EU e-mail, content-free push | Phases 3, 7 |
| 3 | Backup destination (A-3) | **Resolved 2026-11-25**: configured sync server only (official cloud or self-hosted), never silently the official cloud | Phase 3 |
| 4 | Passkey role in unlocking (K-1) | Passkeys authenticate sessions; vault unlock by device-local key or master password; PRF optional | Phase 5 |
| 5 | Server authentication protocol (K-2) | **Resolved 2026-11-25**: OPAQUE over the HKDF-derived auth key ([ADR-0005](adr/0005-server-authentication-opaque.md), accepted) | Phase 3 |
| 6 | Revocation policy (K-4) | Rotate account and vault keys, eager item re-encryption | Phase 5 |
| 7 | Android passkey provider scope (P-1) | Accept Android 14+ for system passkeys | Phase 5 |
| 8 | Free-tier quotas (D-1) | Define before the official cloud opens | Phase 3 (cloud) |
| 9 | NordPass sample export (D-2) | Owner provides a fake-data export | M6 |
| 10 | MVP scope ([ROADMAP.md](../ROADMAP.md)) | **Resolved 2026-11-25**: confirmed as proposed (CLI → server/sync → desktop → extension → NordPass import) | — |

---

## 3. Technical validation criteria

A component is *technically validated* only when every criterion of its
section passes, in addition to the Definition of Done (spec §20). Criteria
marked ✅ are already met (with the evidence named); the others are targets.

### 3.1 Cryptography (Phase 2)

| ID | Criterion | Status |
|----|-----------|--------|
| V-C1 | Only primitives from the reviewed dependency set; no custom primitive; `unsafe` forbidden in workspace crates. | ✅ `#![forbid(unsafe_code)]`, `cargo deny check`, [ADR-0003](adr/0003-dependency-policy.md) |
| V-C2 | Known-answer tests: HKDF (RFC 5869 A.3), Ed25519 (RFC 8032 §7.1 test 1), Argon2id against the reference C implementation, recovery-key format vectors computed independently. | ✅ unit tests in `lk-crypto` |
| V-C3 | HPKE interoperability with a second independent implementation (RFC 9180 test vectors run upstream; add our own cross-implementation vector). | ✅ pyhpke/OpenSSL in both directions (regression test + one-off reverse check), M2 |
| V-C4 | Every single-bit flip and every truncation of an envelope is rejected; parsers never panic. | ✅ exhaustive unit tests + property tests (512 cases each) |
| V-C5 | Coverage-guided fuzzing of every parser (envelope, sealed message, recovery key, later sync/import parsers): ≥ 1 h per target with no crash before each release; continuous in CI. | ⬜ 5 targets, short runs clean, nightly CI workflow; 1 h campaign before release (see [TESTING.md](TESTING.md)) |
| V-C6 | Ciphertexts are bound to their location: swapping, moving or relabeling items, vault keys or private keys is detected. | ✅ `lk-core/tests/flows.rs` |
| V-C7 | Hostile parameters are refused: KDF below the floor (64 MiB, t ≥ 2), substituted public keys, forged device certificates or revocations, transfers to uncertified or revoked devices. | ✅ unit + integration tests |
| V-C8 | KDF cost: Argon2id unlock p50 ≤ 1 s on the reference low-end Android 10 device and ≤ 2 s in WebAssembly on a mid-range laptop, with memory ≥ 64 MiB. Default parameters fixed from these measurements. | ⬜ server CPU measured (147 ms); device and WASM campaign pending |
| V-C9 | No secret in `Debug` output, logs, errors or telemetry; secrets zeroized on drop. | ✅ for `Debug` (tests); ⬜ log/telemetry scanning (Phase 7); ⬜ post-lock memory scan (Phase 8, best effort) |
| V-C10 | Independent cryptographic review of the formats and key hierarchy. | ⬜ before production |

### 3.2 Local vault and storage (Phase 2/4)

| ID | Criterion | Status |
|----|-----------|--------|
| V-S1 | No plaintext vault data on disk: canary test (unique strings written to the vault never appear in database files, WAL, temporary files or logs). | ✅ `lk-store` canary test (database + WAL, open and closed) |
| V-S2 | Crash-safety: killing the process at any point of a write never corrupts the store (transactional writes, recovery test). | ⬜ partial: every mutation is one transaction, rollback tested; process-kill injection pending |
| V-S3 | Schema migrations are forward-only, tested from every released version. | ⬜ partial: forward-only runner and newer-version guard tested; no release yet |
| V-S4 | Importers write no plaintext temporary files; malformed input never panics (fuzzed). | ⬜ M6 |
| V-S5 | Password generator: uniform symbol distribution (χ² test over 10⁶ draws), policy constraints always satisfied; TOTP passes RFC 6238 vectors. | ✅ `lk-generator` statistics, `lk-totp` vectors |

### 3.3 Server and synchronization (Phase 3)

| ID | Criterion | Status |
|----|-----------|--------|
| V-Y1 | The server never receives plaintext or keys: canary strings never appear in database dumps, object storage, logs or traces. | ✅ database (server tests on the item, bundle, vault-key and change tables; plain `pg_dump` of the Compose stack) and server logs (Compose smoke test, which also checks the e-mail is not logged). No object storage or trace export exists yet: re-test when attachments arrive |
| V-Y2 | Idempotence: replaying any sequence of change batches yields the same state (property test). | ⬜ partial: replayed changes and duplicated batches return the recorded outcome (`replays_are_idempotent`), client retries are safe (`offline_edits_are_folded_and_retries_are_safe`); property test over arbitrary sequences pending (with V-Y3) |
| V-Y3 | No lost writes: randomized simulation with ≥ 5 devices, offline periods, reordering and duplication over ≥ 10 000 operations keeps every concurrent version (conflict copies), with tombstones for deletions. | ⬜ carried over: deterministic 2–3-device scenarios only (conflict copies, delete against edit, offline edits); the randomized simulation is not written yet |
| V-Y4 | Revocation: a revoked device is refused on every endpoint at its next request; its sessions are invalidated server-side. | ✅ every authenticated route goes through the same session check, which rejects sessions of revoked devices; tested: next request refused, sessions deleted, login refused, revocation permanent (`devices`, `client_sync`, CLI end to end) |
| V-Y5 | Authorization is enforced server-side on every endpoint (automated negative tests for cross-account access, IDOR, replay). | ⬜ partial: cross-account reads and writes, vault-key planting, enrollment-scope restrictions, foreign certificates, bundle swaps, single-use login attempts and replays are tested; a systematic per-endpoint negative matrix is pending |
| V-Y6 | Rate limiting and request size limits on authentication, enrollment and upload endpoints. | ✅ per-IP and per-e-mail limit on authentication endpoints (`authentication_endpoints_are_rate_limited`); 256 KiB and 32 MiB body limits (`oversized_requests_are_refused`) |
| V-Y7 | Self-hosting: `docker compose up` on a clean host reaches healthy in ≤ 5 min; backup → restore round-trip verified; upgrade from the previous release runs migrations without data loss; amd64 and arm64 images. | ⬜ partial: start from nothing, health, backup → destruction of every volume → restore of an older backup → detection by clients → `lk sync --reset` → nothing lost, verified on every CI run (`compose-smoke`, amd64); the stack is healthy within seconds once the image is built. Pending: timed run on a clean host, upgrade from a previous release (needs a first release), arm64 images |

### 3.4 Clients and autofill (Phase 6)

| ID | Criterion |
|----|-----------|
| V-A1 | Domain matching: test suite with the Public Suffix List, IDN/punycode homographs, subdomains, ports and schemes; never fills an origin that does not match. |
| V-A2 | Never fills into a cross-origin frame without explicit confirmation. |
| V-A3 | Each browser (Chrome, Firefox, Brave) and OS has an automated end-to-end autofill test plus a documented manual matrix. |
| V-A4 | Auto-lock: inactivity timeout, app exit and (where observable) system lock/sleep verified per platform. |
| V-A5 | Hardware protection is reported only when the platform attests it (Android Keystore/StrongBox, Secure Enclave, TPM/Windows Hello). |

### 3.5 User interface

| ID | Criterion |
|----|-----------|
| V-U1 | French and English complete; no hard-coded strings (lint). |
| V-U2 | WCAG 2.2 AA: contrast, keyboard navigation, screen-reader labels (automated + manual audit). |
| V-U3 | Light, dark and system themes; layouts verified at phone, tablet and desktop widths. |
| V-U4 | Disabled or unsupported features are visibly marked as such. |

### 3.6 Performance

| ID | Criterion |
|----|-----------|
| V-P1 | Vault of 10 000 items: open ≤ 1 s after key derivation, search ≤ 50 ms (desktop reference). |
| V-P2 | Sync of 1 000 changed items ≤ 5 s on a 10 Mbit/s link. |
| V-P3 | iOS AutoFill extension peak memory measured and below the platform ceiling with margin ≥ 30 %. |

### 3.7 Privacy and telemetry (Phase 7)

| ID | Criterion |
|----|-----------|
| V-T1 | Telemetry payload schema is allow-listed; automated test rejects any field outside the schema. |
| V-T2 | Disabling telemetry stops all telemetry traffic (network-level test). |
| V-T3 | Crash reports contain no heap data and pass the secret-scrubbing test. |

### 3.8 Release (Phase 8)

| ID | Criterion |
|----|-----------|
| V-R1 | Signed release artifacts for every platform; SBOM published; dependency advisories clean. |
| V-R2 | Independent security audit completed and findings resolved or accepted in writing. |
| V-R3 | Update mechanism verifies signatures before installing. |
| V-R4 | Backup and recovery procedures exercised end to end (recovery key, trusted device, restore from backup). |
