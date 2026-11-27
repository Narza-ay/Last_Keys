# Testing

## How to run

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked --exclude lk-server             # dev profile (dependencies optimized)
cargo test --workspace --locked --exclude lk-server --release   # production profile (panic = abort)
cargo check -p lk-core -p lk-crypto -p lk-generator -p lk-totp -p lk-autofill --target wasm32-unknown-unknown --locked
cargo deny check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --document-private-items
```

Server, synchronization and end-to-end tests need a PostgreSQL 16 role with
`CREATEDB` rights (each test creates and drops its own database):

```bash
export LK_TEST_DATABASE_URL=postgres://lastkeys:lastkeys-dev@127.0.0.1/postgres
cargo test -p lk-server --locked
cargo test -p lk-cli --features server-e2e --test sync_e2e --locked
```

Self-hosting smoke test (Docker with Compose v2, a release `lk` binary and the
server image; takes a few minutes, uses ports 18080/18081/18443 on 127.0.0.1
and touches nothing outside a temporary copy of `infra/`):

```bash
cargo build --release --locked -p lk-cli
docker build -f infra/Dockerfile -t lastkeys/server:local .
LK_BIN=target/release/lk scripts/compose-smoke-test.sh
```

Desktop application (see also [apps/desktop/README.md](../apps/desktop/README.md)):

```bash
cd apps/desktop
npm ci && npm run lint && npm run typecheck && npm test && npm run test:e2e
npx tauri build --debug --no-bundle
LK_E2E_SERVER=http://127.0.0.1:18090 xvfb-run -a node e2e-tauri/run.mjs   # server optional
```

`cargo test` rebuilds `target/debug/last-keys` without the embedded
interface (it then loads the development server): run `npx tauri build
--debug --no-bundle` again before the WebDriver scenarios.

Browser extension (see also [apps/extension/README.md](../apps/extension/README.md)):

```bash
cd apps/extension
npm ci && npm run lint && npm run typecheck && npm test
LK_EXTENSION_E2E=1 npm run build            # dist/chrome, dist/firefox, dist/chrome-e2e
xvfb-run -a node e2e/run.mjs                # needs the desktop build above
```

Fuzzing (nightly toolchain and `cargo install cargo-fuzz`):

```bash
cd fuzz
cargo +nightly fuzz run envelope_parse -- -max_total_time=300 -use_value_profile=1
```

Targets: `envelope_parse`, `sealed_parse`, `recovery_parse`, `bundle_json`, `item_decode`.

KDF benchmark (always in release mode, on the device being measured):

```bash
cargo run --release -p lk-crypto --example kdf_bench
```

## Test inventory (M5)

| Crate | Suites | Tests | What it covers |
|-------|--------|-------|----------------|
| `lk-crypto` | unit (56), properties (10) | 66 | RNG; secret redaction; HKDF (RFC 5869 vector); Argon2id (bounds, NFC, reference-implementation vector); envelope (layout, every bit flip, every truncation, strict parsing, purpose/key/context binding); Ed25519 (RFC 8032 vector, domain separation); HPKE (round trip, binding, tampering, strict parsing, **cross-implementation vector**); recovery key (format vectors, lenient input, typos); parsers never panic (512 cases each) |
| `lk-core` | unit (15), flows (11) | 26 | Account creation/unlock, wrong credentials, hostile KDF parameters, substituted public keys, swapped private keys, versions, JSON round trips; complete lifecycle; item swap/move/relabel detection; vault-key account binding; forged/tampered certificates and revocations; transfer binding, refusal toward revoked or uncertified devices; device identity sealed under the account key |
| `lk-generator` | unit (13), statistics (2) | 15 | Policy constraints and errors, exact entropy, passphrase shape; **χ² uniformity over 10⁶ characters**; wordlist SHA-256 integrity |
| `lk-totp` | vectors (13), properties (3) | 16 | **RFC 4226 and RFC 6238 vectors** (SHA1/256/512, recomputed with Python `hmac`); otpauth parsing, round trip, reserved characters, rejections; clock skew; parsers never panic (1024 cases each) |
| `lk-vault` | unit (11), codec (7), properties (3) | 21 | URL/TOTP normalization, Luhn, field validation, bounded password history with restore/delete, search excludes secrets, fully redacted `Debug`; encrypted round trips; newer schema reported, unknown fields rejected, decoded items validated, size limits; decoder never panics |
| `lk-store` | store (11), sync state (7) | 18 | Create/open/refuse overwrite, reopen + unlock + decrypt, revisions/tombstones/change queue, rollback on failure, vault and account mismatch, password-change persistence, newer schema refused, tampered rows detected, owner-only files, **V-S1 canary test (no plaintext in database or WAL)**; sync metadata: monotonic cursors, server revisions, remote states applied without touching pending local changes, **rollback to an older revision refused**, server history per vault, full-resynchronization reset (live items queued, nothing local deleted), genuine migration from the frozen schema v1 to the latest |
| `lk-auth` | unit (2), opaque (8), properties (1) | 11 | OPAQUE: same session token on both sides, wrong key, unknown account indistinguishable (equal response length), identifier binding, tampering, serialization, foreign server secret, malformed input; server decoders never panic |
| `lk-protocol` | unit (2) | 2 | Wire format of error codes and push outcomes |
| `lk-server` | unit (1), auth (12), devices (5), sync (10), client sync (7) | 35 | **Against a real PostgreSQL** with a client built from the real crates: registration, login, enrollment, fake pre-login, wrong/unknown credentials, duplicate e-mail, closed registration, hostile bundles and certificates, single-use expiring attempts, recovery sessions, logout, rate limits; device enrollment, foreign certificates, revocation (immediate, permanent), forged revocations, immutable device keys; push/pull, decryption on another device, idempotent replays, conflicts, tombstones, misplaced/malformed items, account isolation, pagination, large items, oversized requests refused (256 KiB / 32 MiB, **V-Y6**), password change and recovery reset, bundle identity; **V-Y1** (no plaintext or password in the database); **multi-device synchronization over real HTTP with the `lk-sync` engine**: concurrent edits converge with a conflict copy (no version lost), deletion against edit keeps the edit, offline edits folded and retries safe, revoked device can no longer sync, wrong password cannot enroll; **restored backup detected** (new history, or cursor ahead of the server) and full resynchronization keeping every version without duplicate copies, then normal sync and a new device |
| `lk-sync` | unit (4) | 4 | Server URL policy (HTTPS only, plain HTTP only to the local machine), conflict copies marked and bounded in size, content comparison and content digest ignoring the modification time only |
| `lk-cli` | unit (1), end to end (6) | 7 | Real binary: full workflow (add/list/search/show/reveal/TOTP/edit/history/restore/delete/info), wrong password, recovery-key password reset and rotation, init guards, secrets refused as arguments, generator, item references |
| `lk-cli` (feature `server-e2e`) | sync end to end (2) | 2 | Real binary against an in-process server on PostgreSQL: registration (wrong recovery key refused), enrollment of a second device with e-mail + master password, edits propagated with password history, `devices`, `revoke` (revoked device locked out), password change and recovery-key reset updating the server credential, `sync --reset` against a healthy server changes nothing, third device enrolled with the reset password; plain HTTP to a remote host refused |
| `lk-autofill` | matching (9) | 9 | **V-A1**: exact host and same site, Public Suffix List ICANN and private sections (`alice.github.io` ≠ `bob.github.io`, `co.uk`), substring, suffix and user-info tricks, **look-alike Unicode domains never match** (punycode comparison, display in Unicode), IP addresses, IPv6, localhost and single-label hosts exact only, ports, **no https→http downgrade**, ineligible schemes (`file:`, `javascript:`, `data:`, browser and extension pages), stored URL and title for a saved login |
| `lk-bridge` | unit (12) | 12 | Frames (round trip, empty, oversized announcements refused before allocation, truncation); every request parsed, malformed and oversized requests refused, secrets redacted in `Debug`; **HMAC proofs bound to every input and direction, known-answer vector computed with Python** (shared with the extension); pairing codes from the unambiguous alphabet; endpoint names (socket path, per-user pipe name, case-insensitive); native host manifests and per-browser locations on Linux, macOS and Windows; relay arguments of Chromium and Firefox recognised, anything else refused |
| `lk-client` | unit (1), vault (9), autofill (7) | 17 | Autofill: candidates of a page only (look-alikes, other users' `github.io` sites, http pages excluded), ordering, **every fill re-checked against page and frame, frame of another origin needs confirmation, frame of another site refused even when confirmed**, copies limited to login fields of matching logins, save proposals (new, update, unchanged; case-insensitive usernames; a look-alike never updates the genuine login), saving with password history, updates refused for another site or username. Application layer: create/lock/unlock with password and recovery key, master password rules, edit drafts (keep/set/clear, history on replaced or removed passwords, kept custom fields and documents need their source, type changes refused, validation), **serialized views contain no secret**, explicit field access, TOTP (RFC 6238 vector), cards and identities, search never over secrets, references, local password change and recovery rotation, server operations refused before registration; every error code listed once |
| `lk-desktop` | unit (15), bridge (6) | 21 | Desktop back end without a window: onboarding rules, lock/unlock, **auto-lock after inactivity**, **clipboard cleared after the delay only if it still holds the secret, and on lock**, settings validation and persistence, re-authentication for sensitive operations (except after a recovery-key unlock), generator, items through drafts; every error code has an English translation in the UI; paired-browser store (`0600` file, no key in listings, limit), pairing broker (one request, growing delay after refusals), native host installation per browser and removal of our files only, application identifier equal to the Tauri configuration. **Bridge over a real socket**: pairing with the same code in the dialog, mutual authentication, origin-checked list/fill/copy/save, cross-origin frame confirmation, lock and unlock events, revocation closing every session, nothing before the relay's announcement, requests before authentication refused, wrong or replayed proofs, malformed and oversized frames, refused and busy pairings, one server per endpoint and clean stop; **the real executable in relay mode** with native messaging framing, and its `desktop_unavailable` answer |
| Desktop UI, Vitest | catalogues (8), contrast (39), drafts (5), screens (10) | 62 | French and English define the same keys and placeholders, plural pairs, French typography; **WCAG AA contrast (4.5:1) of every text colour pair in both themes**; editor drafts never load secrets; unlock, recovery key, onboarding rules, reveal/hide, auto-lock screen; browser integration (turn on, browsers, connected extensions, removal), pairing dialog with the code (closing refuses; shown over the unlock screen too), list refreshed after a login saved from the browser |
| Desktop UI, Playwright | `e2e/app.spec.ts` (10) | 10 | The built interface in Chromium with the scripted back end: first start to first item, password change and history restore, copy notice, search and filters, delete confirmation, generator options, language and theme switching, lock/unlock and auto-lock, device revocation, keyboard navigation |
| Desktop application, WebDriver | `e2e-tauri/run.mjs` | 1 scenario (12 steps) | **The real application** (Rust back end + UI, WebKitGTK) driven through tauri-driver: onboarding with Argon2id, add a login, explicit reveal, **copy to the system clipboard and automatic clearing** (read back with xclip), **registration and synchronization with a real `lk-server` on PostgreSQL**, device list verified with the account key, **no plaintext in the vault database or WAL**, lock and wrong password, generator, restart with the item persisted and an automatic sync, settings persisted. Run on the debug build and on the release package installed from the `.deb` |
| Extension, Vitest | content (15), background (23), popup (15), manifests (3) | 56 | Form detection (login, two-step, registration, password change, one-time codes, forms without `<form>`) and **hidden, off-screen, disabled and read-only fields never used**; filling with input/change events; generated passwords only into new-password fields; capture on submit, submit button and Enter, once per submission; **authentication vectors shared with Rust**, non-extractable key; session against a scripted desktop computing proofs independently: mutual authentication, **no proof sent to an impostor**, lock events, unknown or revoked pairing forgotten, pairing approved or refused, reconnection, **no notification loop and the pairing connection kept while the popup asks for the state**; router: page view, top-frame fill, cross-origin confirmation, every frame checked, ineligible pages, save/update/unchanged, submissions while locked, expiry, **concurrent frame reports all kept**, generated password only for frames of the page's origin, access to every site reported; popup in every state, French, confirmation, copy, save, generate, host access proposal; manifests (least privilege, IDs equal to the native host's list) |
| Autofill end to end | `apps/extension/e2e/run.mjs` | 1 scenario (12 steps) | **Real desktop application** (WebDriver) **+ Chromium with the extension** (Playwright) **+ native messaging** registered by the application: create a vault and a login, turn on browser integration (manifest written for Chromium), extension ID allowed by the host, **pairing with the same code in the popup and the desktop dialog**, fill into the page, **another site gets nothing**, **embedded form of another origin filled only after confirmation**, generated password into new-password fields, **submitted credentials saved into the desktop vault**, lock followed by the popup (no password field in the browser), revocation, no secret in the vault files |
| Compose smoke test | `scripts/compose-smoke-test.sh` | 1 scenario | Real images and Compose file: setup, all services healthy, HTTPS through Caddy, server runs as uid 10001, PostgreSQL not published; register + sync with the real `lk` binary; backup, one more change, destruction of every volume, restore of the older backup with `restore.sh`, sync refused until `lk sync --reset`, resynchronization uploading the missing item, enrollment of a new device that receives all items (**V-Y7**); canary item, master password and e-mail absent from a plain `pg_dump` and from the server logs (**V-Y1**) |
| Fuzz | `fuzz/fuzz_targets/` | 5 targets | Parsers never panic; accepted envelopes and sealed messages are canonical; recovery keys and items re-encode identically |

**Total: 282 Rust tests** (280 in the default feature set + 2 behind `server-e2e`), **72 desktop UI tests** (62 Vitest + 10 Playwright), **56 extension tests**, the real-application WebDriver scenario, the autofill end-to-end scenario and the Compose smoke scenario. Server and end-to-end tests require `LK_TEST_DATABASE_URL`; in CI they run in the `server-tests` job, the smoke test in `compose-smoke`, the UI tests in `desktop-ui`, the extension tests in `extension`, the real application and the autofill scenario in `desktop-app`.

## Manual autofill matrix (criterion V-A3)

Automated today: Chromium on Linux (above). Before v0.1, each cell below is
run by hand with the published builds and recorded here (date, versions,
result). Not run yet: ⬜.

| Check | Chrome Linux | Chrome Windows | Chrome macOS | Brave (any) | Firefox Linux | Firefox Windows | Firefox macOS |
|-------|--------------|----------------|--------------|-------------|---------------|-----------------|---------------|
| Turning on browser integration registers the browser ("Ready") | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Pairing: same code, approval in the desktop; refusal shown in the popup | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Access to every site proposed; declining keeps click-to-fill working | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Fill on a real login page (username + password), then the TOTP step | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Look-alike domain and another site: nothing offered | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Embedded login of another origin: confirmation | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Save after sign-up, update after a password change | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Copy username/password/code, clipboard cleared by the desktop | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Desktop locked: popup asks to unlock in the application | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Desktop closed: popup says it is not reachable | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| Revocation in the desktop disconnects the extension | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |

## Results — 2026-11-27, end of M5 (Linux x86_64, toolchain 1.97.0)

| Check | Result |
|-------|--------|
| `cargo fmt --check`, `cargo clippy -D warnings` (all targets, all features) | pass |
| `cargo test --workspace` with PostgreSQL 16 (dev profile) | 280 passed, 0 failed |
| `cargo test --workspace --exclude lk-server --release` | 245 passed, 0 failed |
| `cargo test -p lk-cli --features server-e2e --test sync_e2e` | 2 passed, 0 failed |
| `cargo check` wasm32-unknown-unknown (adds `lk-autofill`) | pass (compile only) |
| `cargo deny check`, `cargo doc -D warnings` | pass |
| Desktop UI: ESLint, TypeScript, Vitest, build, Playwright | pass (62 + 10 tests) |
| Desktop application, WebDriver, with a real server | 12/12 steps |
| Extension: `npm ls`, ESLint, TypeScript, Vitest, Chromium and Firefox builds | pass (56 tests) |
| Autofill end to end (desktop + Chromium + extension + native messaging) | 12/12 steps, run twice |
| Compose smoke test | not rerun (server and infrastructure unchanged since M3) |

## Results — 2026-11-25, end of M3 (Linux x86_64, toolchain 1.97.0)

| Check | Result |
|-------|--------|
| `cargo fmt --check` | pass |
| `cargo clippy -D warnings` (all targets, all features) | pass |
| `cargo test --workspace` with PostgreSQL 16 (dev profile) | 221 passed, 0 failed |
| `cargo test --workspace --exclude lk-server --release` | 186 passed, 0 failed |
| `cargo test -p lk-cli --features server-e2e --test sync_e2e` | 2 passed, 0 failed |
| Compose smoke test (`scripts/compose-smoke-test.sh`, Docker 29.9, amd64) | passed, including the restore of an older backup and `lk sync --reset` |
| `cargo check` wasm32-unknown-unknown (`lk-crypto`, `lk-core`, `lk-generator`, `lk-totp`) | pass (compile only) |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok |
| `scripts/check-advisory-unlinked.sh` | 0 `crypto_bigint` symbols linked (RUSTSEC-2026-0387 not reachable) |
| `cargo doc -D warnings` | pass |
| Fuzzing | no crash: `envelope_parse` 6.28 M runs (60 s), `sealed_parse` 5.98 M (60 s), `recovery_parse` 2.49 M (60 s), `bundle_json` 1.28 M (60 s), `item_decode` 0.99 M (45 s) |
| HPKE interoperability (V-C3) | pyhpke 0.6.5 (pyca/cryptography, OpenSSL) → `lk-crypto`: regression test; `lk-crypto` → pyhpke: verified once with a throw-away program (message opened by Python) |
| Windows, macOS | CI run 45630834635 (commit `dc25306`, M1): all jobs green, 90/90 tests on `windows-latest` and `macos-latest`. Later commits: see the CI run of each commit. |

## KDF benchmark campaign (criterion V-C8)

Goal: fix the default Argon2id parameters from measurements, so that unlock
stays ≤ 1 s on the reference low-end Android 10 device and ≤ 2 s in
WebAssembly on a mid-range laptop, with memory ≥ 64 MiB.

| Device | 64 MiB t=2 p=1 | 64 MiB t=3 p=1 | 64 MiB t=3 p=4 | 128 MiB t=3 p=4 | 256 MiB t=3 p=4 |
|--------|---------------|---------------|---------------|----------------|----------------|
| Server vCPU, Intel Xeon 2.1 GHz (dev container), native | 126 ms | 145 ms | 147 ms | 311 ms | 728 ms |
| Reference low-end Android 10 device | pending (needs the device) | | | | |
| iPhone (iOS 17 minimum device) | pending (needs the device) | | | | |
| Mid-range laptop, WASM in Chrome/Firefox | pending (browser harness, M13) | | | | |

Medians of 5 runs. The `argon2` crate computes lanes sequentially (the
`parallel` feature is not enabled), so `p` changes the memory layout but not
the wall-clock time on native targets.

## Test policy

* Every security property claimed in [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) has a
  test that fails if the property is broken (negative tests, not just round
  trips).
* Every parser of untrusted input gets property tests and a fuzz target.
* Known-answer vectors come from standards or from an independent
  implementation, never from the code under test.
* No test is skipped or disabled to make CI pass.
* Integration tests use only public APIs.
