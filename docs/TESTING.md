# Testing

## How to run

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked --exclude lk-server             # dev profile (dependencies optimized)
cargo test --workspace --locked --exclude lk-server --release   # production profile (panic = abort)
cargo check -p lk-core -p lk-crypto -p lk-generator -p lk-totp --target wasm32-unknown-unknown --locked
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

## Test inventory (M3)

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
| Compose smoke test | `scripts/compose-smoke-test.sh` | 1 scenario | Real images and Compose file: setup, all services healthy, HTTPS through Caddy, server runs as uid 10001, PostgreSQL not published; register + sync with the real `lk` binary; backup, one more change, destruction of every volume, restore of the older backup with `restore.sh`, sync refused until `lk sync --reset`, resynchronization uploading the missing item, enrollment of a new device that receives all items (**V-Y7**); canary item, master password and e-mail absent from a plain `pg_dump` and from the server logs (**V-Y1**) |
| Fuzz | `fuzz/fuzz_targets/` | 5 targets | Parsers never panic; accepted envelopes and sealed messages are canonical; recovery keys and items re-encode identically |

**Total: 223 tests** (221 in the default feature set + 2 behind `server-e2e`) plus the Compose smoke scenario. Server and end-to-end tests require `LK_TEST_DATABASE_URL`; in CI they run in the `server-tests` job, the smoke test in the `compose-smoke` job.

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
| Mid-range laptop, WASM in Chrome/Firefox | pending (browser harness, M4/M5) | | | | |

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
