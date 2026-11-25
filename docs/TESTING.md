# Testing

## How to run

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked              # dev profile (dependencies optimized)
cargo test --workspace --locked --release    # production profile (panic = abort)
cargo check -p lk-core -p lk-crypto -p lk-generator -p lk-totp --target wasm32-unknown-unknown --locked
cargo deny check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --document-private-items
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

## Test inventory (M2)

| Crate | Suites | Tests | What it covers |
|-------|--------|-------|----------------|
| `lk-crypto` | unit (56), properties (10) | 66 | RNG; secret redaction; HKDF (RFC 5869 vector); Argon2id (bounds, NFC, reference-implementation vector); envelope (layout, every bit flip, every truncation, strict parsing, purpose/key/context binding); Ed25519 (RFC 8032 vector, domain separation); HPKE (round trip, binding, tampering, strict parsing, **cross-implementation vector**); recovery key (format vectors, lenient input, typos); parsers never panic (512 cases each) |
| `lk-core` | unit (15), flows (11) | 26 | Account creation/unlock, wrong credentials, hostile KDF parameters, substituted public keys, swapped private keys, versions, JSON round trips; complete lifecycle; item swap/move/relabel detection; vault-key account binding; forged/tampered certificates and revocations; transfer binding, refusal toward revoked or uncertified devices; device identity sealed under the account key |
| `lk-generator` | unit (13), statistics (2) | 15 | Policy constraints and errors, exact entropy, passphrase shape; **χ² uniformity over 10⁶ characters**; wordlist SHA-256 integrity |
| `lk-totp` | vectors (13), properties (3) | 16 | **RFC 4226 and RFC 6238 vectors** (SHA1/256/512, recomputed with Python `hmac`); otpauth parsing, round trip, reserved characters, rejections; clock skew; parsers never panic (1024 cases each) |
| `lk-vault` | unit (11), codec (7), properties (3) | 21 | URL/TOTP normalization, Luhn, field validation, bounded password history with restore/delete, search excludes secrets, fully redacted `Debug`; encrypted round trips; newer schema reported, unknown fields rejected, decoded items validated, size limits; decoder never panics |
| `lk-store` | store (11) | 11 | Create/open/refuse overwrite, reopen + unlock + decrypt, revisions/tombstones/change queue, rollback on failure, vault and account mismatch, password-change persistence, newer schema refused, tampered rows detected, owner-only files, **V-S1 canary test (no plaintext in database or WAL)** |
| `lk-auth` | unit (2), opaque (8), properties (1) | 11 | OPAQUE: same session token on both sides, wrong key, unknown account indistinguishable (equal response length), identifier binding, tampering, serialization, foreign server secret, malformed input; server decoders never panic |
| `lk-protocol` | unit (2) | 2 | Wire format of error codes and push outcomes |
| `lk-server` | unit (1), auth (12), devices (5), sync (9) | 27 | **Against a real PostgreSQL** with a client built from the real crates: registration, login, enrollment, fake pre-login, wrong/unknown credentials, duplicate e-mail, closed registration, hostile bundles and certificates, single-use expiring attempts, recovery sessions, logout, rate limits; device enrollment, foreign certificates, revocation (immediate, permanent), forged revocations, immutable device keys; push/pull, decryption on another device, idempotent replays, conflicts, tombstones, misplaced/malformed items, account isolation, pagination, large items, password change and recovery reset, bundle identity; **V-Y1** (no plaintext or password in the database) |
| `lk-cli` | unit (1), end to end (6) | 7 | Real binary: full workflow (add/list/search/show/reveal/TOTP/edit/history/restore/delete/info), wrong password, recovery-key password reset and rotation, init guards, secrets refused as arguments, generator, item references |
| Fuzz | `fuzz/fuzz_targets/` | 5 targets | Parsers never panic; accepted envelopes and sealed messages are canonical; recovery keys and items re-encode identically |

**Total: 202 tests** (server tests require `LK_TEST_DATABASE_URL`, e.g. `postgres://lastkeys:lastkeys-dev@127.0.0.1/postgres` with `CREATEDB` rights; in CI they run in the `server-tests` job).

## Results — 2026-11-25 (Linux x86_64, toolchain 1.97.0)

| Check | Result |
|-------|--------|
| `cargo fmt --check` | pass |
| `cargo clippy -D warnings` (all targets) | pass |
| `cargo test` (dev and release) | 162 passed, 0 failed |
| `cargo check` wasm32-unknown-unknown (`lk-crypto`, `lk-core`, `lk-generator`, `lk-totp`) | pass (compile only) |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok (one warning: duplicate `syn` versions, build-time only) |
| `cargo doc -D warnings` | pass |
| Fuzzing | no crash: `envelope_parse` 6.28 M runs (60 s), `sealed_parse` 5.98 M (60 s), `recovery_parse` 2.49 M (60 s), `bundle_json` 1.28 M (60 s), `item_decode` 0.99 M (45 s) |
| HPKE interoperability (V-C3) | pyhpke 0.6.5 (pyca/cryptography, OpenSSL) → `lk-crypto`: regression test; `lk-crypto` → pyhpke: verified once with a throw-away program (message opened by Python) |
| Windows, macOS | CI run 45630834635 (commit `dc25306`, M1): all jobs green, 90/90 tests on `windows-latest` and `macos-latest`. M2 commits: see the CI run of each commit. |

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
