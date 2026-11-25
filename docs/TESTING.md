# Testing

## How to run

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked              # dev profile (dependencies optimized)
cargo test --workspace --locked --release    # production profile (panic = abort)
cargo check -p lk-core -p lk-crypto --target wasm32-unknown-unknown --locked
cargo deny check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --document-private-items
```

Fuzzing (nightly toolchain and `cargo install cargo-fuzz`):

```bash
cd fuzz
cargo +nightly fuzz run envelope_parse -- -max_total_time=300 -use_value_profile=1
```

Targets: `envelope_parse`, `sealed_parse`, `recovery_parse`, `bundle_json`.

KDF benchmark (always in release mode, on the device being measured):

```bash
cargo run --release -p lk-crypto --example kdf_bench
```

## Test inventory (M1)

| Suite | Location | Count | What it covers |
|-------|----------|-------|----------------|
| `lk-crypto` unit | `crates/lk-crypto/src/**` | 55 | RNG, secret redaction, HKDF (RFC 5869 vector), Argon2id (bounds, NFC, reference-implementation vector), envelope (layout, every bit flip, every truncation, strict parsing, purpose/key/context binding), Ed25519 (RFC 8032 vector, domain separation), HPKE (round trip, binding, tampering, strict parsing), recovery key (format vectors, lenient input, typo detection) |
| `lk-crypto` properties | `crates/lk-crypto/tests/properties.rs` | 10 (9 × 512 cases + 1 × 256 iterations) | Parsers never panic; envelope and HPKE round trips for arbitrary inputs; any single-byte modification rejected; context binding |
| `lk-core` unit | `crates/lk-core/src/**` | 15 | Account creation/unlock, wrong credentials, hostile KDF parameters, substituted public keys, swapped private keys, format versions, JSON round trips, identifiers, canonical encoding |
| `lk-core` integration | `crates/lk-core/tests/flows.rs` | 10 | Complete lifecycle (account → vault → items → second device by trusted transfer → revocation → password change → recovery-key rotation), item swap/move/relabel/alteration detection, vault-key account binding, forged/tampered device certificates and revocations, transfer binding to sender/recipient, refusal toward revoked or uncertified devices, cross-account key confusion |
| Fuzz | `fuzz/fuzz_targets/` | 4 targets | Parsers never panic; accepted envelopes and sealed messages are canonical; recovery keys re-parse identically |

## Results — 2026-11-25 (Linux x86_64, toolchain 1.97.0)

| Check | Result |
|-------|--------|
| `cargo fmt --check` | pass |
| `cargo clippy -D warnings` (all targets) | pass |
| `cargo test` (dev) | 90 passed, 0 failed |
| `cargo test --release` | 90 passed, 0 failed |
| `cargo check` wasm32-unknown-unknown | pass (compile only) |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok (one warning: duplicate `syn` versions, build-time only) |
| `cargo doc -D warnings` | pass |
| Fuzzing, 60 s per target | no crash: `envelope_parse` 6.28 M runs, `sealed_parse` 5.98 M, `recovery_parse` 2.49 M, `bundle_json` 1.28 M |
| Windows, macOS | CI run 45630834635 (commit `dc25306`): all 7 jobs green; 90/90 tests pass on `windows-latest` and `macos-latest` (dev and release) |

## KDF benchmark campaign (criterion V-C8)

Goal: fix the default Argon2id parameters from measurements, so that unlock
stays ≤ 1 s on the reference low-end Android 10 device and ≤ 2 s in
WebAssembly on a mid-range laptop, with memory ≥ 64 MiB.

| Device | 64 MiB t=2 p=1 | 64 MiB t=3 p=1 | 64 MiB t=3 p=4 | 128 MiB t=3 p=4 | 256 MiB t=3 p=4 |
|--------|---------------|---------------|---------------|----------------|----------------|
| Server vCPU, Intel Xeon 2.1 GHz (dev container), native | 126 ms | 145 ms | 147 ms | 311 ms | 728 ms |
| Reference low-end Android 10 device | pending | | | | |
| iPhone (iOS 17 minimum device) | pending | | | | |
| Mid-range laptop, WASM in Chrome/Firefox | pending | | | | |

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
