# Changelog

All notable changes are documented here. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
semantic versioning once releases begin.

## [Unreleased]

### Added — M3 (in progress, 2026-11-25)
- ADR-0005 accepted (OPAQUE), ADR-0008 (sync protocol), ADR-0009 (server
  stack); AUDIT decisions 3 and 5 resolved.
- `lk-auth`: OPAQUE registration and login (opaque-ke 4.0.1), session tokens
  derived from the OPAQUE session key and stored hashed.
- `lk-protocol`: API v1 types.
- `lk-server`: pre-login, registration, login, sessions (full, enrollment,
  recovery), credential replacement, devices and revocation, vault keys,
  push/pull synchronization, rate limits, migrations; `generate-secret`,
  `migrate`, `serve` commands.
- Security: RUSTSEC-2026-0387 exception justified by proof that the affected
  code is not linked, enforced by the `advisory-guard` CI job.
- CI: server integration tests with a PostgreSQL 16 service.

### Added — M2: local vault (2026-11-25)
- `lk-generator`: password generator (classes, minimums, exclusions,
  uniform draws, Fisher–Yates shuffle) and EFF-wordlist passphrases, with
  exact entropy; χ² uniformity test.
- `lk-totp`: HOTP/TOTP (SHA1/256/512, 6–8 digits), `otpauth://` parsing and
  generation, clock-skew assessment; RFC 4226/6238 vectors.
- `lk-vault`: item schema v1 (logins with URLs/TOTP/backup codes, secure
  notes, payment cards, identities with documents; folders, tags, notes,
  custom fields), validation, bounded password history with restore/delete,
  metadata-only search, fully redacted `Debug`; JSON codec with schema probe.
- `lk-store`: SQLite local store (WAL, `synchronous=FULL`, foreign keys,
  `secure_delete`, owner-only files), transactional writes, tombstones,
  offline change queue, forward-only migrations; canary test proving no
  plaintext reaches the disk.
- `lk` CLI: init, info, add/list/show/edit/delete, history, totp, generate,
  passwd (including recovery-key reset), recovery rotate; secrets never
  accepted as arguments.
- `lk-core`: device identity sealed under the account key; `ChangeId`.
- HPKE cross-implementation vector with pyhpke/OpenSSL; `item_decode` fuzz
  target; `NOTICE` (EFF wordlist attribution).
- CI: `actions/checkout@v5`; WebAssembly check covers the new portable crates.

### Added — M0: foundation (2026-11-25)
- Rust workspace (edition 2024) with pinned toolchain 1.97.0, centrally pinned
  dependencies, committed lock file and strict lints (`unsafe` forbidden, no
  `unwrap`/`expect`/`panic` in production code, `panic = "abort"` in release).
- CI: formatting, Clippy, tests on Linux/Windows/macOS (dev and release
  profiles), WebAssembly build check, `cargo deny`, rustdoc; nightly fuzzing
  workflow; Dependabot.
- Documentation: specification, coherence audit with validation criteria,
  architecture, cryptographic specification, threat model, roadmap, testing,
  platform compatibility, privacy, known limitations, API/deployment/
  self-hosting (planned components), ADRs 0001–0007, status READMEs for every
  future application.

### Added — M1: cryptographic core (2026-11-25)
- `lk-crypto`: OS CSPRNG access; NFC master-password normalization; Argon2id
  with enforced parameter bounds; HKDF-SHA256 with a label registry;
  versioned XChaCha20-Poly1305 envelope with purpose, key identifier and
  context binding; key wrapping; Ed25519 signatures with domain separation;
  HPKE (RFC 9180) sealing and key transfer; recovery key with Crockford Base32
  display and checksum.
- `lk-core`: account creation; `AccountKeyBundle` unlock by password,
  pre-derived password keys, recovery key or transferred account key, with
  public-key consistency checks; password change and recovery-key rotation
  without re-encryption; vault keys and per-item keys with location-bound
  ciphertexts; device identities with sealed storage; account-signed device
  certificates and revocations; trusted-device list computation; signed
  HPKE account-key transfer refused toward uncertified or revoked devices.
- Tests: 90 unit/integration/property tests, 4 fuzz targets, Argon2id
  benchmark example.
