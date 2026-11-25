# Changelog

All notable changes are documented here. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
semantic versioning once releases begin.

## [Unreleased]

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
