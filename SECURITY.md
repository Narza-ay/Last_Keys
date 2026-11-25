# Security policy

## Reporting a vulnerability

Last Keys is not yet released. A private disclosure channel (dedicated
address, PGP key, response-time commitment) will be published here before the
first public release. Until then, report issues privately to the repository
owner; never in a public issue.

## Security principles

1. **End-to-end encryption.** All vault data is encrypted and decrypted on the
   client. Servers (official cloud or self-hosted) store ciphertext only and
   never hold decryption keys.
2. **No custom cryptography.** Only standard primitives from reviewed
   implementations (Argon2id, HKDF-SHA256, XChaCha20-Poly1305, HPKE, Ed25519)
   — see [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md).
3. **No hidden recovery.** Nobody, including the operator, can recover a vault
   without the master password, the recovery key or a trusted device.
4. **Independent device identities**, certified and revoked by the account
   key; clients compute device trust themselves.
5. **Fail closed.** Malformed, unexpected or unverifiable data is rejected.
6. **Honest claims.** Hardware protection, platform compatibility and feature
   availability are only claimed when verified.
7. **Minimal telemetry**, never containing secrets or vault data.

## Engineering controls in place

* `unsafe` code forbidden in workspace crates; strict Clippy lints forbid
  `unwrap`/`expect`/`panic` in production code; release builds abort on panic.
* Secrets zeroized on drop and redacted from `Debug` output.
* Pinned toolchain and dependencies; `cargo deny` (RustSec advisories,
  licenses, sources) in CI; Dependabot.
* Known-answer, negative, property-based and fuzz tests for every
  security-critical component ([docs/TESTING.md](docs/TESTING.md)).

## Threat model and limitations

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).

## Before production

An independent security audit of the cryptographic design and the
implementation is required before any production release (criteria V-C10 and
V-R2 in [docs/AUDIT.md](docs/AUDIT.md)).
