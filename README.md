# Last Keys

**Your passwords. Your keys. Your control.**

Last Keys is a premium, cross-platform password manager and digital identity
vault with end-to-end encryption, independent device identities, offline use,
cloud, self-hosted and peer-to-peer synchronization.

> **Project status — milestone M2 (2026-11-25).** The cryptographic core,
> the vault model, the local encrypted store and the `lk` command-line client
> work end to end on one device. There is **no graphical application and no
> server yet**. See the [roadmap](ROADMAP.md) for what comes next and
> [known limitations](docs/KNOWN_LIMITATIONS.md) for what does not work.

## What exists today

| Component | Status |
|-----------|--------|
| `crates/lk-crypto` — Argon2id, HKDF, XChaCha20-Poly1305 envelopes, HPKE, Ed25519, recovery key | ✅ implemented, tested, fuzzed |
| `crates/lk-core` — account key hierarchy, password change, recovery-key rotation, vault/item keys, device identities, certificates, revocations, trusted-device transfer | ✅ implemented, tested |
| `crates/lk-generator` — passwords and passphrases (OS CSPRNG, exact entropy) | ✅ implemented, tested |
| `crates/lk-totp` — HOTP/TOTP (RFC 4226/6238), `otpauth://` URIs | ✅ implemented, tested |
| `crates/lk-vault` — item schema v1 (logins, notes, cards, identities), validation, password history | ✅ implemented, tested, fuzzed |
| `crates/lk-store` — local encrypted SQLite store with offline change queue | ✅ implemented, tested |
| `apps/cli` — `lk` command-line client (local) | ✅ implemented, tested end to end |
| CI: format, Clippy, tests on Linux/Windows/macOS, WebAssembly check, dependency policy, docs, nightly fuzzing | ✅ configured |
| Server, desktop, browser extension, mobile, web | ⬜ not started — see [`apps/`](apps) |

## Build and test

Requirements: Rust via `rustup` (the pinned toolchain in
`rust-toolchain.toml` installs automatically).

```bash
cargo test --workspace --locked
cargo run --release -p lk-cli -- --help
```

Full verification commands: [docs/TESTING.md](docs/TESTING.md).

## Documentation

| Document | Content |
|----------|---------|
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | Locked product specification and owner decisions |
| [docs/AUDIT.md](docs/AUDIT.md) | Coherence audit, open decisions, technical validation criteria |
| [ROADMAP.md](ROADMAP.md) | MVP definition and milestones |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, crates, data flows, platform adapters |
| [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) | Normative cryptographic formats |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, adversaries, mitigations, residual risks |
| [SECURITY.md](SECURITY.md) | Security policy and principles |
| [docs/TESTING.md](docs/TESTING.md) | Test strategy, inventory and results |
| [docs/PLATFORM_COMPATIBILITY.md](docs/PLATFORM_COMPATIBILITY.md) | What is verified on which platform |
| [docs/PRIVACY.md](docs/PRIVACY.md) | What the server can and cannot see |
| [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) | Current and permanent limitations |
| [docs/API.md](docs/API.md), [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) | Server-side documentation (planned components) |
| [docs/adr/](docs/adr) | Architecture decision records |
| [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md) | Workflow and history |

## License

Proprietary — all rights reserved. See [LICENSE](LICENSE).
