# Last Keys

**Your passwords. Your keys. Your control.**

Last Keys is a premium, cross-platform password manager and digital identity
vault with end-to-end encryption, independent device identities, offline use,
cloud, self-hosted and peer-to-peer synchronization.

> **Project status — milestone M1 (2026-11-25).** The cryptographic core and
> the key hierarchy are implemented and tested. There is **no usable
> application yet**: no UI, no server, no storage. See the
> [roadmap](ROADMAP.md) for what comes next and
> [known limitations](docs/KNOWN_LIMITATIONS.md) for what does not work.

## What exists today

| Component | Status |
|-----------|--------|
| `crates/lk-crypto` — Argon2id, HKDF, XChaCha20-Poly1305 envelopes, HPKE, Ed25519, recovery key | ✅ implemented, tested, fuzzed |
| `crates/lk-core` — account key hierarchy, password change, recovery-key rotation, vault/item keys, device identities, certificates, revocations, trusted-device transfer | ✅ implemented, tested |
| CI: format, Clippy, tests on Linux/Windows/macOS, WebAssembly check, dependency policy, docs, nightly fuzzing | ✅ configured |
| Applications (desktop, mobile, extension, web, server, CLI) | ⬜ not started — see [`apps/`](apps) |

## Build and test

Requirements: Rust via `rustup` (the pinned toolchain in
`rust-toolchain.toml` installs automatically).

```bash
cargo test --workspace --locked
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
