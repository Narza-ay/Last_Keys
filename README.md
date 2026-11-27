# Last Keys

**Your passwords. Your keys. Your control.**

Last Keys is a premium, cross-platform password manager and digital identity
vault with end-to-end encryption, independent device identities, offline use,
cloud, self-hosted and peer-to-peer synchronization.

> **Project status — milestone M4 (2026-11-26).** The cryptographic core,
> the synchronization server (self-hostable with Docker Compose), the `lk`
> command-line client and the **desktop application** (Tauri, French and
> English) work end to end. The desktop app is tested on Linux; Windows and
> macOS installers are built by CI but not yet tested on real machines. See
> the [roadmap](ROADMAP.md) and the [known limitations](docs/KNOWN_LIMITATIONS.md).

## What exists today

| Component | Status |
|-----------|--------|
| `crates/lk-crypto` — Argon2id, HKDF, XChaCha20-Poly1305 envelopes, HPKE, Ed25519, recovery key | ✅ implemented, tested, fuzzed |
| `crates/lk-core` — account key hierarchy, password change, recovery-key rotation, vault/item keys, device identities, certificates, revocations, trusted-device transfer | ✅ implemented, tested |
| `crates/lk-generator` — passwords and passphrases (OS CSPRNG, exact entropy) | ✅ implemented, tested |
| `crates/lk-totp` — HOTP/TOTP (RFC 4226/6238), `otpauth://` URIs | ✅ implemented, tested |
| `crates/lk-vault` — item schema v1 (logins, notes, cards, identities), validation, password history | ✅ implemented, tested, fuzzed |
| `crates/lk-store` — local encrypted SQLite store with offline change queue and sync state | ✅ implemented, tested |
| `crates/lk-auth`, `crates/lk-protocol` — OPAQUE authentication (RFC 9807), API v1 types | ✅ implemented, tested |
| `crates/lk-sync` — client synchronization engine (conflict copies, rollback detection) | ✅ implemented, tested against the real server |
| `apps/server` — synchronization server (axum, PostgreSQL 16) | ✅ implemented, tested against PostgreSQL |
| `infra/` — Docker Compose self-hosting (Caddy TLS, backup/restore) | ✅ verified by an end-to-end smoke test in CI |
| `crates/lk-client` — application layer shared by every client | ✅ implemented, tested |
| `crates/lk-autofill` — which login may be used on which web page (Public Suffix List, punycode, ports) | ✅ implemented, tested |
| `crates/lk-bridge` — browser bridge protocol: frames, pairing, mutual authentication, native messaging manifests | ✅ implemented, tested |
| `apps/desktop` — desktop application (Tauri 2, React), FR/EN, light/dark themes, browser bridge | ✅ Linux tested end to end; Windows/macOS built by CI |
| `apps/extension` — browser extension (Manifest V3, Chrome/Brave/Firefox) connected to the desktop application | ✅ Chromium on Linux tested end to end; Firefox built, not driven end to end |
| `apps/cli` — `lk` command-line client (local vault and synchronization) | ✅ implemented, tested end to end |
| CI: format, Clippy, tests on Linux/Windows/macOS, server tests on PostgreSQL, Compose smoke test, desktop UI and real-app tests, extension tests and builds, autofill end to end, desktop installers, WebAssembly check, dependency policy, docs, nightly fuzzing | ✅ configured |
| Mobile, web | ⬜ not started — see [`apps/`](apps) |

## Build and test

Requirements: Rust via `rustup` (the pinned toolchain in
`rust-toolchain.toml` installs automatically).

```bash
cargo test --workspace --locked --exclude lk-server   # server tests need PostgreSQL, see docs/TESTING.md
cargo run --release -p lk-cli -- --help
```

Self-hosting the server: [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md).

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
| [docs/API.md](docs/API.md), [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) | Server API, CI and deployment, self-hosting |
| [docs/adr/](docs/adr) | Architecture decision records |
| [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md) | Workflow and history |

## License

Proprietary — all rights reserved. See [LICENSE](LICENSE).
