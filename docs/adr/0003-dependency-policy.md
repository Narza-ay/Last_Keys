# ADR-0003: Dependency policy and pinned cryptographic stack

* Status: Accepted
* Date: 2026-11-25

## Context
The spec requires maintained, reputable, pinned dependencies with continuous
vulnerability monitoring, and a proprietary license compatible with them.

## Decision
* Dependencies are declared once in `[workspace.dependencies]` with explicit
  versions; exact resolution is pinned by the committed `Cargo.lock`; CI builds
  with `--locked`.
* `cargo deny check` (advisories, licenses, bans, sources) runs in CI. Only
  permissive licenses are accepted (currently MIT, Apache-2.0, BSD-3-Clause,
  Unicode-3.0, Zlib); copyleft licenses are refused because the product is
  proprietary and statically linked. Only crates.io is allowed as a source.
* Dependabot proposes updates weekly; updates are reviewed, never auto-merged.
* Before adding a dependency: check maintenance (recent releases, active
  repository), security history (RustSec), platform support (including
  `wasm32-unknown-unknown`, Android, iOS), license, and transitive weight.
  Record the review in the pull request.

Cryptographic stack (reviewed 2026-11-25):

| Crate | Version | Notes |
|-------|---------|-------|
| `argon2` | 0.6.0 | RustCrypto; output cross-checked against libargon2 |
| `chacha20poly1305` | 0.11.0 | RustCrypto AEADs |
| `hkdf` / `sha2` | 0.13.0 / 0.11.1 | RustCrypto; RFC 5869 vector in tests |
| `ed25519-dalek` | 3.0.0 | dalek-cryptography; RFC 8032 vector in tests |
| `hpke` | 0.15.1 | RFC 9180 implementation with upstream known-answer tests; also implements X-Wing (hybrid post-quantum), reserved as suite 2. No public independent audit identified at review time — covered by our own interoperability vector (V-C3) and the independent review (V-C10). |
| `getrandom` | 0.4.3 | OS CSPRNG; `wasm_js` backend on browsers |
| `zeroize`, `subtle` | 1.9.2, 2.6.1 | zeroization, constant-time comparison |

## Consequences
Adding a dependency is a reviewed change. The lock file must be committed and
kept current.

## Alternatives considered
Vendoring all sources: deferred to release engineering (Phase 8) if
reproducible builds require it.
