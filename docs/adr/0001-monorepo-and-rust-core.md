# ADR-0001: Monorepo with a shared Rust core

* Status: Accepted
* Date: 2026-11-25

## Context
Last Keys targets seven client surfaces (Windows, macOS, Linux, Android, iOS,
web, browser extensions) plus a server. Cryptographic formats must be
identical everywhere; a divergence between implementations would corrupt
vaults or create vulnerabilities.

## Decision
* One private monorepo containing the Rust workspace (`crates/`), the
  applications (`apps/`), infrastructure and documentation.
* All cryptography and domain logic lives in Rust crates (`lk-crypto`,
  `lk-core`, later `lk-vault`, `lk-store`, `lk-sync`, ...), consumed by:
  Tauri (direct linking), Android/iOS (UniFFI), web app and extension
  (WebAssembly), server and CLI (direct).
* The core performs no I/O and reads no clock; platforms provide adapters.
* Toolchain pinned (`rust-toolchain.toml`), edition 2024, `unsafe` forbidden
  in workspace crates, strict Clippy lints (no `unwrap`/`expect`/`panic` in
  production code).

## Consequences
* One implementation to test, fuzz and audit; formats cannot diverge.
* Mobile and web builds depend on FFI/WASM toolchains (UniFFI, wasm-bindgen),
  added in their milestones. WASM compatibility is checked in CI from day one.
* Contributors need Rust in addition to each platform's language.

## Alternatives considered
* Per-platform implementations (Kotlin, Swift, TypeScript): rejected —
  multiplies the cryptographic attack surface and the audit cost.
* Polyrepo: rejected — cross-cutting format changes would need coordinated
  releases across repositories.
