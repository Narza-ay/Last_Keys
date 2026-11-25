# ADR-0006: Browser cryptography through the Rust core compiled to WebAssembly

* Status: Accepted
* Date: 2026-11-25

## Context
The web application and the browser extensions must read and write the same
formats as native clients. WebCrypto offers neither Argon2id nor
XChaCha20-Poly1305 and its algorithm support varies across browsers.

## Decision
The web application and the extensions use `lk-crypto`/`lk-core` compiled to
`wasm32-unknown-unknown` through a future `lk-wasm` binding crate. Randomness
comes from `crypto.getRandomValues` (getrandom `wasm_js` backend). WebCrypto
may be used for non-extractable session keys that protect in-memory state.

## Consequences
* One implementation everywhere; CI checks the WASM build on every push.
* The CSP must allow `'wasm-unsafe-eval'` (but never `'unsafe-eval'`).
* Argon2id in WASM is slower than native: measured in the KDF campaign
  (criterion V-C8).
* JavaScript memory cannot be reliably zeroized; secrets stay inside WASM
  memory as much as possible and sessions are short.

## Alternatives considered
* A TypeScript implementation (libsodium.js + argon2 WASM): rejected — a
  second implementation of the formats to keep in sync and audit.
