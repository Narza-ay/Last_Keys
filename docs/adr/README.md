# Architecture Decision Records

Every significant technical decision is recorded here (spec §19). An ADR is
never edited after acceptance except to change its status; a new ADR
supersedes it.

Statuses: **Proposed** (awaiting owner approval) · **Accepted** · **Superseded by ADR-xxxx**.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-monorepo-and-rust-core.md) | Monorepo with a shared Rust core | Accepted |
| [0002](0002-key-hierarchy.md) | Key hierarchy v1 | Accepted (format v1; independent review pending) |
| [0003](0003-dependency-policy.md) | Dependency policy and pinned cryptographic stack | Accepted |
| [0004](0004-envelope-format.md) | Versioned envelope with context binding | Accepted |
| [0005](0005-server-authentication-opaque.md) | Server authentication with OPAQUE | Accepted |
| [0006](0006-web-crypto-via-wasm.md) | Browser cryptography through the Rust core compiled to WebAssembly | Accepted |
| [0007](0007-mvp-first-delivery.md) | MVP-first delivery order | Accepted |
| [0008](0008-sync-protocol.md) | Synchronization protocol v1 | Accepted |
| [0009](0009-server-stack.md) | Server technology stack | Accepted |

Template: copy `0000-template.md`.
