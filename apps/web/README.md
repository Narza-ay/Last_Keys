# Web application

**Status: not started — milestone M13 (after the MVP).** Nothing in this directory is functional yet.

Planned: React + TypeScript, cryptography through `lk-wasm` (ADR-0006), strict
CSP (`'wasm-unsafe-eval'` only), Subresource Integrity, no third-party
scripts, no decrypted data in persistent browser storage, ephemeral session
identity. Inherent limitation: the server delivers the code (AUDIT P-7); the
web app can be disabled in self-hosted deployments.
