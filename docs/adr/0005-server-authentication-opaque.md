# ADR-0005: Server authentication with OPAQUE

* Status: Accepted (approved by the owner on 2026-11-25, AUDIT decision 5)
* Date: 2026-11-25

## Context
The master password must never be transmitted and server authentication must
be separate from vault encryption. A classic "hash of a hash" login sends a
password-equivalent to the server at every login and leaves the server with a
verifier that enables cheap offline guessing if the KDF is skipped.

## Decision
* **Protocol:** OPAQUE (aPAKE, RFC 9807) through the `opaque-ke` crate,
  version 4.0.1 (implements RFC 9807; the library was audited by NCC Group in
  2021, findings fixed in 1.2.0). Cipher suite: OPRF over Ristretto255,
  3DH key exchange over Ristretto255 with SHA-512.
* **Password input:** the *server auth key* derived by HKDF from the Argon2id
  master key (`PasswordKeys::auth_key`), never the password itself.
* **Key stretching inside OPAQUE:** `Identity`. Stretching already happened
  client-side (Argon2id with the bounded parameters of ADR-0002), so a thief
  of the server database must still pay one full Argon2id per password guess
  (guess → Argon2id → HKDF → OPRF). Running Argon2id a second time inside
  OPAQUE would double login time without adding security.
* **Credential identifier:** the account e-mail, trimmed and lower-cased.
  Unknown e-mails get OPAQUE's fake response (indistinguishable), and the
  pre-login KDF configuration for an unknown e-mail is a deterministic fake
  derived from a server secret, so the API does not reveal which e-mails have
  accounts.
* **Recovery:** a second OPAQUE registration per account, with the recovery
  auth key (`RecoveryKey::server_auth_key`) and the credential identifier
  `recovery:<e-mail>`.
* **Session token:** after a successful login both sides derive
  `token = HKDF-SHA256(OPAQUE session key, "lastkeys/v1/session-token")`. The
  token is never sent in the login response; the server stores only
  `SHA-256(token)`. Sessions are bound to one device, expire, and are deleted
  when the device is revoked.
* **Server secret:** the OPAQUE `ServerSetup` (OPRF seed, server key pair) is
  generated once, kept **outside the database** (a file referenced by the
  server configuration, mounted as a secret in Docker), never logged.
  Losing it invalidates every OPAQUE registration (users re-register from a
  device that is still unlocked); leaking it together with the database
  enables offline guessing at the Argon2id cost.

## Consequences
* The server never sees the password or a value that logs the user in.
* A stolen server database still requires Argon2id work per guess.
* `opaque-ke` 4.0.1 uses the previous generation of RustCrypto crates
  (`digest` 0.10, `curve25519-dalek` 4): duplicate crate versions in the
  build, isolated in `lk-auth`. Re-evaluate when `opaque-ke` 5 is stable.
* The web application and extension need the client half in WebAssembly
  (to verify at M4/M5).
* RUSTSEC-2026-0387 (timing variability in `crypto-bigint` 0.5, pulled in by
  `elliptic-curve` 0.13) cannot be fixed within `opaque-ke` 4. With our
  Ristretto255 suite the affected code is not linked: verified on an
  unoptimized build (0 `crypto_bigint` symbols vs 227 `curve25519_dalek`),
  and re-verified on every CI run (`scripts/check-advisory-unlinked.sh`).
  The advisory is ignored in `deny.toml` on that basis only. `opaque-ke`
  5.0 (pre-release at the time of writing) moves to the patched stack;
  migrate once it is stable.

## Alternatives considered
* SRP-6a: older aPAKE with weaker security proofs and fewer maintained Rust
  implementations.
* Hash-based login (Bitwarden-style): simpler but transmits a
  password-equivalent at each login.
