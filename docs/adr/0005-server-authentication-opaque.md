# ADR-0005: Server authentication with OPAQUE

* Status: **Proposed** — requires owner approval before Phase 3 (AUDIT decision 5)
* Date: 2026-11-25

## Context
The master password must never be transmitted and server authentication must
be separate from vault encryption. A classic "hash of a hash" login sends a
password-equivalent to the server at every login and leaves the server with a
verifier that enables cheap offline guessing if the KDF is skipped.

## Decision (proposed)
* Use OPAQUE (aPAKE, RFC 9807) via the `opaque-ke` crate (latest stable 4.x;
  maintained by Meta, reviewed by NCC Group in an earlier version — to
  re-verify at adoption).
* OPAQUE's password input is the **server auth key** derived by HKDF from the
  Argon2id master key (`MasterKey::server_auth_key`), with an identity key
  stretching function inside OPAQUE: Argon2id runs once per login on the
  client.
* Recovery authentication uses the same protocol with the recovery auth key.
* After OPAQUE, sessions are bound to the device signing key (signed requests).

## Consequences
* The server never sees the password or a value that logs the user in.
* A stolen server database still requires Argon2id work per guess.
* E-mail enumeration resistance is provided by OPAQUE's fake-record handling.

## Alternatives considered
* SRP-6a: older aPAKE with weaker security proofs and fewer maintained Rust
  implementations.
* Hash-based login (Bitwarden-style): simpler but transmits a
  password-equivalent at each login.
