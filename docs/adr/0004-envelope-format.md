# ADR-0004: Versioned envelope with context binding

* Status: Accepted
* Date: 2026-11-25

## Context
Spec §5.2: every encrypted object needs a versioned envelope with algorithm
identifiers and integrity data; nonces must never repeat under a key; formats
must evolve without breaking existing data.

## Decision
A fixed 46-byte header (magic, version, suite, purpose, reserved flags, key
identifier, 24-byte random nonce) followed by the XChaCha20-Poly1305
ciphertext and tag. The AEAD associated data is the header followed by a
caller-supplied context string that names the object's location. Strict
parsing; unknown values rejected. Full layout in `docs/CRYPTOGRAPHY.md`.

## Consequences
* 192-bit random nonces make accidental reuse negligible without counters or
  state, which suits offline multi-device writes.
* A suite byte allows introducing AES-256-GCM, chunked streaming or
  post-quantum constructions later without ambiguity.
* Purpose and key identifiers allow early, precise errors and safe rotation.
* Overhead: 62 bytes per object.

## Alternatives considered
* AES-256-GCM with 96-bit random nonces: rejected as default — random nonces
  are only safe for a limited number of messages per key; hardware AES is not
  guaranteed on all targets (and not in WASM).
* Self-describing formats (COSE, JWE): rejected — larger parsers, more
  options to get wrong; our needs are narrow.
