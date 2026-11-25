# Cryptographic specification (format version 1)

Normative description of every cryptographic construction and byte format in
Last Keys. The reference implementation is `crates/lk-crypto` and
`crates/lk-core`; where this document and the code disagree, it is a bug in
one of them. Intended for independent review.

## 1. Primitives

| Use | Primitive | Implementation |
|-----|-----------|----------------|
| Password stretching | Argon2id v1.3 (RFC 9106) | `argon2` 0.6 (RustCrypto) |
| Key derivation | HKDF-SHA256 (RFC 5869) | `hkdf` 0.13, `sha2` 0.11 |
| Symmetric AEAD | XChaCha20-Poly1305 | `chacha20poly1305` 0.11 |
| Public-key encryption | HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 (RFC 9180) | `hpke` 0.15 |
| Signatures | Ed25519 (RFC 8032), `verify_strict` | `ed25519-dalek` 3.0 |
| Randomness | OS CSPRNG | `getrandom` 0.4 |

No other primitive is used. Keys are 256-bit. All random values come from the
OS CSPRNG; there is no user-space PRNG.

## 2. Master password and KDF

* The password is normalized to Unicode **NFC** (RFC 8265 OpaqueString uses
  NFC), whitespace preserved. Empty passwords and passwords longer than 4096
  bytes after normalization are rejected.
* `master_key = Argon2id(password, salt, m, t, p, len = 32)` with a random
  16-byte per-account salt.
* Accepted parameter bounds (enforced by every client before deriving, to
  defeat downgrade by a hostile server): `64 MiB ≤ m ≤ 2 GiB`,
  `2 ≤ t ≤ 20`, `1 ≤ p ≤ 16`.
* Provisional default: `m = 64 MiB, t = 3, p = 4` (RFC 9106 §4 second
  recommended option), to be confirmed by the device benchmark campaign
  ([TESTING.md](TESTING.md)).

## 3. Derived keys (HKDF labels)

`HKDF-SHA256(salt = none, ikm, info = label)`; a key's public identifier is
`HKDF-SHA256(ikm, label || "#key-id")[0..16]`.

| Input | Label | Output |
|-------|-------|--------|
| master key | `lastkeys/v1/master/password-wrap-key` | wraps the account key |
| master key | `lastkeys/v1/master/server-auth-key` | server authentication secret |
| recovery key | `lastkeys/v1/recovery/wrap-key` | wraps the account key |
| recovery key | `lastkeys/v1/recovery/server-auth-key` | recovery authentication secret |

Labels are unique, versioned and never reused.

## 4. Envelope (symmetric ciphertext)

```text
offset  size  field
0       2     magic "LK" (0x4C 0x4B)
2       1     format version = 1
3       1     suite = 1 (XChaCha20-Poly1305)
4       1     purpose (table below)
5       1     flags = 0 (reserved)
6       16    key identifier of the encryption key
22      24    nonce (OS CSPRNG, fresh per encryption)
46      n+16  ciphertext || Poly1305 tag
```

* AEAD associated data = the 46-byte header || context (unambiguous because
  the header has a fixed length).
* Maximum plaintext: 16 MiB (attachments will use a chunked format, new suite).
* Parsing is strict: unknown version/suite/purpose or non-zero flags are
  rejected; accepted inputs are canonical (verified by fuzzing).
* A wrapped key's plaintext is `key_id (16) || key (32)`.

| Purpose | Value | Meaning |
|---------|-------|---------|
| AccountKeyByPassword | 1 | account key wrapped by the password wrapping key |
| AccountKeyByRecovery | 2 | account key wrapped by the recovery wrapping key |
| AccountKeyByLocalDevice | 3 | account key wrapped by a device-local key (Phase 5) |
| VaultKey | 4 | vault key wrapped by an account key |
| ItemKey | 5 | item key wrapped by a vault key |
| ItemContent | 6 | item content encrypted by its item key |
| PrivateKey | 7 | asymmetric private key; plaintext `type (1=Ed25519 seed, 2=X25519) || 32 bytes` |
| Export | 8 | encrypted export payload |
| — | 9–255 | reserved |

## 5. Contexts

Contexts bind ciphertexts to their location. Identifiers are lower-case
hyphenated UUIDs.

| Object | Context |
|--------|---------|
| Account key (password) | `lastkeys/v1/account/{account}/account-key/by-password` |
| Account key (recovery) | `lastkeys/v1/account/{account}/account-key/by-recovery` |
| Account signing private key | `lastkeys/v1/account/{account}/signing-private-key` |
| Account encryption private key | `lastkeys/v1/account/{account}/encryption-private-key` |
| Vault key | `lastkeys/v1/account/{account}/vault/{vault}/vault-key` |
| Item key | `lastkeys/v1/vault/{vault}/item/{item}/item-key` |
| Item content | `lastkeys/v1/vault/{vault}/item/{item}/content` |
| Device signing private key | `lastkeys/v1/device/{device}/signing-private-key` |
| Device encryption private key | `lastkeys/v1/device/{device}/encryption-private-key` |
| Account-key transfer (HPKE) | `lastkeys/v1/account/{account}/account-key-transfer/{from}/{to}` |

## 6. HPKE sealed message

```text
offset  size  field
0       1     format version = 1
1       1     suite = 1 (X25519 / HKDF-SHA256 / ChaCha20-Poly1305); 2 reserved for X-Wing (hybrid post-quantum)
2       32    encapsulated key
34      n+16  ciphertext || tag
```

`info = "lastkeys/v1/hpke/" || label`, `aad = version || suite || context`.
Maximum plaintext 64 KiB. Labels: `account-key-transfer`.

## 7. Signatures

`Ed25519.sign("LastKeys signature v1" || 0x00 || len(label) || label || message)`,
verified with `verify_strict`. Signed messages use the canonical encoding
below, never JSON.

Canonical encoding: `u32be(len(statement)) || statement || version (1 byte)`,
then fields in order; fixed-size fields raw, `u8` raw, `u64` big-endian,
variable fields `u32be(len) || bytes`.

| Statement (label) | Fields after the header |
|-------------------|-------------------------|
| `device-certificate` | account id (16), device id (16), var(name), platform (u8), created_at (u64), var(signing pk), var(encryption pk), issued_at (u64) |
| `device-revocation` | account id (16), device id (16), revoked_at (u64) |
| `account-key-transfer` | account id (16), from device (16), to device (16), var(sealed message) |

## 8. Recovery key

256 bits from the OS CSPRNG, displayed as `LK1-` + 14 groups of 4 Crockford
Base32 symbols encoding `key (32) || SHA-256("lastkeys/v1/recovery/checksum" || key)[0..3]`.
Parsing is case-insensitive, ignores spaces and hyphens, maps `I`/`L`→`1`,
`O`→`0`, and accepts the prefix as optional. Test vectors: the all-zero key
displays as `LK1-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0005-B7J7`.

## 9. Security properties claimed (and tested)

* Confidentiality and integrity of every object under its key (AEAD).
* Context binding: objects cannot be swapped, moved or relabeled.
* Purpose binding: an object sealed for one purpose is never accepted as another.
* Downgrade resistance for KDF parameters.
* Public-key substitution in the account bundle is detected at unlock.
* Device list integrity: only account-signed certificates and revocations count.
* Account-key transfers are bound to sender, recipient and account, and are
  refused toward uncertified or revoked devices.

## 10. Not yet specified

Server authentication (OPAQUE, [ADR-0005](adr/0005-server-authentication-opaque.md)),
device-local unlock, sync log authentication, sharing, temporary links,
attachment streaming, export file format, pairing verification codes. Each
gets a section here before implementation.
