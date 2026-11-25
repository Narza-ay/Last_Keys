# ADR-0002: Key hierarchy v1

* Status: Accepted (format version 1; independent cryptographic review pending before production)
* Date: 2026-11-25

## Context
Requirements: client-side encryption only; master password never sent and
never recoverable; password change without server decryption; separate server
authentication; two independent recovery methods (recovery key, trusted
device); independent device identities; revocation; per-item keys for
sharing; versioned formats.

## Decision
* **Account key**: random 256-bit root key of the account. It never changes
  on password or recovery-key changes; it is wrapped independently by:
  the password wrapping key (HKDF of the Argon2id master key), the recovery
  wrapping key (HKDF of the 256-bit recovery key), and — for transfers — the
  recipient device's X25519 key via HPKE.
* **Server authentication secrets** are derived with distinct HKDF labels
  from the master key and from the recovery key; they cannot decrypt anything.
* **Account key pairs**: Ed25519 (certifies and revokes devices) and X25519
  (receives shares), private halves wrapped by the account key; public halves
  checked against the private halves at every unlock.
* **Vault keys** (random, per vault) wrapped by the account key of each member;
  **item keys** (random, per item) wrapped by the vault key; content encrypted
  by the item key.
* **Device identities**: one Ed25519 + X25519 pair per installation, never
  copied; trust established by account-signed certificates and revocations
  evaluated by clients.
* **Trusted-device transfer**: HPKE-sealed account key, signed by the sending
  device, bound to (account, sender, recipient); refused toward uncertified or
  revoked devices.
* Every ciphertext uses the envelope of ADR-0004 with a context naming its
  location.

## Consequences
* Password change and recovery-key rotation are O(1) re-wraps.
* Sharing one item re-wraps one item key.
* Revocation needs key rotation and re-encryption to protect *future* data
  from a revoked device (AUDIT K-4, Phase 5).
* Losing the password, the recovery key and every trusted device loses the
  data: there is deliberately no other way in.

## Alternatives considered
* Deriving the vault key directly from the password: rejected — a password
  change would re-encrypt everything and recovery would be impossible without
  the password.
* A "secret key" mixed into the KDF (1Password model): deferred — it improves
  resistance to server-side guessing but adds a second secret the user must
  keep for every new device; can be added later as a new KDF version.
* Custom ECIES instead of HPKE: rejected — HPKE is the standard (RFC 9180).
