//! # lk-crypto
//!
//! Cryptographic foundation of Last Keys. This crate is the *only* place in
//! the code base that touches cryptographic primitives; every other component
//! uses the safe, typed API exposed here.
//!
//! | Need                         | Construction                                   |
//! |------------------------------|------------------------------------------------|
//! | Password stretching          | Argon2id v1.3 (RFC 9106), bounded parameters   |
//! | Sub-key derivation           | HKDF-SHA256 (RFC 5869), versioned labels       |
//! | Symmetric encryption         | XChaCha20-Poly1305 in a versioned [`envelope`] |
//! | Public-key encryption        | HPKE (RFC 9180) X25519 / HKDF-SHA256 / ChaCha20-Poly1305 |
//! | Signatures                   | Ed25519 (RFC 8032), strict verification        |
//! | Randomness                   | Operating-system CSPRNG only                   |
//!
//! Design rules (see `docs/ARCHITECTURE.md` and `docs/adr/`):
//!
//! * No custom primitives; only audited or standard-conformant implementations.
//! * Secrets are zeroized on drop and redacted from `Debug` output.
//! * Every ciphertext is versioned, names its purpose and key, and is bound to
//!   a caller-supplied context.
//! * No `unsafe` code.

#![forbid(unsafe_code)]

mod derive;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod recovery;
pub mod rng;
pub mod seal;
pub mod secret;
pub mod sign;

pub use envelope::{Envelope, Purpose, Suite};
pub use error::{CryptoError, Result};
pub use kdf::{KdfAlgorithm, KdfParams, KdfSalt, MasterKey, MasterPassword, derive_master_key};
pub use recovery::RecoveryKey;
pub use seal::{EncryptionKeyPair, PublicEncryptionKey, SealedMessage, seal_key_to, seal_to};
pub use secret::{AuthKey, KeyId, SymmetricKey};
pub use sign::{Signature, SigningKeyPair, VerifyingKey};
/// Re-exported so that callers can name the type of returned plaintexts.
pub use zeroize::Zeroizing;
