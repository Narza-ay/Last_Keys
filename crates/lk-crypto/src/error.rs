//! Error type for every fallible operation in `lk-crypto`.
//!
//! Error values never carry secret material: variants only describe *what*
//! failed so that they can be logged or shown to a user safely.

use thiserror::Error;

/// Errors returned by `lk-crypto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// The operating system random number generator failed.
    #[error("the operating system random number generator is unavailable")]
    RandomUnavailable,

    /// KDF parameters are outside the bounds accepted by Last Keys.
    #[error("key derivation parameters are outside the accepted bounds")]
    KdfParamsOutOfBounds,

    /// The KDF algorithm identifier is not supported by this version.
    #[error("unsupported key derivation algorithm")]
    UnsupportedKdf,

    /// The KDF salt has an invalid length.
    #[error("invalid key derivation salt length")]
    InvalidSalt,

    /// The KDF implementation reported an internal failure.
    #[error("key derivation failed")]
    KdfFailure,

    /// The master password is empty or exceeds the maximum length.
    #[error("the master password is empty or too long")]
    InvalidPassword,

    /// An envelope or sealed message could not be parsed.
    #[error("malformed encrypted object")]
    Malformed,

    /// The envelope format version is not supported by this build.
    #[error("unsupported encrypted object version")]
    UnsupportedVersion,

    /// The cipher suite identifier is not supported by this build.
    #[error("unsupported cipher suite")]
    UnsupportedSuite,

    /// The object was encrypted for a different purpose than expected.
    #[error("encrypted object purpose does not match the expected purpose")]
    PurposeMismatch,

    /// The object was encrypted under a different key than the one supplied.
    #[error("encrypted object was produced with a different key")]
    KeyMismatch,

    /// Authentication failed: wrong key, wrong context or tampered data.
    #[error("decryption failed: wrong key or tampered data")]
    DecryptionFailed,

    /// The plaintext exceeds the maximum size for a single envelope.
    #[error("plaintext is too large for a single encrypted object")]
    PlaintextTooLarge,

    /// A public key could not be decoded.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// A signature is malformed or does not verify.
    #[error("invalid signature")]
    InvalidSignature,

    /// A recovery key has an invalid format.
    #[error("invalid recovery key format")]
    InvalidRecoveryKeyFormat,

    /// A recovery key checksum does not match (likely a typo).
    #[error("recovery key checksum mismatch")]
    RecoveryKeyChecksum,
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, CryptoError>;
