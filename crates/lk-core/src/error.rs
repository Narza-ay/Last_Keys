//! Error type of `lk-core`. Variants never carry secret material.

use lk_crypto::CryptoError;
use thiserror::Error;

/// Errors returned by `lk-core`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CoreError {
    /// A cryptographic operation failed (wrong password, tampering, ...).
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// The master password or recovery key is wrong (or the wrapped account
    /// key was tampered with: the two cases are indistinguishable by design).
    #[error("wrong master password or recovery key")]
    InvalidCredentials,

    /// A stored or received structure has an unsupported format version.
    #[error("unsupported format version {0}")]
    UnsupportedFormat(u8),

    /// A stored or received structure is internally inconsistent
    /// (e.g. public keys that do not match the encrypted private keys).
    #[error("inconsistent or tampered key material")]
    InconsistentKeyMaterial,

    /// An object belongs to a different account, vault, item or device than
    /// the one it is being used with.
    #[error("object does not belong to the expected {0}")]
    Mismatch(&'static str),

    /// The device is not certified by the account, or has been revoked.
    #[error("device is not trusted by this account")]
    UntrustedDevice,

    /// A text field exceeds its maximum length.
    #[error("field too long: {0}")]
    FieldTooLong(&'static str),

    /// The account has no recovery key configured.
    #[error("no recovery key is configured for this account")]
    NoRecoveryKey,
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, CoreError>;
