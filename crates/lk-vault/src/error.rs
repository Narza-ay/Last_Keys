//! Vault errors. Messages name fields, never their values.

use lk_core::CoreError;
use lk_totp::TotpError;
use thiserror::Error;

/// Errors returned by `lk-vault`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum VaultError {
    /// A field fails validation.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Field name.
        field: &'static str,
        /// Reason, without the value.
        reason: &'static str,
    },
    /// The item was written by a newer version of Last Keys.
    #[error("item schema version {0} is not supported by this version; please update")]
    UnsupportedSchema(u16),
    /// The decrypted payload is not a valid item.
    #[error("corrupted item payload")]
    Corrupted,
    /// The serialized item exceeds the maximum size.
    #[error("item is too large")]
    TooLarge,
    /// The operation does not apply to this item type.
    #[error("operation not applicable to this item type")]
    WrongItemType,
    /// History index out of range.
    #[error("no such history entry")]
    NoSuchHistoryEntry,
    /// Invalid TOTP configuration.
    #[error(transparent)]
    Totp(#[from] TotpError),
    /// Key or encryption error.
    #[error(transparent)]
    Core(#[from] CoreError),
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, VaultError>;

pub(crate) const fn invalid(field: &'static str, reason: &'static str) -> VaultError {
    VaultError::Invalid { field, reason }
}
