//! CLI errors and their user-facing messages (never containing secrets).

use core::fmt;

use lk_core::CoreError;

/// A CLI failure.
pub(crate) enum CliError {
    /// Message shown as-is.
    Message(String),
    /// Wrong master password or recovery key.
    Credentials,
    /// Any lower-level error, shown with its (secret-free) description.
    Other(Box<dyn std::error::Error>),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(m) => f.write_str(m),
            Self::Credentials => f.write_str("wrong master password or recovery key"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

pub(crate) fn fail(message: impl Into<String>) -> CliError {
    CliError::Message(message.into())
}

impl From<lk_sync::SyncError> for CliError {
    fn from(e: lk_sync::SyncError) -> Self {
        match e {
            lk_sync::SyncError::InvalidCredentials => Self::Credentials,
            rollback @ lk_sync::SyncError::ServerRollback(_) => Self::Message(format!(
                "{rollback}.\nIf the server administrator restored a backup, run `lk sync --reset`: \
                 every item of this device is uploaded again and versions that differ from the \
                 server's are kept as conflict copies (nothing is deleted).\nOtherwise do not \
                 reset: the server may be misbehaving; contact its administrator."
            )),
            other => Self::Other(Box::new(other)),
        }
    }
}

impl From<CoreError> for CliError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::InvalidCredentials => Self::Credentials,
            other => Self::Other(Box::new(other)),
        }
    }
}

macro_rules! boxed_from {
    ($($ty:ty),* $(,)?) => {
        $(impl From<$ty> for CliError {
            fn from(e: $ty) -> Self {
                Self::Other(Box::new(e))
            }
        })*
    };
}

boxed_from!(
    std::io::Error,
    lk_crypto::CryptoError,
    lk_store::StoreError,
    lk_vault::VaultError,
    lk_generator::GeneratorError,
    lk_totp::TotpError,
);

pub(crate) type Result<T> = core::result::Result<T, CliError>;
