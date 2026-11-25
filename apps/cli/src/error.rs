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
