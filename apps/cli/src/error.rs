//! CLI errors and their user-facing messages (never containing secrets).

use core::fmt;

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

impl From<lk_client::ClientError> for CliError {
    fn from(e: lk_client::ClientError) -> Self {
        use lk_client::ClientError;
        match e {
            ClientError::InvalidCredentials => Self::Credentials,
            ClientError::NoVault(path) => Self::Message(format!(
                "no vault at {} (create one with `lk init`)",
                path.display()
            )),
            ClientError::NotRegistered => Self::Message(
                "this vault is not registered on a server (use `lk register` or `lk login`)"
                    .to_owned(),
            ),
            ClientError::NoVaultOnServer => Self::Message(
                "the account has no vault on the server yet; run `lk sync` on a registered device first"
                    .to_owned(),
            ),
            ClientError::Sync(rollback @ lk_sync::SyncError::ServerRollback(_)) => {
                Self::Message(format!(
                    "{rollback}.\nIf the server administrator restored a backup, run `lk sync --reset`: \
                     every item of this device is uploaded again and versions that differ from the \
                     server's are kept as conflict copies (nothing is deleted).\nOtherwise do not \
                     reset: the server may be misbehaving; contact its administrator."
                ))
            }
            ClientError::Sync(lk_sync::SyncError::InvalidCredentials) => Self::Credentials,
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
    lk_vault::VaultError,
    lk_generator::GeneratorError,
);

pub(crate) type Result<T> = core::result::Result<T, CliError>;
