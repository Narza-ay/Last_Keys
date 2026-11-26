//! Errors of the application layer. Messages never contain secrets or vault
//! data; [`ClientError::kind`] gives a stable code for user interfaces,
//! which translate it.

use std::path::PathBuf;

use lk_core::CoreError;
use lk_protocol::ErrorCode;
use lk_sync::SyncError;
use serde::Serialize;
use thiserror::Error;

/// Errors returned by `lk-client`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// No vault file at this path.
    #[error("no vault at {}", .0.display())]
    NoVault(PathBuf),
    /// A vault file already exists at this path.
    #[error("a vault already exists at {}", .0.display())]
    VaultExists(PathBuf),
    /// Wrong master password or recovery key (or unknown account).
    #[error("wrong master password or recovery key")]
    InvalidCredentials,
    /// The new master password is too short.
    #[error("the master password must have at least {min} characters")]
    WeakMasterPassword {
        /// Minimum number of characters.
        min: usize,
    },
    /// The new master password and its confirmation differ.
    #[error("the passwords do not match")]
    PasswordMismatch,
    /// A reference (ID prefix) is too short.
    #[error("{0}")]
    InvalidReference(&'static str),
    /// No item or device matches a reference.
    #[error("no {what} matches {reference}")]
    NoMatch {
        /// "item" or "device".
        what: &'static str,
        /// The reference given.
        reference: String,
    },
    /// Several items or devices match a reference.
    #[error("{count} {what}s match {reference}; give more characters")]
    Ambiguous {
        /// "item" or "device".
        what: &'static str,
        /// The reference given.
        reference: String,
        /// Number of matches.
        count: usize,
    },
    /// The item does not exist (or was deleted).
    #[error("no such item")]
    ItemNotFound,
    /// The vault is not registered on a server.
    #[error("this vault is not registered on a server")]
    NotRegistered,
    /// The vault is already registered on a server.
    #[error("this vault is already registered on a server")]
    AlreadyRegistered,
    /// The operation needs the master password, not the recovery key.
    #[error("this operation needs the master password, not the recovery key")]
    NeedsMasterPassword,
    /// The account has no vault on the server yet.
    #[error("the account has no vault on the server yet; synchronize a registered device first")]
    NoVaultOnServer,
    /// The local store holds no vault key.
    #[error("the store contains no vault")]
    EmptyStore,
    /// The local device has no certificate.
    #[error("this device has no certificate")]
    NoCertificate,
    /// The e-mail address is not valid.
    #[error("invalid e-mail address")]
    InvalidEmail,
    /// The device list returned by the server does not verify.
    #[error("the device list returned by the server failed verification")]
    UntrustedDeviceList,
    /// A device cannot revoke itself.
    #[error("this is the current device; it cannot revoke itself")]
    CannotRevokeSelf,
    /// The item has no TOTP configuration.
    #[error("this item has no TOTP configuration")]
    NoTotp,
    /// The operation does not apply to this item type.
    #[error("this operation does not apply to this item type")]
    WrongItemType,
    /// The requested secret field does not exist on the item.
    #[error("this item has no such field")]
    NoSuchField,
    /// An edit request is inconsistent.
    #[error("invalid edit: {0}")]
    InvalidDraft(&'static str),
    /// Synchronization or server error.
    #[error(transparent)]
    Sync(#[from] SyncError),
    /// Key hierarchy error.
    #[error(transparent)]
    Core(CoreError),
    /// Cryptographic error.
    #[error(transparent)]
    Crypto(#[from] lk_crypto::CryptoError),
    /// Local store error.
    #[error(transparent)]
    Store(#[from] lk_store::StoreError),
    /// Item model error (validation).
    #[error(transparent)]
    Vault(#[from] lk_vault::VaultError),
    /// TOTP error.
    #[error(transparent)]
    Totp(#[from] lk_totp::TotpError),
    /// File-system error.
    #[error("file error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CoreError> for ClientError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::InvalidCredentials => Self::InvalidCredentials,
            other => Self::Core(other),
        }
    }
}

/// Stable, machine-readable error codes for user interfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorKind {
    /// No vault file.
    NoVault,
    /// A vault already exists.
    VaultExists,
    /// Wrong master password or recovery key.
    InvalidCredentials,
    /// Master password too short.
    WeakMasterPassword,
    /// Password and confirmation differ.
    PasswordMismatch,
    /// No such item, device or field.
    NotFound,
    /// Ambiguous reference.
    Ambiguous,
    /// Invalid input (validation, reference, e-mail, edit).
    InvalidInput,
    /// Not registered on a server.
    NotRegistered,
    /// Already registered on a server.
    AlreadyRegistered,
    /// Needs the master password.
    NeedsMasterPassword,
    /// No vault on the server.
    NoVaultOnServer,
    /// Device list failed verification.
    UntrustedDeviceList,
    /// A device cannot revoke itself.
    CannotRevokeSelf,
    /// No TOTP on the item.
    NoTotp,
    /// Wrong item type.
    WrongItemType,
    /// The server's data went back in time (restored backup or attack).
    ServerRollback,
    /// This device is revoked.
    DeviceRevoked,
    /// The server cannot be reached.
    Network,
    /// The server URL is not acceptable.
    InvalidServerUrl,
    /// The e-mail address is already registered.
    EmailTaken,
    /// The server does not accept new accounts.
    RegistrationClosed,
    /// Too many attempts.
    RateLimited,
    /// Other server error.
    Server,
    /// Local data failed an integrity check.
    Corrupted,
    /// Unexpected internal error.
    Internal,
}

impl ErrorKind {
    /// Every code, for user interfaces that must translate them all.
    pub const ALL: &'static [Self] = &[
        Self::NoVault,
        Self::VaultExists,
        Self::InvalidCredentials,
        Self::WeakMasterPassword,
        Self::PasswordMismatch,
        Self::NotFound,
        Self::Ambiguous,
        Self::InvalidInput,
        Self::NotRegistered,
        Self::AlreadyRegistered,
        Self::NeedsMasterPassword,
        Self::NoVaultOnServer,
        Self::UntrustedDeviceList,
        Self::CannotRevokeSelf,
        Self::NoTotp,
        Self::WrongItemType,
        Self::ServerRollback,
        Self::DeviceRevoked,
        Self::Network,
        Self::InvalidServerUrl,
        Self::EmailTaken,
        Self::RegistrationClosed,
        Self::RateLimited,
        Self::Server,
        Self::Corrupted,
        Self::Internal,
    ];

    /// Position in [`Self::ALL`]. The exhaustive `match` makes adding a
    /// variant without listing it a compile error.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::NoVault => 0,
            Self::VaultExists => 1,
            Self::InvalidCredentials => 2,
            Self::WeakMasterPassword => 3,
            Self::PasswordMismatch => 4,
            Self::NotFound => 5,
            Self::Ambiguous => 6,
            Self::InvalidInput => 7,
            Self::NotRegistered => 8,
            Self::AlreadyRegistered => 9,
            Self::NeedsMasterPassword => 10,
            Self::NoVaultOnServer => 11,
            Self::UntrustedDeviceList => 12,
            Self::CannotRevokeSelf => 13,
            Self::NoTotp => 14,
            Self::WrongItemType => 15,
            Self::ServerRollback => 16,
            Self::DeviceRevoked => 17,
            Self::Network => 18,
            Self::InvalidServerUrl => 19,
            Self::EmailTaken => 20,
            Self::RegistrationClosed => 21,
            Self::RateLimited => 22,
            Self::Server => 23,
            Self::Corrupted => 24,
            Self::Internal => 25,
        }
    }
}

impl ClientError {
    /// Stable code of this error.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::NoVault(_) => ErrorKind::NoVault,
            Self::VaultExists(_) => ErrorKind::VaultExists,
            Self::InvalidCredentials => ErrorKind::InvalidCredentials,
            Self::WeakMasterPassword { .. } => ErrorKind::WeakMasterPassword,
            Self::PasswordMismatch => ErrorKind::PasswordMismatch,
            Self::NoMatch { .. } | Self::ItemNotFound | Self::NoSuchField => ErrorKind::NotFound,
            Self::Ambiguous { .. } => ErrorKind::Ambiguous,
            Self::InvalidReference(_)
            | Self::InvalidEmail
            | Self::InvalidDraft(_)
            | Self::Vault(_)
            | Self::Totp(_) => ErrorKind::InvalidInput,
            Self::NotRegistered => ErrorKind::NotRegistered,
            Self::AlreadyRegistered => ErrorKind::AlreadyRegistered,
            Self::NeedsMasterPassword => ErrorKind::NeedsMasterPassword,
            Self::NoVaultOnServer => ErrorKind::NoVaultOnServer,
            Self::UntrustedDeviceList => ErrorKind::UntrustedDeviceList,
            Self::CannotRevokeSelf => ErrorKind::CannotRevokeSelf,
            Self::NoTotp => ErrorKind::NoTotp,
            Self::WrongItemType => ErrorKind::WrongItemType,
            Self::Sync(e) => sync_kind(e),
            Self::EmptyStore | Self::NoCertificate | Self::Store(_) | Self::Core(_) => {
                ErrorKind::Corrupted
            }
            Self::Crypto(_) | Self::Io(_) => ErrorKind::Internal,
        }
    }
}

fn sync_kind(e: &SyncError) -> ErrorKind {
    match e {
        SyncError::InvalidUrl(_) => ErrorKind::InvalidServerUrl,
        SyncError::Transport(_) => ErrorKind::Network,
        SyncError::InvalidCredentials => ErrorKind::InvalidCredentials,
        SyncError::DeviceRevoked => ErrorKind::DeviceRevoked,
        SyncError::ServerRollback(_) => ErrorKind::ServerRollback,
        SyncError::Server { code, .. } => match code {
            Some(ErrorCode::EmailTaken) => ErrorKind::EmailTaken,
            Some(ErrorCode::RegistrationClosed) => ErrorKind::RegistrationClosed,
            Some(ErrorCode::RateLimited) => ErrorKind::RateLimited,
            _ => ErrorKind::Server,
        },
        SyncError::Integrity(_) => ErrorKind::Server,
        SyncError::Core(CoreError::InvalidCredentials) => ErrorKind::InvalidCredentials,
        SyncError::Auth(_) | SyncError::Core(_) | SyncError::Store(_) | SyncError::Vault(_) => {
            ErrorKind::Internal
        }
        _ => ErrorKind::Internal,
    }
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, ClientError>;

#[cfg(test)]
mod tests {
    use super::ErrorKind;

    #[test]
    fn all_lists_every_kind_once_in_order() {
        for (i, kind) in ErrorKind::ALL.iter().enumerate() {
            assert_eq!(kind.index(), i, "{kind:?}");
        }
    }
}
