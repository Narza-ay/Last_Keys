//! Synchronization errors. Messages never contain secrets or vault data.

use lk_protocol::ErrorCode;
use thiserror::Error;

/// Errors returned by `lk-sync`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SyncError {
    /// The server URL is not acceptable (plain HTTP is allowed only for the
    /// local machine).
    #[error("invalid server URL: {0}")]
    InvalidUrl(&'static str),
    /// Network or TLS failure.
    #[error("cannot reach the server: {0}")]
    Transport(String),
    /// The server answered with an error.
    #[error("server error {status}: {message}")]
    Server {
        /// HTTP status.
        status: u16,
        /// Machine-readable code, when provided.
        code: Option<ErrorCode>,
        /// Server message.
        message: String,
    },
    /// Wrong credentials (or unknown account).
    #[error("wrong e-mail, master password or recovery key")]
    InvalidCredentials,
    /// This device has been revoked.
    #[error("this device has been revoked")]
    DeviceRevoked,
    /// The server answered something unexpected (malformed, inconsistent).
    #[error("server response failed an integrity check: {0}")]
    Integrity(&'static str),
    /// The server's data is older than what this device already
    /// synchronized: a backup was restored, or the server misbehaves.
    /// Synchronization stops until the user asks for a full
    /// resynchronization ([`crate::resync_vault`]), which never deletes local
    /// data.
    #[error("the server's data is older than this device's last synchronization ({0})")]
    ServerRollback(&'static str),
    /// OPAQUE failure.
    #[error(transparent)]
    Auth(#[from] lk_auth::AuthError),
    /// Key hierarchy failure.
    #[error(transparent)]
    Core(#[from] lk_core::CoreError),
    /// Local store failure.
    #[error(transparent)]
    Store(#[from] lk_store::StoreError),
    /// Item model failure.
    #[error(transparent)]
    Vault(#[from] lk_vault::VaultError),
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, SyncError>;
