//! Account-level client flows built on the API: registering an existing
//! local account on a server, and enrolling a new device with the master
//! password.

use lk_core::{
    AccountKeyBundle, AccountKeys, DeviceCertificate, DeviceIdentity, PasswordKeys, Platform,
};
use lk_crypto::{MasterPassword, RecoveryKey};
use lk_protocol::{CredentialKind, SessionKind};

use crate::api::{Api, Session};
use crate::error::{Result, SyncError};
use crate::transport::Transport;

/// Registers a locally created account on a server, with password keys
/// already derived from the bundle's KDF configuration. The recovery key is
/// required because the server stores a second OPAQUE credential derived
/// from it; asking for it also proves the user kept it.
///
/// # Errors
/// [`SyncError::InvalidCredentials`] if the password or recovery key does
/// not unlock `bundle`; transport or server errors (e.g. e-mail taken).
pub fn register_account<T: Transport>(
    api: &Api<T>,
    email: &str,
    password_keys: &PasswordKeys,
    recovery_key: &RecoveryKey,
    bundle: &AccountKeyBundle,
    certificate: &DeviceCertificate,
) -> Result<()> {
    let keys = bundle
        .unlock_with_password_keys(password_keys)
        .map_err(|_| SyncError::InvalidCredentials)?;
    let by_recovery = bundle
        .unlock_with_recovery_key(recovery_key)
        .map_err(|_| SyncError::InvalidCredentials)?;
    if by_recovery.account_id() != keys.account_id() {
        return Err(SyncError::InvalidCredentials);
    }
    api.register(
        email,
        password_keys.auth_key(),
        &recovery_key
            .server_auth_key()
            .map_err(lk_core::CoreError::from)?,
        bundle,
        certificate,
    )?;
    Ok(())
}

/// Logs in from a device already registered on the account.
///
/// # Errors
/// [`SyncError::InvalidCredentials`], [`SyncError::DeviceRevoked`], or an
/// integrity error if the session is not a full session.
pub fn login_registered<T: Transport>(
    api: &Api<T>,
    email: &str,
    password_keys: &PasswordKeys,
    device: &DeviceIdentity,
) -> Result<Session> {
    let session = api.login(
        email,
        password_keys.auth_key(),
        CredentialKind::Password,
        device.device_id(),
    )?;
    if session.kind != SessionKind::Full {
        return Err(SyncError::Integrity(
            "this device is not registered on the account",
        ));
    }
    Ok(session)
}

/// Result of [`enroll_device`].
#[derive(Debug)]
pub struct Enrollment {
    /// Full session of the new device.
    pub session: Session,
    /// Account bundle downloaded from the server.
    pub bundle: AccountKeyBundle,
    /// Unlocked account keys.
    pub keys: AccountKeys,
    /// Certificate of the new device.
    pub certificate: DeviceCertificate,
}

/// Enrolls a new device with the master password: pre-login, OPAQUE login
/// (enrollment session), bundle download, unlock (which proves the bundle
/// matches the password), self-certification with the account key, device
/// registration.
///
/// # Errors
/// [`SyncError::InvalidCredentials`], transport or server errors.
pub fn enroll_device<T: Transport>(
    api: &Api<T>,
    email: &str,
    password: &MasterPassword,
    device: &DeviceIdentity,
    device_name: &str,
    platform: Platform,
    now: u64,
) -> Result<Enrollment> {
    let kdf = api.prelogin(email)?;
    let password_keys = PasswordKeys::derive(password, &kdf)?;
    let mut session = api.login(
        email,
        password_keys.auth_key(),
        CredentialKind::Password,
        device.device_id(),
    )?;
    let bundle = api.bundle(&session)?;
    if bundle.kdf != kdf {
        return Err(SyncError::Integrity(
            "pre-login configuration differs from the bundle",
        ));
    }
    let keys = bundle
        .unlock_with_password_keys(&password_keys)
        .map_err(|_| SyncError::Integrity("bundle does not match the password"))?;
    let certificate = keys.certify_device(device.public_info(device_name, platform, now)?, now)?;
    match session.kind {
        SessionKind::Enrollment | SessionKind::Full => {
            api.register_device(&session, &certificate)?
        }
        SessionKind::Recovery => return Err(SyncError::Integrity("unexpected recovery session")),
    }
    // The server upgrades the enrollment session once the device is registered.
    session.kind = SessionKind::Full;
    Ok(Enrollment {
        session,
        bundle,
        keys,
        certificate,
    })
}
