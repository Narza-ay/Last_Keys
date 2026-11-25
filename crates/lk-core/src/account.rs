//! Account key hierarchy.
//!
//! ```text
//! master password ──Argon2id──► master key ──HKDF──┬─► password wrapping key ─┐
//!                                                  └─► server auth key        │ wraps
//! recovery key ─────────────────────HKDF───────────┬─► recovery wrapping key ─┤
//!                                                  └─► recovery auth key      ▼
//!                                                                    account key (random)
//!                                                                      │ wraps
//!                        ┌─────────────────────────┬───────────────────┤
//!                        ▼                         ▼                   ▼
//!             account signing key       account encryption key    vault keys ──► item keys
//!                (Ed25519)                   (X25519/HPKE)
//! ```
//!
//! The account key never changes when the password or the recovery key
//! changes: only its wrappings do, so no vault data has to be re-encrypted
//! and the server never needs to decrypt anything.

use lk_crypto::{
    AuthKey, CryptoError, EncryptionKeyPair, Envelope, KdfAlgorithm, KdfParams, KdfSalt,
    MasterPassword, PublicEncryptionKey, Purpose, RecoveryKey, SigningKeyPair, SymmetricKey,
    VerifyingKey, derive_master_key,
};
use serde::{Deserialize, Serialize};

use crate::bytes::Bytes;
use crate::context;
use crate::error::{CoreError, Result};
use crate::ids::AccountId;

/// Current format version of [`AccountKeyBundle`].
pub const ACCOUNT_BUNDLE_VERSION: u8 = 1;

/// Serialized KDF configuration of an account (public, non-secret).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfConfig {
    /// KDF algorithm identifier (see [`KdfAlgorithm`]).
    pub algorithm: u8,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Parallelism.
    pub parallelism: u32,
    /// Per-account random salt (16 bytes).
    pub salt: Bytes,
}

impl KdfConfig {
    fn new(params: KdfParams, salt: KdfSalt) -> Self {
        Self {
            algorithm: params.algorithm.id(),
            memory_kib: params.memory_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
            salt: Bytes::from(*salt.as_bytes()),
        }
    }

    /// Parses and validates the parameters (enforcing the security floor).
    ///
    /// # Errors
    /// Fails for unknown algorithms or out-of-bounds parameters.
    pub fn params(&self) -> Result<KdfParams> {
        let params = KdfParams {
            algorithm: KdfAlgorithm::from_id(self.algorithm)?,
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        };
        params.validate()?;
        Ok(params)
    }

    /// Parses the salt.
    ///
    /// # Errors
    /// Fails if the salt does not have the expected length.
    pub fn salt(&self) -> Result<KdfSalt> {
        self.salt
            .to_array()
            .map(KdfSalt::from_bytes)
            .ok_or(CoreError::Crypto(CryptoError::InvalidSalt))
    }
}

/// Keys derived from the master password.
///
/// On a new device the client first fetches the public [`KdfConfig`],
/// derives these keys, authenticates to the server with
/// [`PasswordKeys::auth_key`], then downloads the [`AccountKeyBundle`] and
/// unlocks it with [`AccountKeyBundle::unlock_with_password_keys`]: the
/// Argon2id computation runs only once.
#[derive(Debug)]
pub struct PasswordKeys {
    wrapping: SymmetricKey,
    auth: AuthKey,
}

impl PasswordKeys {
    /// Runs Argon2id (slow, by design) and derives the sub-keys.
    ///
    /// # Errors
    /// Fails if the KDF configuration is invalid or below the security floor.
    pub fn derive(password: &MasterPassword, kdf: &KdfConfig) -> Result<Self> {
        let master = derive_master_key(password, &kdf.salt()?, &kdf.params()?)?;
        Ok(Self {
            wrapping: master.password_wrapping_key()?,
            auth: master.server_auth_key()?,
        })
    }

    /// Secret for the server authentication protocol. Distinct from every
    /// encryption key: possessing it does not allow decrypting the vault.
    #[must_use]
    pub const fn auth_key(&self) -> &AuthKey {
        &self.auth
    }
}

/// Everything the server (or the local store) keeps about an account's keys.
/// Every secret in it is encrypted; it is safe to store server-side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeyBundle {
    /// Format version ([`ACCOUNT_BUNDLE_VERSION`]).
    pub format_version: u8,
    /// Account identifier.
    pub account_id: AccountId,
    /// Public KDF configuration.
    pub kdf: KdfConfig,
    /// Account key wrapped by the password wrapping key (envelope).
    pub account_key_by_password: Bytes,
    /// Account key wrapped by the recovery wrapping key (envelope), if a
    /// recovery key is configured.
    pub account_key_by_recovery: Option<Bytes>,
    /// Account Ed25519 public key.
    pub signing_public_key: Bytes,
    /// Account X25519 public key.
    pub encryption_public_key: Bytes,
    /// Account Ed25519 private key wrapped by the account key (envelope).
    pub signing_private_key: Bytes,
    /// Account X25519 private key wrapped by the account key (envelope).
    pub encryption_private_key: Bytes,
}

impl AccountKeyBundle {
    fn check_version(&self) -> Result<()> {
        if self.format_version == ACCOUNT_BUNDLE_VERSION {
            Ok(())
        } else {
            Err(CoreError::UnsupportedFormat(self.format_version))
        }
    }

    /// Unlocks the account with the master password (runs Argon2id).
    ///
    /// # Errors
    /// [`CoreError::InvalidCredentials`] for a wrong password; other errors
    /// for malformed or inconsistent bundles.
    pub fn unlock_with_password(&self, password: &MasterPassword) -> Result<AccountKeys> {
        self.check_version()?;
        let keys = PasswordKeys::derive(password, &self.kdf)?;
        self.unlock_with_password_keys(&keys)
    }

    /// Unlocks the account with already-derived password keys.
    ///
    /// # Errors
    /// See [`AccountKeyBundle::unlock_with_password`].
    pub fn unlock_with_password_keys(&self, keys: &PasswordKeys) -> Result<AccountKeys> {
        self.check_version()?;
        let envelope = Envelope::from_bytes(self.account_key_by_password.as_slice())?;
        let account_key = envelope
            .open_key(
                &keys.wrapping,
                Purpose::AccountKeyByPassword,
                &context::account_key_by_password(&self.account_id),
            )
            .map_err(credentials_error)?;
        self.unlock_with_account_key(account_key)
    }

    /// Unlocks the account with the personal recovery key.
    ///
    /// # Errors
    /// [`CoreError::NoRecoveryKey`] if none is configured,
    /// [`CoreError::InvalidCredentials`] for a wrong recovery key.
    pub fn unlock_with_recovery_key(&self, recovery_key: &RecoveryKey) -> Result<AccountKeys> {
        self.check_version()?;
        let wrapped = self
            .account_key_by_recovery
            .as_ref()
            .ok_or(CoreError::NoRecoveryKey)?;
        let envelope = Envelope::from_bytes(wrapped.as_slice())?;
        let account_key = envelope
            .open_key(
                &recovery_key.wrapping_key()?,
                Purpose::AccountKeyByRecovery,
                &context::account_key_by_recovery(&self.account_id),
            )
            .map_err(credentials_error)?;
        self.unlock_with_account_key(account_key)
    }

    /// Completes an unlock once the account key is known (from a password,
    /// a recovery key or a transfer from a trusted device).
    ///
    /// The private keys are decrypted and checked against the public keys
    /// stored in the bundle, so a server cannot substitute its own public
    /// keys without detection.
    ///
    /// # Errors
    /// [`CoreError::InconsistentKeyMaterial`] if the bundle does not belong
    /// to this account key or has been tampered with.
    pub fn unlock_with_account_key(&self, account_key: SymmetricKey) -> Result<AccountKeys> {
        self.check_version()?;
        let signing_env = Envelope::from_bytes(self.signing_private_key.as_slice())?;
        let encryption_env = Envelope::from_bytes(self.encryption_private_key.as_slice())?;
        let signing = SigningKeyPair::open(
            &signing_env,
            &account_key,
            &context::account_signing_private_key(&self.account_id),
        )
        .map_err(|_| CoreError::InconsistentKeyMaterial)?;
        let encryption = EncryptionKeyPair::open_sealed(
            &encryption_env,
            &account_key,
            &context::account_encryption_private_key(&self.account_id),
        )
        .map_err(|_| CoreError::InconsistentKeyMaterial)?;
        if signing.verifying_key() != self.signing_public_key()?
            || encryption.public_key() != self.encryption_public_key()?
        {
            return Err(CoreError::InconsistentKeyMaterial);
        }
        Ok(AccountKeys {
            account_id: self.account_id,
            account_key,
            signing,
            encryption,
        })
    }

    /// Account signing public key (used to verify device certificates).
    ///
    /// # Errors
    /// Fails if the stored key is malformed.
    pub fn signing_public_key(&self) -> Result<VerifyingKey> {
        let bytes = self
            .signing_public_key
            .to_array()
            .ok_or(CoreError::Crypto(CryptoError::InvalidPublicKey))?;
        Ok(VerifyingKey::from_bytes(&bytes)?)
    }

    /// Account encryption public key (used by others to share with us).
    ///
    /// # Errors
    /// Fails if the stored key is malformed.
    pub fn encryption_public_key(&self) -> Result<PublicEncryptionKey> {
        let bytes = self
            .encryption_public_key
            .to_array()
            .ok_or(CoreError::Crypto(CryptoError::InvalidPublicKey))?;
        Ok(PublicEncryptionKey::from_bytes(&bytes)?)
    }
}

/// Maps "wrong key" outcomes of an account-key unwrap to a single,
/// user-facing error. The key identifier of a password-derived key is itself
/// derived from the password, so a wrong password surfaces as `KeyMismatch`.
fn credentials_error(e: CryptoError) -> CoreError {
    match e {
        CryptoError::KeyMismatch | CryptoError::DecryptionFailed => CoreError::InvalidCredentials,
        other => CoreError::Crypto(other),
    }
}

/// The unlocked key material of an account. Lives in memory only.
#[derive(Debug)]
pub struct AccountKeys {
    pub(crate) account_id: AccountId,
    pub(crate) account_key: SymmetricKey,
    pub(crate) signing: SigningKeyPair,
    pub(crate) encryption: EncryptionKeyPair,
}

/// Result of [`create_account`].
#[derive(Debug)]
pub struct NewAccount {
    /// Unlocked keys, ready to use.
    pub keys: AccountKeys,
    /// Encrypted bundle to persist locally and upload to the server.
    pub bundle: AccountKeyBundle,
    /// Recovery key to show to the user exactly once.
    pub recovery_key: RecoveryKey,
    /// Secret to register with the server authentication protocol.
    pub auth_key: AuthKey,
    /// Secret to register with the server recovery protocol.
    pub recovery_auth_key: AuthKey,
}

/// Creates the complete key hierarchy of a new account.
///
/// # Errors
/// Fails if `params` are below the security floor or the OS RNG fails.
pub fn create_account(password: &MasterPassword, params: KdfParams) -> Result<NewAccount> {
    params.validate()?;
    let account_id = AccountId::generate()?;
    let kdf = KdfConfig::new(params, KdfSalt::random()?);
    let password_keys = PasswordKeys::derive(password, &kdf)?;
    let recovery_key = RecoveryKey::generate()?;

    let account_key = SymmetricKey::generate()?;
    let signing = SigningKeyPair::generate()?;
    let encryption = EncryptionKeyPair::generate()?;

    let bundle = AccountKeyBundle {
        format_version: ACCOUNT_BUNDLE_VERSION,
        account_id,
        kdf,
        account_key_by_password: Envelope::seal_key(
            &password_keys.wrapping,
            Purpose::AccountKeyByPassword,
            &context::account_key_by_password(&account_id),
            &account_key,
        )?
        .to_bytes()
        .into(),
        account_key_by_recovery: Some(
            Envelope::seal_key(
                &recovery_key.wrapping_key()?,
                Purpose::AccountKeyByRecovery,
                &context::account_key_by_recovery(&account_id),
                &account_key,
            )?
            .to_bytes()
            .into(),
        ),
        signing_public_key: Bytes::from(signing.verifying_key().to_bytes()),
        encryption_public_key: Bytes::from(encryption.public_key().to_bytes()),
        signing_private_key: signing
            .seal(
                &account_key,
                &context::account_signing_private_key(&account_id),
            )?
            .to_bytes()
            .into(),
        encryption_private_key: encryption
            .seal(
                &account_key,
                &context::account_encryption_private_key(&account_id),
            )?
            .to_bytes()
            .into(),
    };

    let recovery_auth_key = recovery_key.server_auth_key()?;
    Ok(NewAccount {
        keys: AccountKeys {
            account_id,
            account_key,
            signing,
            encryption,
        },
        bundle,
        recovery_key,
        auth_key: password_keys.auth,
        recovery_auth_key,
    })
}

impl AccountKeys {
    /// Account identifier.
    #[must_use]
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Account signing public key.
    #[must_use]
    pub fn signing_public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Account encryption public key.
    #[must_use]
    pub fn encryption_public_key(&self) -> PublicEncryptionKey {
        self.encryption.public_key()
    }

    fn check_bundle(&self, bundle: &AccountKeyBundle) -> Result<()> {
        bundle.check_version()?;
        if bundle.account_id != self.account_id {
            return Err(CoreError::Mismatch("account"));
        }
        Ok(())
    }

    /// Changes the master password: a new salt and new parameters are used
    /// and only the password wrapping of the account key changes. The
    /// recovery key keeps working; no vault data is re-encrypted.
    ///
    /// Returns the new bundle and the new server authentication secret.
    ///
    /// # Errors
    /// Fails if `params` are below the floor or the bundle is foreign.
    pub fn change_password(
        &self,
        bundle: &AccountKeyBundle,
        new_password: &MasterPassword,
        params: KdfParams,
    ) -> Result<(AccountKeyBundle, AuthKey)> {
        self.check_bundle(bundle)?;
        params.validate()?;
        let kdf = KdfConfig::new(params, KdfSalt::random()?);
        let keys = PasswordKeys::derive(new_password, &kdf)?;
        let mut updated = bundle.clone();
        updated.kdf = kdf;
        updated.account_key_by_password = Envelope::seal_key(
            &keys.wrapping,
            Purpose::AccountKeyByPassword,
            &context::account_key_by_password(&self.account_id),
            &self.account_key,
        )?
        .to_bytes()
        .into();
        Ok((updated, keys.auth))
    }

    /// Replaces the recovery key. The previous recovery key stops working as
    /// soon as the returned bundle replaces the old one everywhere.
    ///
    /// Returns the new bundle, the new recovery key (show once) and the new
    /// recovery authentication secret.
    ///
    /// # Errors
    /// Fails if the bundle is foreign or the OS RNG fails.
    pub fn rotate_recovery_key(
        &self,
        bundle: &AccountKeyBundle,
    ) -> Result<(AccountKeyBundle, RecoveryKey, AuthKey)> {
        self.check_bundle(bundle)?;
        let recovery_key = RecoveryKey::generate()?;
        let mut updated = bundle.clone();
        updated.account_key_by_recovery = Some(
            Envelope::seal_key(
                &recovery_key.wrapping_key()?,
                Purpose::AccountKeyByRecovery,
                &context::account_key_by_recovery(&self.account_id),
                &self.account_key,
            )?
            .to_bytes()
            .into(),
        );
        let auth = recovery_key.server_auth_key()?;
        Ok((updated, recovery_key, auth))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        KdfParams::recommended()
    }

    #[test]
    fn create_then_unlock_with_password_and_recovery_key() {
        let pw = MasterPassword::new("correct horse battery staple").unwrap();
        let new = create_account(&pw, params()).unwrap();
        let by_pw = new.bundle.unlock_with_password(&pw).unwrap();
        assert_eq!(by_pw.account_id(), new.keys.account_id());
        assert_eq!(by_pw.account_key.id(), new.keys.account_key.id());
        let by_rk = new
            .bundle
            .unlock_with_recovery_key(&new.recovery_key)
            .unwrap();
        assert_eq!(by_rk.account_key.id(), new.keys.account_key.id());
        assert_eq!(by_rk.signing_public_key(), new.keys.signing_public_key());
    }

    #[test]
    fn wrong_password_and_wrong_recovery_key_are_rejected() {
        let pw = MasterPassword::new("right password").unwrap();
        let new = create_account(&pw, params()).unwrap();
        let wrong = MasterPassword::new("wrong password").unwrap();
        assert_eq!(
            new.bundle.unlock_with_password(&wrong).unwrap_err(),
            CoreError::InvalidCredentials
        );
        let other_rk = RecoveryKey::generate().unwrap();
        assert_eq!(
            new.bundle.unlock_with_recovery_key(&other_rk).unwrap_err(),
            CoreError::InvalidCredentials
        );
    }

    #[test]
    fn auth_keys_are_distinct_from_each_other() {
        let pw = MasterPassword::new("pw-for-auth").unwrap();
        let new = create_account(&pw, params()).unwrap();
        assert_ne!(
            new.auth_key.expose_secret(),
            new.recovery_auth_key.expose_secret()
        );
        // Re-deriving from the stored KDF config yields the same auth key.
        let again = PasswordKeys::derive(&pw, &new.bundle.kdf).unwrap();
        assert_eq!(
            again.auth_key().expose_secret(),
            new.auth_key.expose_secret()
        );
    }

    #[test]
    fn weak_kdf_params_from_a_hostile_server_are_refused() {
        let pw = MasterPassword::new("pw").unwrap();
        let new = create_account(&pw, params()).unwrap();
        let mut hostile = new.bundle.clone();
        hostile.kdf.memory_kib = 1024;
        hostile.kdf.iterations = 1;
        assert_eq!(
            hostile.unlock_with_password(&pw).unwrap_err(),
            CoreError::Crypto(CryptoError::KdfParamsOutOfBounds)
        );
    }

    #[test]
    fn substituted_public_key_is_detected() {
        let pw = MasterPassword::new("pw").unwrap();
        let new = create_account(&pw, params()).unwrap();
        let attacker = EncryptionKeyPair::generate().unwrap();
        let mut tampered = new.bundle.clone();
        tampered.encryption_public_key = Bytes::from(attacker.public_key().to_bytes());
        assert_eq!(
            tampered.unlock_with_password(&pw).unwrap_err(),
            CoreError::InconsistentKeyMaterial
        );
    }

    #[test]
    fn swapped_private_keys_between_accounts_are_detected() {
        let pw = MasterPassword::new("pw").unwrap();
        let a = create_account(&pw, params()).unwrap();
        let b = create_account(&pw, params()).unwrap();
        let mut franken = a.bundle.clone();
        franken.signing_private_key = b.bundle.signing_private_key.clone();
        assert_eq!(
            franken.unlock_with_password(&pw).unwrap_err(),
            CoreError::InconsistentKeyMaterial
        );
    }

    #[test]
    fn unsupported_bundle_version_is_rejected() {
        let pw = MasterPassword::new("pw").unwrap();
        let new = create_account(&pw, params()).unwrap();
        let mut future = new.bundle;
        future.format_version = 2;
        assert_eq!(
            future.unlock_with_password(&pw).unwrap_err(),
            CoreError::UnsupportedFormat(2)
        );
    }

    #[test]
    fn bundle_json_roundtrip() {
        let pw = MasterPassword::new("pw").unwrap();
        let new = create_account(&pw, params()).unwrap();
        let json = serde_json::to_string(&new.bundle).unwrap();
        let back: AccountKeyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, new.bundle);
        back.unlock_with_password(&pw).unwrap();
    }
}
