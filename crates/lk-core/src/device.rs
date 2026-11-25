//! Device identities, certificates, revocations and account-key transfer.
//!
//! Every installation of Last Keys has its own [`DeviceIdentity`]: an
//! independent Ed25519 signing key and X25519 encryption key. Private keys
//! are never copied between devices.
//!
//! * The account signing key **certifies** each device ([`DeviceCertificate`])
//!   and **revokes** it ([`DeviceRevocation`]). Clients compute the trusted
//!   device list themselves with [`trusted_devices`]; a server cannot add a
//!   device it made up, because it cannot forge the account signature.
//! * A trusted, unlocked device enrolls a new device (or helps a user who
//!   lost their password) by sealing the account key to the new device's
//!   encryption key with HPKE and signing the transfer with its own device
//!   key ([`AccountKeyTransfer`]). This is a cryptographic authorization, not
//!   a notification approval.
//!
//! Limitations (see `docs/THREAT_MODEL.md`): revocation stops future
//! synchronization and authorization; it cannot erase data a device already
//! decrypted. The out-of-band pairing check that binds a new device's keys to
//! the user's intent is specified for Phase 5 and is not implemented here.

use std::collections::{HashMap, HashSet};

use lk_crypto::{
    CryptoError, EncryptionKeyPair, Envelope, PublicEncryptionKey, Signature, SigningKeyPair,
    SymmetricKey, VerifyingKey, seal_key_to,
};
use serde::{Deserialize, Serialize};

use crate::account::AccountKeys;
use crate::bytes::Bytes;
use crate::context::{self, Canonical};
use crate::error::{CoreError, Result};
use crate::ids::{AccountId, DeviceId};

/// Current format version of device structures.
pub const DEVICE_FORMAT_VERSION: u8 = 1;
/// Maximum length of a device name, in bytes of UTF-8.
pub const MAX_DEVICE_NAME_BYTES: usize = 128;

/// Client platform of a device. Values are part of the signed format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
#[repr(u8)]
pub enum Platform {
    /// Windows desktop application.
    Windows = 1,
    /// macOS desktop application.
    MacOs = 2,
    /// Linux desktop application.
    Linux = 3,
    /// Android application.
    Android = 4,
    /// iOS application.
    Ios = 5,
    /// Web application session.
    Web = 6,
    /// Browser extension.
    BrowserExtension = 7,
    /// Command-line client.
    Cli = 8,
}

/// Public description of a device, as registered with the account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublicInfo {
    /// Device identifier.
    pub device_id: DeviceId,
    /// User-visible device name.
    pub name: String,
    /// Client platform.
    pub platform: Platform,
    /// Creation time (Unix seconds, supplied by the caller's clock).
    pub created_at_unix: u64,
    /// Device Ed25519 public key.
    pub signing_public_key: Bytes,
    /// Device X25519 public key.
    pub encryption_public_key: Bytes,
}

impl DevicePublicInfo {
    /// Device signing public key.
    ///
    /// # Errors
    /// Fails if the stored key is malformed.
    pub fn signing_key(&self) -> Result<VerifyingKey> {
        let bytes = self
            .signing_public_key
            .to_array()
            .ok_or(CoreError::Crypto(CryptoError::InvalidPublicKey))?;
        Ok(VerifyingKey::from_bytes(&bytes)?)
    }

    /// Device encryption public key.
    ///
    /// # Errors
    /// Fails if the stored key is malformed.
    pub fn encryption_key(&self) -> Result<PublicEncryptionKey> {
        let bytes = self
            .encryption_public_key
            .to_array()
            .ok_or(CoreError::Crypto(CryptoError::InvalidPublicKey))?;
        Ok(PublicEncryptionKey::from_bytes(&bytes)?)
    }

    fn validate(&self) -> Result<()> {
        if self.name.len() > MAX_DEVICE_NAME_BYTES {
            return Err(CoreError::FieldTooLong("device name"));
        }
        self.signing_key()?;
        self.encryption_key()?;
        Ok(())
    }

    fn write_canonical(&self, c: &mut Canonical) {
        c.fixed(self.device_id.as_bytes())
            .var(self.name.as_bytes())
            .u8(self.platform as u8)
            .u64(self.created_at_unix)
            .var(self.signing_public_key.as_slice())
            .var(self.encryption_public_key.as_slice());
    }
}

/// The private identity of the local device. Memory only; persist it with
/// [`DeviceIdentity::seal`].
#[derive(Debug)]
pub struct DeviceIdentity {
    device_id: DeviceId,
    signing: SigningKeyPair,
    encryption: EncryptionKeyPair,
}

/// A device identity encrypted for local storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDeviceIdentity {
    /// Format version ([`DEVICE_FORMAT_VERSION`]).
    pub format_version: u8,
    /// Device identifier.
    pub device_id: DeviceId,
    /// Ed25519 private key (envelope).
    pub signing_private_key: Bytes,
    /// X25519 private key (envelope).
    pub encryption_private_key: Bytes,
}

impl DeviceIdentity {
    /// Generates a new, independent device identity.
    ///
    /// # Errors
    /// Fails only if the OS RNG fails.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            device_id: DeviceId::generate()?,
            signing: SigningKeyPair::generate()?,
            encryption: EncryptionKeyPair::generate()?,
        })
    }

    /// Device identifier.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Builds the public description to register with the account.
    ///
    /// # Errors
    /// [`CoreError::FieldTooLong`] if `name` exceeds
    /// [`MAX_DEVICE_NAME_BYTES`].
    pub fn public_info(
        &self,
        name: &str,
        platform: Platform,
        created_at_unix: u64,
    ) -> Result<DevicePublicInfo> {
        let info = DevicePublicInfo {
            device_id: self.device_id,
            name: name.to_owned(),
            platform,
            created_at_unix,
            signing_public_key: Bytes::from(self.signing.verifying_key().to_bytes()),
            encryption_public_key: Bytes::from(self.encryption.public_key().to_bytes()),
        };
        info.validate()?;
        Ok(info)
    }

    /// Encrypts the identity under `wrapping_key` for local storage. In
    /// production `wrapping_key` is protected by the platform key store
    /// (Phase 5); on platforms without hardware protection this is reported
    /// to the user as software-only protection.
    ///
    /// # Errors
    /// Fails only if the OS RNG fails.
    pub fn seal(&self, wrapping_key: &SymmetricKey) -> Result<SealedDeviceIdentity> {
        Ok(SealedDeviceIdentity {
            format_version: DEVICE_FORMAT_VERSION,
            device_id: self.device_id,
            signing_private_key: self
                .signing
                .seal(
                    wrapping_key,
                    &context::device_signing_private_key(&self.device_id),
                )?
                .to_bytes()
                .into(),
            encryption_private_key: self
                .encryption
                .seal(
                    wrapping_key,
                    &context::device_encryption_private_key(&self.device_id),
                )?
                .to_bytes()
                .into(),
        })
    }

    /// Decrypts an identity sealed with [`DeviceIdentity::seal`].
    ///
    /// # Errors
    /// Fails for a wrong key, an unsupported version or tampered data.
    pub fn open(sealed: &SealedDeviceIdentity, wrapping_key: &SymmetricKey) -> Result<Self> {
        check_version(sealed.format_version)?;
        let signing = SigningKeyPair::open(
            &Envelope::from_bytes(sealed.signing_private_key.as_slice())?,
            wrapping_key,
            &context::device_signing_private_key(&sealed.device_id),
        )?;
        let encryption = EncryptionKeyPair::open_sealed(
            &Envelope::from_bytes(sealed.encryption_private_key.as_slice())?,
            wrapping_key,
            &context::device_encryption_private_key(&sealed.device_id),
        )?;
        Ok(Self {
            device_id: sealed.device_id,
            signing,
            encryption,
        })
    }

    /// Receives the account key from a trusted device.
    ///
    /// Verifies that the transfer is addressed to this device, that it comes
    /// from `sender` and is signed by `sender`'s device key, then decrypts it.
    /// The caller must then call
    /// [`crate::AccountKeyBundle::unlock_with_account_key`] (which proves the
    /// key belongs to the account) and check, with [`trusted_devices`], that
    /// `sender` is certified and not revoked before trusting the result.
    ///
    /// # Errors
    /// [`CoreError::Mismatch`] if the transfer is not for this device or not
    /// from `sender`; cryptographic errors for invalid signatures or data.
    pub fn receive_account_key(
        &self,
        transfer: &AccountKeyTransfer,
        sender: &DevicePublicInfo,
    ) -> Result<SymmetricKey> {
        check_version(transfer.format_version)?;
        if transfer.to_device != self.device_id {
            return Err(CoreError::Mismatch("recipient device"));
        }
        if transfer.from_device != sender.device_id {
            return Err(CoreError::Mismatch("sender device"));
        }
        sender.signing_key()?.verify(
            context::SIG_ACCOUNT_KEY_TRANSFER,
            &transfer.signed_bytes(),
            &signature_from(&transfer.signature)?,
        )?;
        let sealed = lk_crypto::SealedMessage::from_bytes(transfer.sealed_account_key.as_slice())?;
        Ok(self.encryption.open_key(
            &sealed,
            context::HPKE_ACCOUNT_KEY_TRANSFER,
            &context::account_key_transfer(
                &transfer.account_id,
                &transfer.from_device,
                &transfer.to_device,
            ),
        )?)
    }
}

/// Statement, signed by the account key, that a device belongs to the
/// account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    /// Format version ([`DEVICE_FORMAT_VERSION`]).
    pub format_version: u8,
    /// Account identifier.
    pub account_id: AccountId,
    /// Certified device.
    pub device: DevicePublicInfo,
    /// Issue time (Unix seconds).
    pub issued_at_unix: u64,
    /// Ed25519 signature by the account signing key.
    pub signature: Bytes,
}

impl DeviceCertificate {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut c = Canonical::new(b"device-certificate", self.format_version);
        c.fixed(self.account_id.as_bytes());
        self.device.write_canonical(&mut c);
        c.u64(self.issued_at_unix);
        c.finish()
    }

    /// Verifies the certificate against the account signing key.
    ///
    /// # Errors
    /// [`CoreError::UntrustedDevice`] if the signature or account do not
    /// match.
    pub fn verify(&self, account_id: &AccountId, account_key: &VerifyingKey) -> Result<()> {
        check_version(self.format_version)?;
        if &self.account_id != account_id {
            return Err(CoreError::UntrustedDevice);
        }
        self.device.validate()?;
        account_key
            .verify(
                context::SIG_DEVICE_CERTIFICATE,
                &self.signed_bytes(),
                &signature_from(&self.signature)?,
            )
            .map_err(|_| CoreError::UntrustedDevice)
    }
}

/// Statement, signed by the account key, that a device is revoked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRevocation {
    /// Format version ([`DEVICE_FORMAT_VERSION`]).
    pub format_version: u8,
    /// Account identifier.
    pub account_id: AccountId,
    /// Revoked device.
    pub device_id: DeviceId,
    /// Revocation time (Unix seconds).
    pub revoked_at_unix: u64,
    /// Ed25519 signature by the account signing key.
    pub signature: Bytes,
}

impl DeviceRevocation {
    fn signed_bytes(&self) -> Vec<u8> {
        Canonical::new(b"device-revocation", self.format_version)
            .fixed(self.account_id.as_bytes())
            .fixed(self.device_id.as_bytes())
            .u64(self.revoked_at_unix)
            .finish()
    }

    /// Verifies the revocation against the account signing key.
    ///
    /// # Errors
    /// Fails if the signature or account do not match.
    pub fn verify(&self, account_id: &AccountId, account_key: &VerifyingKey) -> Result<()> {
        check_version(self.format_version)?;
        if &self.account_id != account_id {
            return Err(CoreError::Mismatch("account"));
        }
        account_key.verify(
            context::SIG_DEVICE_REVOCATION,
            &self.signed_bytes(),
            &signature_from(&self.signature)?,
        )?;
        Ok(())
    }
}

/// The account key sealed to a recipient device and signed by the sender.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeyTransfer {
    /// Format version ([`DEVICE_FORMAT_VERSION`]).
    pub format_version: u8,
    /// Account identifier.
    pub account_id: AccountId,
    /// Sending (already trusted) device.
    pub from_device: DeviceId,
    /// Receiving device.
    pub to_device: DeviceId,
    /// HPKE sealed message containing the account key.
    pub sealed_account_key: Bytes,
    /// Ed25519 signature by the sending device.
    pub signature: Bytes,
}

impl AccountKeyTransfer {
    fn signed_bytes(&self) -> Vec<u8> {
        Canonical::new(b"account-key-transfer", self.format_version)
            .fixed(self.account_id.as_bytes())
            .fixed(self.from_device.as_bytes())
            .fixed(self.to_device.as_bytes())
            .var(self.sealed_account_key.as_slice())
            .finish()
    }
}

impl AccountKeys {
    /// Certifies a device as belonging to this account.
    ///
    /// # Errors
    /// Fails if the device description is invalid.
    pub fn certify_device(
        &self,
        device: DevicePublicInfo,
        issued_at_unix: u64,
    ) -> Result<DeviceCertificate> {
        device.validate()?;
        let mut cert = DeviceCertificate {
            format_version: DEVICE_FORMAT_VERSION,
            account_id: self.account_id,
            device,
            issued_at_unix,
            signature: Bytes::default(),
        };
        let sig = self
            .signing
            .sign(context::SIG_DEVICE_CERTIFICATE, &cert.signed_bytes())?;
        cert.signature = Bytes::from(sig.to_bytes());
        Ok(cert)
    }

    /// Encrypts the local device identity under the account key, for storage
    /// on this device. The device's private keys then become usable only
    /// after an unlock. This is software protection; platform key stores
    /// (hardware-backed where available) replace it in milestone M7.
    ///
    /// # Errors
    /// Fails only if the OS RNG fails.
    pub fn seal_device_identity(&self, device: &DeviceIdentity) -> Result<SealedDeviceIdentity> {
        device.seal(&self.account_key)
    }

    /// Decrypts a device identity sealed with
    /// [`AccountKeys::seal_device_identity`].
    ///
    /// # Errors
    /// Fails if it was sealed by another account or tampered with.
    pub fn open_device_identity(&self, sealed: &SealedDeviceIdentity) -> Result<DeviceIdentity> {
        DeviceIdentity::open(sealed, &self.account_key)
    }

    /// Revokes a device.
    ///
    /// # Errors
    /// Not expected to fail.
    pub fn revoke_device(
        &self,
        device_id: DeviceId,
        revoked_at_unix: u64,
    ) -> Result<DeviceRevocation> {
        let mut rev = DeviceRevocation {
            format_version: DEVICE_FORMAT_VERSION,
            account_id: self.account_id,
            device_id,
            revoked_at_unix,
            signature: Bytes::default(),
        };
        let sig = self
            .signing
            .sign(context::SIG_DEVICE_REVOCATION, &rev.signed_bytes())?;
        rev.signature = Bytes::from(sig.to_bytes());
        Ok(rev)
    }

    /// Seals the account key to a certified recipient device, signed by the
    /// local (sending) device.
    ///
    /// The recipient certificate and the account's revocation list are
    /// verified first: the account key is only ever sent to a device this
    /// account has certified and not revoked.
    ///
    /// # Errors
    /// [`CoreError::UntrustedDevice`] if the recipient is not certified by
    /// this account, is revoked, or if any revocation fails verification.
    pub fn transfer_account_key(
        &self,
        sender: &DeviceIdentity,
        recipient: &DeviceCertificate,
        revocations: &[DeviceRevocation],
    ) -> Result<AccountKeyTransfer> {
        let account_key = self.signing.verifying_key();
        recipient.verify(&self.account_id, &account_key)?;
        for rev in revocations {
            rev.verify(&self.account_id, &account_key)
                .map_err(|_| CoreError::UntrustedDevice)?;
            if rev.device_id == recipient.device.device_id {
                return Err(CoreError::UntrustedDevice);
            }
        }
        let from = sender.device_id;
        let to = recipient.device.device_id;
        let sealed = seal_key_to(
            &recipient.device.encryption_key()?,
            context::HPKE_ACCOUNT_KEY_TRANSFER,
            &context::account_key_transfer(&self.account_id, &from, &to),
            &self.account_key,
        )?;
        let mut transfer = AccountKeyTransfer {
            format_version: DEVICE_FORMAT_VERSION,
            account_id: self.account_id,
            from_device: from,
            to_device: to,
            sealed_account_key: sealed.to_bytes().into(),
            signature: Bytes::default(),
        };
        let sig = sender
            .signing
            .sign(context::SIG_ACCOUNT_KEY_TRANSFER, &transfer.signed_bytes())?;
        transfer.signature = Bytes::from(sig.to_bytes());
        Ok(transfer)
    }
}

/// Computes the list of devices trusted by an account.
///
/// Every certificate and revocation must verify under the account signing
/// key: an invalid entry means the list was tampered with and the whole
/// computation fails (fail closed) rather than silently skipping it. Two
/// certificates for the same device with different keys are also rejected.
///
/// # Errors
/// [`CoreError::UntrustedDevice`] or [`CoreError::InconsistentKeyMaterial`]
/// if any entry is invalid.
pub fn trusted_devices<'a>(
    account_id: &AccountId,
    account_key: &VerifyingKey,
    certificates: &'a [DeviceCertificate],
    revocations: &[DeviceRevocation],
) -> Result<Vec<&'a DevicePublicInfo>> {
    let mut revoked = HashSet::new();
    for rev in revocations {
        rev.verify(account_id, account_key)
            .map_err(|_| CoreError::UntrustedDevice)?;
        revoked.insert(rev.device_id);
    }
    let mut seen: HashMap<DeviceId, &DevicePublicInfo> = HashMap::new();
    let mut trusted = Vec::new();
    for cert in certificates {
        cert.verify(account_id, account_key)?;
        if let Some(previous) = seen.insert(cert.device.device_id, &cert.device) {
            if previous.signing_public_key != cert.device.signing_public_key
                || previous.encryption_public_key != cert.device.encryption_public_key
            {
                return Err(CoreError::InconsistentKeyMaterial);
            }
            continue;
        }
        if !revoked.contains(&cert.device.device_id) {
            trusted.push(&cert.device);
        }
    }
    Ok(trusted)
}

fn check_version(v: u8) -> Result<()> {
    if v == DEVICE_FORMAT_VERSION {
        Ok(())
    } else {
        Err(CoreError::UnsupportedFormat(v))
    }
}

fn signature_from(bytes: &Bytes) -> Result<Signature> {
    bytes
        .to_array()
        .map(Signature::from_bytes)
        .ok_or(CoreError::Crypto(CryptoError::InvalidSignature))
}
