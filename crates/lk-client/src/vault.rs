//! The vault lifecycle and every operation a client offers on an unlocked
//! vault.

use std::path::{Path, PathBuf};

use lk_core::{
    AccountKeys, DeviceId, DeviceIdentity, ItemId, PasswordKeys, Platform, VaultKey, create_account,
};
use lk_crypto::{KdfParams, MasterPassword, RecoveryKey, Zeroizing};
use lk_protocol::CredentialKind;
use lk_store::{Store, StoredItem};
use lk_sync::{
    Api, UreqTransport, enroll_device, login_registered, register_account, resync_vault, sync_vault,
};
use lk_totp::Totp;
use lk_vault::{ItemContent, ItemData, codec};

use crate::draft::ItemDraft;
use crate::error::{ClientError, Result};
use crate::view::{
    DeviceStatus, DeviceView, Field, ItemSummary, ItemView, KdfView, RemoteView, SyncSummary,
    TotpView, UnlockMethod, VaultInfo,
};

/// Minimum length of a new master password (characters). Existing passwords
/// are never re-checked.
pub const MIN_MASTER_PASSWORD_CHARS: usize = 12;

/// Minimum length of an ID prefix used as a reference.
pub const MIN_REFERENCE_CHARS: usize = 4;

/// Checks a new master password and its confirmation, and converts it.
///
/// # Errors
/// [`ClientError::PasswordMismatch`], [`ClientError::WeakMasterPassword`]
/// or a normalization error.
pub fn new_master_password(password: &str, confirmation: &str) -> Result<MasterPassword> {
    if password != confirmation {
        return Err(ClientError::PasswordMismatch);
    }
    if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(ClientError::WeakMasterPassword {
            min: MIN_MASTER_PASSWORD_CHARS,
        });
    }
    Ok(MasterPassword::new(password)?)
}

/// How to unlock a vault.
pub enum Credential<'a> {
    /// The master password.
    MasterPassword(&'a MasterPassword),
    /// The recovery key (allows resetting a forgotten master password).
    RecoveryKey(&'a RecoveryKey),
}

/// Creates the parent directory of a vault file, private to the user.
fn create_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent)?;
    }
    Ok(())
}

fn refuse_existing(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(ClientError::VaultExists(path.to_path_buf()));
    }
    Ok(())
}

fn normalized_email(email: &str) -> Result<String> {
    lk_auth::normalize_email(email).map_err(|_| ClientError::InvalidEmail)
}

/// An unlocked vault. Keys are zeroized when it is dropped (lock).
pub struct Vault {
    path: PathBuf,
    store: Store,
    keys: AccountKeys,
    vault: VaultKey,
    device: DeviceIdentity,
    /// Present when unlocked with the master password.
    password_keys: Option<PasswordKeys>,
    /// Present when unlocked with the recovery key.
    recovery_key: Option<RecoveryKey>,
}

impl core::fmt::Debug for Vault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("account", &self.keys.account_id())
            .finish_non_exhaustive()
    }
}

/// Result of [`Vault::create`].
pub struct Created {
    /// The new, unlocked vault.
    pub vault: Vault,
    /// The recovery key, to show to the user exactly once.
    pub recovery_key: RecoveryKey,
}

/// Result of [`Vault::enroll`].
pub struct Enrolled {
    /// The new, unlocked vault of this device.
    pub vault: Vault,
    /// Items received by the initial synchronization.
    pub received: usize,
}

impl Vault {
    /// Creates an account and its first vault on this device.
    ///
    /// # Errors
    /// [`ClientError::VaultExists`], file or key errors.
    pub fn create(
        path: &Path,
        password: &MasterPassword,
        device_name: &str,
        platform: Platform,
        now: u64,
    ) -> Result<Created> {
        refuse_existing(path)?;
        create_parent(path)?;
        let account = create_account(password, KdfParams::recommended())?;
        let device = DeviceIdentity::generate()?;
        let info = device.public_info(device_name, platform, now)?;
        let certificate = account.keys.certify_device(info, now)?;
        let sealed = account.keys.seal_device_identity(&device)?;
        let mut store = Store::create(path, &account.bundle, &sealed, Some(&certificate), now)?;
        let (vault, wrapped) = account.keys.create_vault()?;
        store.put_wrapped_vault_key(&wrapped)?;
        let password_keys = PasswordKeys::derive(password, &account.bundle.kdf)?;
        Ok(Created {
            vault: Self {
                path: path.to_path_buf(),
                store,
                keys: account.keys,
                vault,
                device,
                password_keys: Some(password_keys),
                recovery_key: None,
            },
            recovery_key: account.recovery_key,
        })
    }

    /// Sets this device up from an existing account: enrollment with the
    /// master password, local vault creation, initial synchronization.
    ///
    /// # Errors
    /// [`ClientError::VaultExists`], [`ClientError::InvalidCredentials`],
    /// [`ClientError::NoVaultOnServer`], network or server errors. Nothing
    /// is written locally unless enrollment succeeds.
    pub fn enroll(
        path: &Path,
        server: &str,
        email: &str,
        password: &MasterPassword,
        device_name: &str,
        platform: Platform,
        now: u64,
    ) -> Result<Enrolled> {
        refuse_existing(path)?;
        let email = normalized_email(email)?;
        let server = lk_sync::normalize_server_url(server)?;
        let api = Api::new(UreqTransport::new(&server)?);
        let device = DeviceIdentity::generate()?;
        let enrollment =
            enroll_device(&api, &email, password, &device, device_name, platform, now)?;
        let wrapped_keys = api.vault_keys(&enrollment.session)?;
        let first = wrapped_keys.first().ok_or(ClientError::NoVaultOnServer)?;
        create_parent(path)?;
        let sealed = enrollment.keys.seal_device_identity(&device)?;
        let mut store = Store::create(
            path,
            &enrollment.bundle,
            &sealed,
            Some(&enrollment.certificate),
            now,
        )?;
        store.set_remote(&server, &email)?;
        let mut received = 0usize;
        for wrapped in &wrapped_keys {
            store.put_wrapped_vault_key(wrapped)?;
            let vault = enrollment.keys.open_vault_key(wrapped)?;
            let report = sync_vault(&api, &enrollment.session, &mut store, &vault, wrapped, now)?;
            received = received.saturating_add(report.pulled);
        }
        let _ = api.logout(&enrollment.session);
        let vault = enrollment.keys.open_vault_key(first)?;
        let password_keys = PasswordKeys::derive(password, &enrollment.bundle.kdf)?;
        Ok(Enrolled {
            vault: Self {
                path: path.to_path_buf(),
                store,
                keys: enrollment.keys,
                vault,
                device,
                password_keys: Some(password_keys),
                recovery_key: None,
            },
            received,
        })
    }

    /// Unlocks the vault at `path`.
    ///
    /// # Errors
    /// [`ClientError::NoVault`], [`ClientError::InvalidCredentials`], or an
    /// integrity error.
    pub fn unlock(path: &Path, credential: &Credential<'_>) -> Result<Self> {
        if !path.exists() {
            return Err(ClientError::NoVault(path.to_path_buf()));
        }
        let store = Store::open(path)?;
        let bundle = store.account_bundle()?;
        let (keys, password_keys, recovery_key) = match credential {
            Credential::MasterPassword(password) => {
                let pkeys = PasswordKeys::derive(password, &bundle.kdf)?;
                (bundle.unlock_with_password_keys(&pkeys)?, Some(pkeys), None)
            }
            Credential::RecoveryKey(rk) => {
                let copy = RecoveryKey::parse(rk.to_display_string()?.as_str())?;
                (bundle.unlock_with_recovery_key(rk)?, None, Some(copy))
            }
        };
        // Integrity check of the local device identity.
        let device = keys.open_device_identity(&store.sealed_device()?)?;
        let wrapped = store.wrapped_vault_keys()?;
        let first = wrapped.first().ok_or(ClientError::EmptyStore)?;
        let vault = keys.open_vault_key(first)?;
        Ok(Self {
            path: path.to_path_buf(),
            store,
            keys,
            vault,
            device,
            password_keys,
            recovery_key,
        })
    }

    /// Checks the master password again (before a sensitive operation in an
    /// already unlocked session).
    ///
    /// # Errors
    /// [`ClientError::InvalidCredentials`] if it is wrong.
    pub fn verify_master_password(&self, password: &MasterPassword) -> Result<()> {
        let bundle = self.store.account_bundle()?;
        bundle.unlock_with_password(password)?;
        Ok(())
    }

    /// Path of the vault file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// This device's identifier.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device.device_id()
    }

    /// How the vault was unlocked.
    #[must_use]
    pub const fn unlock_method(&self) -> UnlockMethod {
        if self.password_keys.is_some() {
            UnlockMethod::MasterPassword
        } else {
            UnlockMethod::RecoveryKey
        }
    }

    /// General information.
    ///
    /// # Errors
    /// Store errors.
    pub fn info(&self) -> Result<VaultInfo> {
        let bundle = self.store.account_bundle()?;
        let params = bundle.kdf.params()?;
        let certificate = self
            .store
            .device_certificate()?
            .ok_or(ClientError::NoCertificate)?;
        Ok(VaultInfo {
            account_id: self.keys.account_id(),
            device_id: certificate.device.device_id,
            device_name: certificate.device.name.clone(),
            platform: certificate.device.platform,
            enrolled_at: certificate.device.created_at_unix,
            kdf: KdfView {
                memory_kib: params.memory_kib,
                iterations: params.iterations,
                parallelism: params.parallelism,
            },
            recovery_key_configured: bundle.account_key_by_recovery.is_some(),
            items: self.store.items(&self.vault.vault_id())?.len(),
            pending_changes: self.store.pending_changes()?.len(),
            remote: self
                .store
                .remote()?
                .map(|(server, email)| RemoteView { server, email }),
            unlocked_with: self.unlock_method(),
        })
    }

    // ------------------------------------------------------------- items

    fn decrypted(&self) -> Result<Vec<(StoredItem, ItemData)>> {
        self.store
            .items(&self.vault.vault_id())?
            .into_iter()
            .map(|stored| {
                let data = codec::open(&self.vault, &stored.item)?;
                Ok((stored, data))
            })
            .collect()
    }

    fn stored(&self, id: &ItemId) -> Result<StoredItem> {
        let stored = self.store.item(id)?.ok_or(ClientError::ItemNotFound)?;
        if stored.item.vault_id != self.vault.vault_id() {
            return Err(ClientError::ItemNotFound);
        }
        Ok(stored)
    }

    /// Items matching `query` (title, folder, tags, username, URLs; never
    /// secrets), sorted by title.
    ///
    /// # Errors
    /// Store or decryption errors.
    pub fn items(&self, query: &str) -> Result<Vec<ItemSummary>> {
        let mut rows: Vec<ItemSummary> = self
            .decrypted()?
            .iter()
            .filter(|(_, d)| d.matches(query))
            .map(|(s, d)| ItemSummary::new(s.item.item_id, d))
            .collect();
        rows.sort_by(|a, b| {
            a.title
                .to_lowercase()
                .cmp(&b.title.to_lowercase())
                .then(a.id.cmp(&b.id))
        });
        Ok(rows)
    }

    /// The decrypted item (for clients that display secrets themselves,
    /// such as the CLI).
    ///
    /// # Errors
    /// [`ClientError::ItemNotFound`] or decryption errors.
    pub fn item(&self, id: &ItemId) -> Result<ItemData> {
        Ok(codec::open(&self.vault, &self.stored(id)?.item)?)
    }

    /// View of an item, without secret values.
    ///
    /// # Errors
    /// As [`Self::item`].
    pub fn item_view(&self, id: &ItemId) -> Result<ItemView> {
        Ok(ItemView::new(*id, &self.item(id)?))
    }

    /// Resolves an ID prefix (at least [`MIN_REFERENCE_CHARS`] characters).
    ///
    /// # Errors
    /// [`ClientError::InvalidReference`], [`ClientError::NoMatch`],
    /// [`ClientError::Ambiguous`].
    pub fn find(&self, reference: &str) -> Result<ItemId> {
        let r = reference.trim().to_lowercase();
        if r.chars().count() < MIN_REFERENCE_CHARS {
            return Err(ClientError::InvalidReference(
                "an item reference needs at least 4 characters of its ID",
            ));
        }
        let matches: Vec<ItemId> = self
            .store
            .items(&self.vault.vault_id())?
            .into_iter()
            .map(|s| s.item.item_id)
            .filter(|id| id.to_string().starts_with(&r))
            .collect();
        match matches.as_slice() {
            [one] => Ok(*one),
            [] => Err(ClientError::NoMatch {
                what: "item",
                reference: reference.to_owned(),
            }),
            many => Err(ClientError::Ambiguous {
                what: "item",
                reference: reference.to_owned(),
                count: many.len(),
            }),
        }
    }

    /// Adds a new item.
    ///
    /// # Errors
    /// Validation or store errors.
    pub fn create_item(&mut self, data: &ItemData, now: u64) -> Result<ItemId> {
        data.validate()?;
        let sealed = codec::seal_new(&self.vault, data)?;
        self.store.upsert_item(&sealed, now)?;
        Ok(sealed.item_id)
    }

    /// Adds a new item from an edit request.
    ///
    /// # Errors
    /// As [`ItemDraft::into_new_item`] and [`Self::create_item`].
    pub fn create_from_draft(&mut self, draft: ItemDraft, now: u64) -> Result<ItemId> {
        let data = draft.into_new_item(now)?;
        self.create_item(&data, now)
    }

    /// Modifies an item. `edit` receives the decrypted item; the result is
    /// validated, re-encrypted under a fresh key and queued for
    /// synchronization. Returns the new local revision.
    ///
    /// # Errors
    /// [`ClientError::ItemNotFound`], the error of `edit`, validation or
    /// store errors.
    pub fn update_item(
        &mut self,
        id: &ItemId,
        now: u64,
        edit: impl FnOnce(&mut ItemData) -> Result<()>,
    ) -> Result<u64> {
        let stored = self.stored(id)?;
        let mut data = codec::open(&self.vault, &stored.item)?;
        let now = now.max(data.updated_at);
        edit(&mut data)?;
        data.updated_at = data.updated_at.max(now);
        data.validate()?;
        let sealed = codec::seal_update(&self.vault, &stored.item, &data)?;
        Ok(self.store.upsert_item(&sealed, now)?)
    }

    /// Applies an edit request to an item.
    ///
    /// # Errors
    /// As [`ItemDraft::apply_to`] and [`Self::update_item`].
    pub fn update_from_draft(&mut self, id: &ItemId, draft: ItemDraft, now: u64) -> Result<u64> {
        self.update_item(id, now, |data| {
            let now = now.max(data.updated_at);
            draft.apply_to(data, now)
        })
    }

    /// Deletes an item (a tombstone is kept for synchronization).
    ///
    /// # Errors
    /// [`ClientError::ItemNotFound`] or store errors.
    pub fn delete_item(&mut self, id: &ItemId, now: u64) -> Result<()> {
        self.stored(id)?;
        Ok(self.store.delete_item(id, now)?)
    }

    /// Current TOTP code of a login.
    ///
    /// # Errors
    /// [`ClientError::NoTotp`] or TOTP errors.
    pub fn totp(&self, id: &ItemId, now: u64) -> Result<TotpView> {
        let data = self.item(id)?;
        let ItemContent::Login(login) = &data.content else {
            return Err(ClientError::NoTotp);
        };
        let uri = login.totp.as_ref().ok_or(ClientError::NoTotp)?;
        let totp = Totp::from_uri(uri.expose())?;
        let code = totp.code_at(now)?;
        Ok(TotpView {
            code: code.as_str().to_owned(),
            period: totp.period(),
            remaining: totp.seconds_remaining(now),
        })
    }

    /// Value of one field, for an explicit reveal or copy.
    ///
    /// # Errors
    /// [`ClientError::NoSuchField`], [`ClientError::WrongItemType`],
    /// [`ClientError::NoTotp`] or decryption errors.
    pub fn field_value(&self, id: &ItemId, field: Field, now: u64) -> Result<Zeroizing<String>> {
        let data = self.item(id)?;
        let some = |v: Option<&str>| {
            v.filter(|v| !v.is_empty())
                .map(|v| Zeroizing::new(v.to_owned()))
                .ok_or(ClientError::NoSuchField)
        };
        match (field, &data.content) {
            (Field::Notes, _) => some(data.notes.as_ref().map(|n| n.expose())),
            (Field::CustomField { index }, _) => {
                some(data.custom_fields.get(index).map(|f| f.value.expose()))
            }
            (Field::HistoryPassword { index }, _) => some(
                data.password_history
                    .get(index)
                    .map(|h| h.password.expose()),
            ),
            (Field::Username, ItemContent::Login(l)) => some(l.username.as_deref()),
            (Field::Password, ItemContent::Login(l)) => {
                some(l.password.as_ref().map(|p| p.expose()))
            }
            (Field::Url { index }, ItemContent::Login(l)) => {
                some(l.urls.get(index).map(String::as_str))
            }
            (Field::TotpSecret, ItemContent::Login(l)) => some(l.totp.as_ref().map(|t| t.expose())),
            (Field::TotpCode, ItemContent::Login(_)) => {
                Ok(Zeroizing::new(self.totp(id, now)?.code))
            }
            (Field::BackupCode { index }, ItemContent::Login(l)) => {
                some(l.backup_codes.get(index).map(|c| c.expose()))
            }
            (Field::CardNumber, ItemContent::PaymentCard(c)) => {
                some(c.number.as_ref().map(|n| n.expose()))
            }
            (Field::SecurityCode, ItemContent::PaymentCard(c)) => {
                some(c.security_code.as_ref().map(|s| s.expose()))
            }
            (Field::Pin, ItemContent::PaymentCard(c)) => some(c.pin.as_ref().map(|p| p.expose())),
            (Field::DocumentNumber { index }, ItemContent::Identity(i)) => {
                some(i.documents.get(index).map(|d| d.number.expose()))
            }
            _ => Err(ClientError::WrongItemType),
        }
    }

    /// Restores the previous password at `index` (0 = most recent) as the
    /// current one; the current password goes to the history.
    ///
    /// # Errors
    /// [`ClientError::ItemNotFound`] or item errors.
    pub fn restore_password(&mut self, id: &ItemId, index: usize, now: u64) -> Result<u64> {
        self.update_item(id, now, |data| {
            Ok(data.restore_password(index, now.max(data.updated_at))?)
        })
    }

    /// Permanently deletes the previous password at `index`.
    ///
    /// # Errors
    /// [`ClientError::ItemNotFound`] or item errors.
    pub fn delete_history_entry(&mut self, id: &ItemId, index: usize, now: u64) -> Result<u64> {
        self.update_item(id, now, |data| {
            Ok(data.delete_history_entry(index, now.max(data.updated_at))?)
        })
    }

    // ---------------------------------------------------- account & server

    fn remote(&self) -> Result<Option<(Api<UreqTransport>, String)>> {
        match self.store.remote()? {
            Some((url, email)) => Ok(Some((Api::new(UreqTransport::new(&url)?), email))),
            None => Ok(None),
        }
    }

    fn remote_required(&self) -> Result<(Api<UreqTransport>, String)> {
        self.remote()?.ok_or(ClientError::NotRegistered)
    }

    fn full_session(&self, api: &Api<UreqTransport>, email: &str) -> Result<lk_sync::Session> {
        let keys = self
            .password_keys
            .as_ref()
            .ok_or(ClientError::NeedsMasterPassword)?;
        Ok(login_registered(api, email, keys, &self.device)?)
    }

    /// Server binding, if registered.
    ///
    /// # Errors
    /// Store errors.
    pub fn remote_view(&self) -> Result<Option<RemoteView>> {
        Ok(self
            .store
            .remote()?
            .map(|(server, email)| RemoteView { server, email }))
    }

    /// Registers the account on a server (first device), then synchronizes.
    /// The recovery key registers the recovery credential.
    ///
    /// # Errors
    /// [`ClientError::AlreadyRegistered`], [`ClientError::NeedsMasterPassword`],
    /// [`ClientError::InvalidCredentials`] (wrong recovery key), network or
    /// server errors (e.g. e-mail taken).
    pub fn register(
        &mut self,
        server: &str,
        email: &str,
        recovery_key: &RecoveryKey,
        now: u64,
    ) -> Result<SyncSummary> {
        if self.store.remote()?.is_some() {
            return Err(ClientError::AlreadyRegistered);
        }
        let email = normalized_email(email)?;
        let server = lk_sync::normalize_server_url(server)?;
        let password_keys = self
            .password_keys
            .as_ref()
            .ok_or(ClientError::NeedsMasterPassword)?;
        let certificate = self
            .store
            .device_certificate()?
            .ok_or(ClientError::NoCertificate)?;
        let bundle = self.store.account_bundle()?;
        // The recovery key must be this account's: check before registering.
        bundle.unlock_with_recovery_key(recovery_key)?;
        let api = Api::new(UreqTransport::new(&server)?);
        register_account(
            &api,
            &email,
            password_keys,
            recovery_key,
            &bundle,
            &certificate,
        )?;
        self.store.set_remote(&server, &email)?;
        self.sync(false, now)
    }

    /// Synchronizes every vault. With `reset`, runs a full
    /// resynchronization (after a server restore, see
    /// [`lk_sync::resync_vault`]).
    ///
    /// # Errors
    /// [`ClientError::NotRegistered`], [`ClientError::NeedsMasterPassword`],
    /// network, server or rollback errors.
    pub fn sync(&mut self, reset: bool, now: u64) -> Result<SyncSummary> {
        let (api, email) = self.remote_required()?;
        let session = self.full_session(&api, &email)?;
        let mut total = SyncSummary::default();
        let result = (|| {
            for wrapped in self.store.wrapped_vault_keys()? {
                let vault = self.keys.open_vault_key(&wrapped)?;
                let report = if reset {
                    resync_vault(&api, &session, &mut self.store, &vault, &wrapped, now)?
                } else {
                    sync_vault(&api, &session, &mut self.store, &vault, &wrapped, now)?
                };
                total.add(&report);
            }
            Ok::<(), ClientError>(())
        })();
        let _ = api.logout(&session);
        result.map(|()| total)
    }

    /// The account's devices, verified with the account key (fails closed:
    /// one forged entry rejects the whole list).
    ///
    /// # Errors
    /// [`ClientError::UntrustedDeviceList`], network or server errors.
    pub fn devices(&self) -> Result<Vec<DeviceView>> {
        let (api, email) = self.remote_required()?;
        let session = self.full_session(&api, &email)?;
        let list = api.devices(&session);
        let _ = api.logout(&session);
        let list = list?;
        let certificates: Vec<_> = list.devices.iter().map(|d| d.certificate.clone()).collect();
        let revocations: Vec<_> = list
            .devices
            .iter()
            .filter_map(|d| d.revocation.clone())
            .collect();
        let trusted = lk_core::trusted_devices(
            &self.keys.account_id(),
            &self.keys.signing_public_key(),
            &certificates,
            &revocations,
        )
        .map_err(|_| ClientError::UntrustedDeviceList)?;
        let mut out = Vec::new();
        for entry in &list.devices {
            let d = &entry.certificate.device;
            let status = if entry.revocation.is_some() {
                DeviceStatus::Revoked
            } else if !trusted.iter().any(|t| t.device_id == d.device_id) {
                // Unreachable after a successful verification; fail closed.
                return Err(ClientError::UntrustedDeviceList);
            } else if d.device_id == self.device.device_id() {
                DeviceStatus::ThisDevice
            } else {
                DeviceStatus::Active
            };
            out.push(DeviceView {
                id: d.device_id,
                name: d.name.clone(),
                platform: d.platform,
                status,
                enrolled_at: d.created_at_unix,
                last_seen: entry.last_seen_unix,
            });
        }
        out.sort_by(|a, b| {
            (
                a.status != DeviceStatus::ThisDevice,
                a.status == DeviceStatus::Revoked,
                a.enrolled_at,
            )
                .cmp(&(
                    b.status != DeviceStatus::ThisDevice,
                    b.status == DeviceStatus::Revoked,
                    b.enrolled_at,
                ))
        });
        Ok(out)
    }

    /// Resolves a device ID prefix among the account's devices.
    ///
    /// # Errors
    /// [`ClientError::InvalidReference`], [`ClientError::NoMatch`],
    /// [`ClientError::Ambiguous`], or the errors of [`Self::devices`].
    pub fn find_device(&self, reference: &str) -> Result<DeviceId> {
        let r = reference.trim().to_lowercase();
        if r.chars().count() < MIN_REFERENCE_CHARS {
            return Err(ClientError::InvalidReference(
                "a device reference needs at least 4 characters of its ID",
            ));
        }
        let matches: Vec<DeviceId> = self
            .devices()?
            .into_iter()
            .map(|d| d.id)
            .filter(|id| id.to_string().starts_with(&r))
            .collect();
        match matches.as_slice() {
            [one] => Ok(*one),
            [] => Err(ClientError::NoMatch {
                what: "device",
                reference: reference.to_owned(),
            }),
            many => Err(ClientError::Ambiguous {
                what: "device",
                reference: reference.to_owned(),
                count: many.len(),
            }),
        }
    }

    /// Revokes another device: the server refuses it from its next request.
    /// Data it already decrypted cannot be erased remotely.
    ///
    /// # Errors
    /// [`ClientError::CannotRevokeSelf`], network or server errors.
    pub fn revoke_device(&self, device: DeviceId, now: u64) -> Result<()> {
        if device == self.device.device_id() {
            return Err(ClientError::CannotRevokeSelf);
        }
        let (api, email) = self.remote_required()?;
        let session = self.full_session(&api, &email)?;
        let revocation = self.keys.revoke_device(device, now)?;
        let result = api.revoke(&session, &revocation);
        let _ = api.logout(&session);
        Ok(result?)
    }

    /// Changes the master password (or, unlocked with the recovery key,
    /// resets it). When registered, the server credential is replaced first:
    /// if that fails, nothing changes locally. Afterwards the vault counts
    /// as unlocked with the new master password.
    ///
    /// # Errors
    /// Network or server errors; key errors.
    pub fn change_master_password(
        &mut self,
        new_password: &MasterPassword,
        now: u64,
    ) -> Result<()> {
        let bundle = self.store.account_bundle()?;
        let (updated, new_auth) =
            self.keys
                .change_password(&bundle, new_password, KdfParams::recommended())?;
        if let Some((api, email)) = self.remote()? {
            let session = match &self.recovery_key {
                Some(rk) => api.login(
                    &email,
                    &rk.server_auth_key()?,
                    CredentialKind::Recovery,
                    self.device.device_id(),
                )?,
                None => self.full_session(&api, &email)?,
            };
            let result =
                api.replace_credential(&session, CredentialKind::Password, &new_auth, &updated);
            if self.recovery_key.is_none() {
                let _ = api.logout(&session);
            }
            result?;
        }
        self.store.replace_account_bundle(&updated, now)?;
        self.password_keys = Some(PasswordKeys::derive(new_password, &updated.kdf)?);
        self.recovery_key = None;
        Ok(())
    }

    /// Replaces the recovery key; returns the new one (show it once). The
    /// previous key stops working.
    ///
    /// # Errors
    /// [`ClientError::NeedsMasterPassword`], network or server errors.
    pub fn rotate_recovery_key(&mut self, now: u64) -> Result<RecoveryKey> {
        if self.password_keys.is_none() {
            return Err(ClientError::NeedsMasterPassword);
        }
        let bundle = self.store.account_bundle()?;
        let (updated, recovery_key, new_auth) = self.keys.rotate_recovery_key(&bundle)?;
        if let Some((api, email)) = self.remote()? {
            let session = self.full_session(&api, &email)?;
            let result =
                api.replace_credential(&session, CredentialKind::Recovery, &new_auth, &updated);
            let _ = api.logout(&session);
            result?;
        }
        self.store.replace_account_bundle(&updated, now)?;
        Ok(recovery_key)
    }
}
