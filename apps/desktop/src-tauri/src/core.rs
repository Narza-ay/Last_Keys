//! Application state and every operation of the desktop back end, without
//! any dependency on Tauri, so that it can be tested directly. Commands
//! (`commands.rs`) are thin wrappers around these methods.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lk_client::{
    Credential, DeviceId, DeviceView, Field, ItemDraft, ItemId, ItemSummary, ItemView,
    MasterPassword, Platform, RecoveryKey, SyncSummary, TotpView, Vault, VaultInfo, Zeroizing,
};
use lk_generator::{PassphrasePolicy, PasswordPolicy, StrengthLevel};
use serde::{Deserialize, Serialize};

use crate::clipboard::{ClipboardBackend, ClipboardGuard};
use crate::error::{UiError, UiResult};
use crate::settings::Settings;

/// Current Unix time (seconds).
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Platform of this build.
#[must_use]
pub const fn current_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Linux
    }
}

/// A sensible default name for this device (editable by the user).
#[must_use]
pub fn default_device_name() -> String {
    let from_env = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok();
    let from_file = || {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|h| h.trim().to_owned())
    };
    from_env
        .or_else(from_file)
        .map(|n| n.trim().chars().take(64).collect::<String>())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| {
            match current_platform() {
                Platform::Windows => "Windows PC",
                Platform::MacOs => "Mac",
                _ => "Linux computer",
            }
            .to_owned()
        })
}

/// Where the application keeps its files.
#[derive(Clone, Debug)]
pub struct Paths {
    /// The vault (an `lk-store` file).
    pub vault: PathBuf,
    /// Preferences.
    pub settings: PathBuf,
}

impl Paths {
    /// Both files in one directory.
    #[must_use]
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            vault: dir.join("vault.lkvault"),
            settings: dir.join("settings.json"),
        }
    }
}

/// What the UI needs to know at start-up and after a lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    /// A vault exists on this device.
    pub vault_exists: bool,
    /// It is unlocked.
    pub unlocked: bool,
    /// Platform.
    pub platform: Platform,
    /// Application version.
    pub version: &'static str,
    /// Suggested device name for onboarding.
    pub default_device_name: String,
}

/// Options of the password generator, as sent by the UI.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordOptions {
    /// Length.
    pub length: usize,
    /// Lower-case letters.
    pub lowercase: bool,
    /// Upper-case letters.
    pub uppercase: bool,
    /// Digits.
    pub digits: bool,
    /// Symbols.
    pub symbols: bool,
    /// Leave out easily confused characters.
    pub exclude_ambiguous: bool,
}

/// Options of the passphrase generator, as sent by the UI.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PassphraseOptions {
    /// Number of words.
    pub words: usize,
    /// Separator.
    pub separator: String,
    /// Capitalize each word.
    pub capitalize: bool,
    /// Add a number.
    pub include_number: bool,
}

/// A generated secret, shown in the generator.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedView {
    /// The secret.
    pub value: String,
    /// Entropy (bits).
    pub entropy_bits: f64,
    /// Strength level.
    pub level: StrengthLevel,
}

/// Result of a copy: when the clipboard will be cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyResult {
    /// Seconds until the clipboard is cleared.
    pub clears_in_seconds: u32,
}

fn master_password(text: &str) -> UiResult<MasterPassword> {
    let text = Zeroizing::new(text.to_owned());
    MasterPassword::new(&text).map_err(|_| UiError::new("invalid_input", "invalid master password"))
}

fn recovery_key(text: &str) -> UiResult<RecoveryKey> {
    RecoveryKey::parse(text)
        .map_err(|_| UiError::new("invalid_recovery_key", "this is not a valid recovery key"))
}

fn display(recovery_key: &RecoveryKey) -> UiResult<String> {
    recovery_key
        .to_display_string()
        .map(|s| s.as_str().to_owned())
        .map_err(|_| UiError::internal())
}

/// The desktop back end.
pub struct DesktopCore {
    paths: Paths,
    platform: Platform,
    vault: Option<Vault>,
    settings: Settings,
    last_activity: Instant,
    clipboard: ClipboardGuard,
}

impl DesktopCore {
    /// Starts locked, with the stored preferences.
    #[must_use]
    pub fn new(
        paths: Paths,
        platform: Platform,
        clipboard: Box<dyn ClipboardBackend>,
        now: Instant,
    ) -> Self {
        let settings = Settings::load(&paths.settings);
        Self {
            paths,
            platform,
            vault: None,
            settings,
            last_activity: now,
            clipboard: ClipboardGuard::new(clipboard),
        }
    }

    fn vault(&self) -> UiResult<&Vault> {
        self.vault.as_ref().ok_or_else(UiError::locked)
    }

    fn vault_mut(&mut self) -> UiResult<&mut Vault> {
        self.vault.as_mut().ok_or_else(UiError::locked)
    }

    // ------------------------------------------------- status & settings

    /// Start-up information.
    #[must_use]
    pub fn status(&self) -> AppStatus {
        AppStatus {
            vault_exists: self.paths.vault.exists(),
            unlocked: self.vault.is_some(),
            platform: self.platform,
            version: env!("CARGO_PKG_VERSION"),
            default_device_name: default_device_name(),
        }
    }

    /// Current preferences.
    #[must_use]
    pub fn settings(&self) -> Settings {
        self.settings.clone()
    }

    /// Replaces the preferences.
    ///
    /// # Errors
    /// `invalid_setting`, or `internal` if they cannot be saved.
    pub fn set_settings(&mut self, settings: Settings) -> UiResult<Settings> {
        settings.validate()?;
        settings.save(&self.paths.settings)?;
        self.settings = settings;
        Ok(self.settings.clone())
    }

    // ---------------------------------------------------------- locking

    /// Records user activity (postpones auto-lock).
    pub fn touch(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Periodic work: clipboard clearing and auto-lock. Returns `true` when
    /// this call locked the vault.
    pub fn tick(&mut self, now: Instant) -> bool {
        self.clipboard.tick(now);
        let idle = now.saturating_duration_since(self.last_activity);
        let limit =
            Duration::from_secs(u64::from(self.settings.auto_lock_minutes).saturating_mul(60));
        if self.vault.is_some() && idle >= limit {
            self.lock();
            return true;
        }
        false
    }

    /// Locks: the vault is dropped (keys zeroized) and a copied secret is
    /// removed from the clipboard.
    pub fn lock(&mut self) {
        self.vault = None;
        self.clipboard.clear_if_ours();
    }

    // ------------------------------------------------- vault lifecycle

    /// Creates the account and vault; returns the recovery key to show once.
    ///
    /// # Errors
    /// `vault_exists`, `weak_master_password`, `password_mismatch`.
    pub fn create_vault(
        &mut self,
        password: &str,
        confirmation: &str,
        device_name: &str,
        now: Instant,
    ) -> UiResult<String> {
        let password = lk_client::new_master_password(password, confirmation)?;
        let created = Vault::create(
            &self.paths.vault,
            &password,
            device_name.trim(),
            self.platform,
            unix_now(),
        )?;
        let shown = display(&created.recovery_key)?;
        self.vault = Some(created.vault);
        self.touch(now);
        Ok(shown)
    }

    /// Enrolls this device in an existing account; returns the number of
    /// items received.
    ///
    /// # Errors
    /// `vault_exists`, `invalid_credentials`, `network`, server errors.
    pub fn enroll(
        &mut self,
        server: &str,
        email: &str,
        password: &str,
        device_name: &str,
        now: Instant,
    ) -> UiResult<usize> {
        let password = master_password(password)?;
        let enrolled = Vault::enroll(
            &self.paths.vault,
            server,
            email,
            &password,
            device_name.trim(),
            self.platform,
            unix_now(),
        )?;
        self.vault = Some(enrolled.vault);
        self.touch(now);
        Ok(enrolled.received)
    }

    /// Unlocks with the master password.
    ///
    /// # Errors
    /// `no_vault`, `invalid_credentials`.
    pub fn unlock(&mut self, password: &str, now: Instant) -> UiResult<()> {
        let password = master_password(password)?;
        self.vault = Some(Vault::unlock(
            &self.paths.vault,
            &Credential::MasterPassword(&password),
        )?);
        self.touch(now);
        Ok(())
    }

    /// Unlocks with the recovery key (then the master password can be
    /// reset).
    ///
    /// # Errors
    /// `invalid_recovery_key`, `invalid_credentials`.
    pub fn unlock_with_recovery_key(&mut self, key: &str, now: Instant) -> UiResult<()> {
        let key = recovery_key(key)?;
        self.vault = Some(Vault::unlock(
            &self.paths.vault,
            &Credential::RecoveryKey(&key),
        )?);
        self.touch(now);
        Ok(())
    }

    /// Vault information.
    ///
    /// # Errors
    /// `locked`.
    pub fn info(&self) -> UiResult<VaultInfo> {
        Ok(self.vault()?.info()?)
    }

    // ------------------------------------------------------------ items

    /// Item list.
    ///
    /// # Errors
    /// `locked`.
    pub fn list_items(&self, query: &str) -> UiResult<Vec<ItemSummary>> {
        Ok(self.vault()?.items(query)?)
    }

    /// Item view (no secret values).
    ///
    /// # Errors
    /// `locked`, `not_found`.
    pub fn get_item(&self, id: &ItemId) -> UiResult<ItemView> {
        Ok(self.vault()?.item_view(id)?)
    }

    /// Value of one field, for an explicit reveal.
    ///
    /// # Errors
    /// `locked`, `not_found`.
    pub fn reveal_field(&self, id: &ItemId, field: Field) -> UiResult<String> {
        Ok(self
            .vault()?
            .field_value(id, field, unix_now())?
            .as_str()
            .to_owned())
    }

    /// Copies one field to the clipboard without sending it to the UI.
    ///
    /// # Errors
    /// `locked`, `not_found`, `clipboard`.
    pub fn copy_field(&mut self, id: &ItemId, field: Field, now: Instant) -> UiResult<CopyResult> {
        let value = self.vault()?.field_value(id, field, unix_now())?;
        self.copy_text(&value, now)
    }

    /// Copies a text (e.g. a freshly generated password) with the same
    /// clearing policy.
    ///
    /// # Errors
    /// `clipboard`.
    pub fn copy_text(&mut self, value: &str, now: Instant) -> UiResult<CopyResult> {
        let seconds = self.settings.clipboard_clear_seconds;
        self.clipboard
            .copy(value, now, Duration::from_secs(u64::from(seconds)))?;
        Ok(CopyResult {
            clears_in_seconds: seconds,
        })
    }

    /// Current TOTP code.
    ///
    /// # Errors
    /// `locked`, `no_totp`.
    pub fn totp(&self, id: &ItemId) -> UiResult<TotpView> {
        Ok(self.vault()?.totp(id, unix_now())?)
    }

    /// Adds an item.
    ///
    /// # Errors
    /// `locked`, `invalid_input`.
    pub fn create_item(&mut self, draft: ItemDraft) -> UiResult<ItemId> {
        Ok(self.vault_mut()?.create_from_draft(draft, unix_now())?)
    }

    /// Modifies an item.
    ///
    /// # Errors
    /// `locked`, `not_found`, `invalid_input`, `wrong_item_type`.
    pub fn update_item(&mut self, id: &ItemId, draft: ItemDraft) -> UiResult<()> {
        self.vault_mut()?.update_from_draft(id, draft, unix_now())?;
        Ok(())
    }

    /// Deletes an item.
    ///
    /// # Errors
    /// `locked`, `not_found`.
    pub fn delete_item(&mut self, id: &ItemId) -> UiResult<()> {
        Ok(self.vault_mut()?.delete_item(id, unix_now())?)
    }

    /// Restores a previous password.
    ///
    /// # Errors
    /// `locked`, `not_found`, `invalid_input`.
    pub fn restore_password(&mut self, id: &ItemId, index: usize) -> UiResult<()> {
        self.vault_mut()?.restore_password(id, index, unix_now())?;
        Ok(())
    }

    /// Deletes a previous password.
    ///
    /// # Errors
    /// `locked`, `not_found`, `invalid_input`.
    pub fn delete_history_entry(&mut self, id: &ItemId, index: usize) -> UiResult<()> {
        self.vault_mut()?
            .delete_history_entry(id, index, unix_now())?;
        Ok(())
    }

    // -------------------------------------------------------- generator

    /// Generates a password.
    ///
    /// # Errors
    /// `invalid_input` for impossible options.
    pub fn generate_password(&self, options: &PasswordOptions) -> UiResult<GeneratedView> {
        let min = |enabled: bool| usize::from(enabled);
        let generated = lk_generator::generate_password(&PasswordPolicy {
            length: options.length,
            lowercase: options.lowercase,
            uppercase: options.uppercase,
            digits: options.digits,
            symbols: options.symbols,
            min_lowercase: min(options.lowercase),
            min_uppercase: min(options.uppercase),
            min_digits: min(options.digits),
            min_symbols: min(options.symbols),
            exclude_ambiguous: options.exclude_ambiguous,
            exclude: String::new(),
        })?;
        Ok(GeneratedView {
            value: generated.expose_secret().to_owned(),
            entropy_bits: generated.entropy_bits(),
            level: generated.level(),
        })
    }

    /// Generates a passphrase.
    ///
    /// # Errors
    /// `invalid_input` for impossible options.
    pub fn generate_passphrase(&self, options: &PassphraseOptions) -> UiResult<GeneratedView> {
        let generated = lk_generator::generate_passphrase(&PassphrasePolicy {
            words: options.words,
            separator: options.separator.clone(),
            capitalize: options.capitalize,
            include_number: options.include_number,
        })?;
        Ok(GeneratedView {
            value: generated.expose_secret().to_owned(),
            entropy_bits: generated.entropy_bits(),
            level: generated.level(),
        })
    }

    // ---------------------------------------------------------- account

    fn verify(&self, current_password: &str) -> UiResult<()> {
        // A missing or malformed current password is simply a wrong one.
        let password = master_password(current_password)
            .map_err(|_| UiError::from(lk_client::ClientError::InvalidCredentials))?;
        Ok(self.vault()?.verify_master_password(&password)?)
    }

    /// Changes the master password. The current one is required, except
    /// after unlocking with the recovery key (password reset).
    ///
    /// # Errors
    /// `invalid_credentials`, `weak_master_password`, `password_mismatch`,
    /// network or server errors.
    pub fn change_master_password(
        &mut self,
        current: Option<&str>,
        new: &str,
        confirmation: &str,
    ) -> UiResult<()> {
        if self.vault()?.unlock_method() == lk_client::UnlockMethod::MasterPassword {
            self.verify(current.unwrap_or_default())?;
        }
        let new = lk_client::new_master_password(new, confirmation)?;
        Ok(self.vault_mut()?.change_master_password(&new, unix_now())?)
    }

    /// Replaces the recovery key (current master password required);
    /// returns the new key to show once.
    ///
    /// # Errors
    /// `invalid_credentials`, `needs_master_password`, network or server
    /// errors.
    pub fn rotate_recovery_key(&mut self, current_password: &str) -> UiResult<String> {
        self.verify(current_password)?;
        let key = self.vault_mut()?.rotate_recovery_key(unix_now())?;
        display(&key)
    }

    // ----------------------------------------------------------- server

    /// Registers the account on a server and synchronizes.
    ///
    /// # Errors
    /// `invalid_recovery_key`, `invalid_credentials`, `email_taken`,
    /// `invalid_server_url`, `network`, server errors.
    pub fn register(&mut self, server: &str, email: &str, recovery: &str) -> UiResult<SyncSummary> {
        let key = recovery_key(recovery)?;
        Ok(self
            .vault_mut()?
            .register(server, email, &key, unix_now())?)
    }

    /// Synchronizes (with `reset`, a full resynchronization after a server
    /// restore).
    ///
    /// # Errors
    /// `not_registered`, `server_rollback`, `network`, server errors.
    pub fn sync(&mut self, reset: bool) -> UiResult<SyncSummary> {
        Ok(self.vault_mut()?.sync(reset, unix_now())?)
    }

    /// The account's devices.
    ///
    /// # Errors
    /// `not_registered`, `untrusted_device_list`, `network`.
    pub fn devices(&self) -> UiResult<Vec<DeviceView>> {
        Ok(self.vault()?.devices()?)
    }

    /// Revokes another device.
    ///
    /// # Errors
    /// `cannot_revoke_self`, `network`, server errors.
    pub fn revoke_device(&self, device: DeviceId) -> UiResult<()> {
        Ok(self.vault()?.revoke_device(device, unix_now())?)
    }
}

#[cfg(test)]
mod tests;
