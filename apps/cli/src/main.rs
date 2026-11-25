//! `lk` — Last Keys command-line client.
//!
//! Exercises the complete local stack (key hierarchy, vault model, local
//! encrypted store, generator, TOTP) end to end. Secrets are read from hidden
//! prompts or, with `--password-stdin`, one per line from standard input;
//! they are never accepted as arguments.

#![forbid(unsafe_code)]
// A command-line program communicates through stdout and stderr.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod error;
mod format;
mod input;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use lk_core::{AccountKeys, DeviceIdentity, PasswordKeys, Platform, VaultKey, create_account};
use lk_crypto::{KdfParams, MasterPassword, RecoveryKey};
use lk_generator::{PassphrasePolicy, PasswordPolicy, generate_passphrase, generate_password};
use lk_protocol::CredentialKind;
use lk_store::{Store, StoredItem};
use lk_sync::{
    Api, SyncReport, UreqTransport, enroll_device, login_registered, register_account,
    resync_vault, sync_vault,
};
use lk_totp::Totp;
use lk_vault::{
    ItemContent, ItemData, ItemKind, Login, PaymentCard, SecretString, SecureNote, codec,
    normalize_totp, normalize_url,
};

use crate::error::{Result, fail};
use crate::format::{short_id, utc};
use crate::input::SecretInput;

/// Minimum master password length accepted by this client (characters).
const MIN_MASTER_PASSWORD_CHARS: usize = 12;

#[derive(Parser)]
#[command(name = "lk", version, about = "Last Keys command-line client")]
struct Cli {
    /// Vault file (default: $LK_VAULT, then ~/.lastkeys/vault.lkvault).
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    /// Read secrets from standard input, one per line, instead of prompting.
    #[arg(long, global = true)]
    password_stdin: bool,
    /// Unlock with the recovery key instead of the master password.
    #[arg(long, global = true)]
    recovery_key: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new account and vault on this device.
    Init {
        /// Name of this device.
        #[arg(long, default_value = "lk command line")]
        device_name: String,
    },
    /// Show account, device and vault information.
    Info,
    /// Add an item.
    #[command(subcommand)]
    Add(AddCommand),
    /// List items, optionally filtered by a search query.
    List {
        /// Text searched in titles, usernames, URLs, folders and tags.
        query: Option<String>,
    },
    /// Show an item.
    Show {
        /// Item ID or ID prefix (at least 4 characters).
        item: String,
        /// Display secrets in clear.
        #[arg(long)]
        reveal: bool,
    },
    /// Modify an item.
    Edit(EditArgs),
    /// Delete an item.
    Delete {
        /// Item ID or ID prefix.
        item: String,
    },
    /// Show the password history of a login.
    History {
        /// Item ID or ID prefix.
        item: String,
        /// Display previous passwords in clear.
        #[arg(long)]
        reveal: bool,
    },
    /// Show the current TOTP code of a login.
    Totp {
        /// Item ID or ID prefix.
        item: String,
    },
    /// Generate a password or a passphrase (no vault needed).
    Generate(GenerateArgs),
    /// Change the master password (with --recovery-key: reset a forgotten one).
    Passwd,
    /// Recovery key management.
    #[command(subcommand)]
    Recovery(RecoveryCommand),
    /// Register this vault's account on a sync server (asks for the master
    /// password and the recovery key), then synchronize.
    Register {
        /// Server URL (https://…; http:// only for the local machine).
        #[arg(long)]
        server: String,
        /// Account e-mail.
        #[arg(long)]
        email: String,
    },
    /// Set up this device from an account that already exists on a server.
    Login {
        /// Server URL.
        #[arg(long)]
        server: String,
        /// Account e-mail.
        #[arg(long)]
        email: String,
        /// Name of this device.
        #[arg(long, default_value = "lk command line")]
        device_name: String,
    },
    /// Synchronize with the server.
    Sync {
        /// Full resynchronization after the server was restored from a
        /// backup: every local item is uploaded again; versions that differ
        /// from the server's are kept as conflict copies (nothing is deleted).
        #[arg(long)]
        reset: bool,
    },
    /// List the account's devices (verified with the account key).
    Devices,
    /// Revoke a device (it immediately loses access to the server).
    Revoke {
        /// Device ID or ID prefix (at least 4 characters).
        device: String,
    },
}

#[derive(Subcommand)]
enum AddCommand {
    /// Add a login.
    Login {
        /// Title.
        #[arg(long)]
        title: String,
        /// Username or e-mail.
        #[arg(long)]
        username: Option<String>,
        /// Website address (repeatable).
        #[arg(long = "url")]
        urls: Vec<String>,
        /// Generate the password instead of prompting for it.
        #[arg(long)]
        generate: bool,
        /// Length of the generated password.
        #[arg(long, default_value_t = 20)]
        length: usize,
        /// Prompt for a TOTP secret or otpauth URI.
        #[arg(long)]
        totp: bool,
        /// Prompt for notes.
        #[arg(long)]
        notes: bool,
    },
    /// Add a secure note (one line, prompted).
    Note {
        /// Title.
        #[arg(long)]
        title: String,
    },
    /// Add a payment card (number and security code are prompted).
    Card {
        /// Title.
        #[arg(long)]
        title: String,
        /// Name on the card.
        #[arg(long)]
        cardholder: Option<String>,
        /// Expiry date, MM/YYYY.
        #[arg(long)]
        expiry: Option<String>,
    },
}

#[derive(Args)]
struct EditArgs {
    /// Item ID or ID prefix.
    item: String,
    /// New title.
    #[arg(long)]
    title: Option<String>,
    /// New username.
    #[arg(long)]
    username: Option<String>,
    /// Add a website address.
    #[arg(long = "add-url")]
    add_urls: Vec<String>,
    /// Prompt for a new password (the old one goes to the history).
    #[arg(long, conflicts_with = "generate")]
    password: bool,
    /// Generate a new password (the old one goes to the history).
    #[arg(long)]
    generate: bool,
    /// Length of the generated password.
    #[arg(long, default_value_t = 20)]
    length: usize,
    /// Restore the history entry with this number as the current password.
    #[arg(long)]
    restore_password: Option<usize>,
    /// Permanently delete the history entry with this number.
    #[arg(long)]
    delete_history: Option<usize>,
    /// Mark or unmark as favorite.
    #[arg(long)]
    favorite: Option<bool>,
}

#[derive(Args)]
struct GenerateArgs {
    /// Password length.
    #[arg(long, default_value_t = 20)]
    length: usize,
    /// Leave out upper-case letters.
    #[arg(long)]
    no_uppercase: bool,
    /// Leave out lower-case letters.
    #[arg(long)]
    no_lowercase: bool,
    /// Leave out digits.
    #[arg(long)]
    no_digits: bool,
    /// Leave out symbols.
    #[arg(long)]
    no_symbols: bool,
    /// Leave out easily confused characters.
    #[arg(long)]
    exclude_ambiguous: bool,
    /// Generate a passphrase instead.
    #[arg(long)]
    passphrase: bool,
    /// Number of words in the passphrase.
    #[arg(long, default_value_t = 6)]
    words: usize,
    /// Passphrase separator.
    #[arg(long, default_value = "-")]
    separator: String,
    /// Capitalize passphrase words.
    #[arg(long)]
    capitalize: bool,
    /// Add a digit to the passphrase.
    #[arg(long)]
    number: bool,
}

#[derive(Subcommand)]
enum RecoveryCommand {
    /// Replace the recovery key (the old one stops working).
    Rotate,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lk: {e}");
            ExitCode::FAILURE
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn vault_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(p) = &cli.vault {
        return Ok(p.clone());
    }
    if let Some(p) = std::env::var_os("LK_VAULT") {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| fail("cannot locate the home directory; use --vault"))?;
    Ok(PathBuf::from(home).join(".lastkeys").join("vault.lkvault"))
}

fn run(cli: Cli) -> Result<()> {
    let path = vault_path(&cli)?;
    let mut input = SecretInput::new(cli.password_stdin);
    match &cli.command {
        Command::Generate(args) => generate(args),
        Command::Init { device_name } => init(&path, &mut input, device_name),
        Command::Login {
            server,
            email,
            device_name,
        } => login_new_device(&path, &mut input, server, email, device_name),
        command => {
            let mut session = Session::open(&path, &mut input, cli.recovery_key)?;
            match command {
                Command::Info => session.info(&path),
                Command::Add(add) => session.add(add, &mut input),
                Command::List { query } => session.list(query.as_deref()),
                Command::Show { item, reveal } => session.show(item, *reveal),
                Command::Edit(args) => session.edit(args, &mut input),
                Command::Delete { item } => session.delete(item),
                Command::History { item, reveal } => session.history(item, *reveal),
                Command::Totp { item } => session.totp(item),
                Command::Passwd => session.passwd(&mut input),
                Command::Recovery(RecoveryCommand::Rotate) => session.rotate_recovery(),
                Command::Register { server, email } => session.register(&mut input, server, email),
                Command::Sync { reset } => session.sync(*reset).map(|_| ()),
                Command::Devices => session.devices(),
                Command::Revoke { device } => session.revoke(device),
                Command::Generate(_) | Command::Init { .. } | Command::Login { .. } => Ok(()),
            }
        }
    }
}

fn read_new_master_password(input: &mut SecretInput) -> Result<MasterPassword> {
    let pw = input.read_confirmed("New master password: ", "Repeat the master password: ")?;
    if pw.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err(fail(format!(
            "the master password must have at least {MIN_MASTER_PASSWORD_CHARS} characters"
        )));
    }
    Ok(MasterPassword::new(&pw)?)
}

fn print_recovery_key(rk: &RecoveryKey) -> Result<()> {
    let shown = rk.to_display_string()?;
    eprintln!();
    eprintln!("IMPORTANT: write down this recovery key and keep it somewhere safe.");
    eprintln!(
        "It is shown only once. Without it, a forgotten master password cannot be recovered."
    );
    println!("Recovery key: {}", shown.as_str());
    eprintln!();
    Ok(())
}

fn init(path: &Path, input: &mut SecretInput, device_name: &str) -> Result<()> {
    if path.exists() {
        return Err(fail(format!(
            "a vault already exists at {}",
            path.display()
        )));
    }
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
    let password = read_new_master_password(input)?;
    eprintln!("Deriving keys (Argon2id)...");
    let account = create_account(&password, KdfParams::recommended())?;
    let now = now();
    let device = DeviceIdentity::generate()?;
    let info = device.public_info(device_name, Platform::Cli, now)?;
    let certificate = account.keys.certify_device(info, now)?;
    let sealed = account.keys.seal_device_identity(&device)?;
    let mut store = Store::create(path, &account.bundle, &sealed, Some(&certificate), now)?;
    let (_, wrapped) = account.keys.create_vault()?;
    store.put_wrapped_vault_key(&wrapped)?;
    println!("Vault created: {}", path.display());
    println!("Account: {}", account.keys.account_id());
    println!("Device:  {}", device.device_id());
    print_recovery_key(&account.recovery_key)
}

/// Sets up this device from an existing account: enrollment with the master
/// password, local store creation, initial synchronization.
fn login_new_device(
    path: &Path,
    input: &mut SecretInput,
    server: &str,
    email: &str,
    device_name: &str,
) -> Result<()> {
    if path.exists() {
        return Err(fail(format!(
            "a vault already exists at {}",
            path.display()
        )));
    }
    let email = lk_auth::normalize_email(email).map_err(|_| fail("invalid e-mail address"))?;
    let api = Api::new(UreqTransport::new(server)?);
    let password = MasterPassword::new(&input.read("Master password: ")?)?;
    eprintln!("Deriving keys (Argon2id)...");
    let device = DeviceIdentity::generate()?;
    let now = now();
    let enrollment = enroll_device(
        &api,
        &email,
        &password,
        &device,
        device_name,
        Platform::Cli,
        now,
    )?;
    let vaults = api.vault_keys(&enrollment.session)?;
    if vaults.is_empty() {
        return Err(fail(
            "the account has no vault on the server yet; run `lk sync` on a registered device first",
        ));
    }
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
    let sealed = enrollment.keys.seal_device_identity(&device)?;
    let mut store = Store::create(
        path,
        &enrollment.bundle,
        &sealed,
        Some(&enrollment.certificate),
        now,
    )?;
    store.set_remote(&lk_sync::normalize_server_url(server)?, &email)?;
    let mut received = 0usize;
    for wrapped in &vaults {
        store.put_wrapped_vault_key(wrapped)?;
        let vault = enrollment.keys.open_vault_key(wrapped)?;
        let report = sync_vault(&api, &enrollment.session, &mut store, &vault, wrapped, now)?;
        received = received.saturating_add(report.pulled);
    }
    let _ = api.logout(&enrollment.session);
    println!(
        "Device {} enrolled on {server} as {email}.",
        device.device_id()
    );
    println!(
        "Vault created: {} ({received} item(s) received)",
        path.display()
    );
    Ok(())
}

fn generate(args: &GenerateArgs) -> Result<()> {
    let generated = if args.passphrase {
        generate_passphrase(&PassphrasePolicy {
            words: args.words,
            separator: args.separator.clone(),
            capitalize: args.capitalize,
            include_number: args.number,
        })?
    } else {
        generate_password(&password_policy(args))?
    };
    println!("{}", generated.expose_secret());
    eprintln!(
        "entropy: {:.1} bits ({:?})",
        generated.entropy_bits(),
        generated.level()
    );
    Ok(())
}

fn password_policy(args: &GenerateArgs) -> PasswordPolicy {
    let min = |enabled: bool| usize::from(enabled);
    PasswordPolicy {
        length: args.length,
        lowercase: !args.no_lowercase,
        uppercase: !args.no_uppercase,
        digits: !args.no_digits,
        symbols: !args.no_symbols,
        min_lowercase: min(!args.no_lowercase),
        min_uppercase: min(!args.no_uppercase),
        min_digits: min(!args.no_digits),
        min_symbols: min(!args.no_symbols),
        exclude_ambiguous: args.exclude_ambiguous,
        exclude: String::new(),
    }
}

fn simple_password(length: usize) -> Result<SecretString> {
    let generated = generate_password(&PasswordPolicy {
        length,
        ..PasswordPolicy::default()
    })?;
    eprintln!(
        "Generated a password of {:.0} bits.",
        generated.entropy_bits()
    );
    Ok(SecretString::new(generated.expose_secret()))
}

fn optional_secret(input: &mut SecretInput, prompt: &str) -> Result<Option<SecretString>> {
    let value = input.read(prompt)?;
    Ok((!value.is_empty()).then(|| SecretString::new(value.as_str())))
}

/// An unlocked vault.
struct Session {
    store: Store,
    keys: AccountKeys,
    vault: VaultKey,
    device: DeviceIdentity,
    /// Present when unlocked with the master password.
    password_keys: Option<PasswordKeys>,
    /// Present when unlocked with the recovery key.
    recovery_key: Option<RecoveryKey>,
}

impl Session {
    fn open(path: &Path, input: &mut SecretInput, use_recovery_key: bool) -> Result<Self> {
        if !path.exists() {
            return Err(fail(format!(
                "no vault at {} (create one with `lk init`)",
                path.display()
            )));
        }
        let store = Store::open(path)?;
        let bundle = store.account_bundle()?;
        let (keys, password_keys, recovery_key) = if use_recovery_key {
            let text = input.read("Recovery key: ")?;
            let rk = RecoveryKey::parse(&text)?;
            (bundle.unlock_with_recovery_key(&rk)?, None, Some(rk))
        } else {
            let pw = input.read("Master password: ")?;
            let pkeys = PasswordKeys::derive(&MasterPassword::new(&pw)?, &bundle.kdf)?;
            (bundle.unlock_with_password_keys(&pkeys)?, Some(pkeys), None)
        };
        // Integrity check of the local device identity.
        let device = keys.open_device_identity(&store.sealed_device()?)?;
        let wrapped = store.wrapped_vault_keys()?;
        let first = wrapped
            .first()
            .ok_or_else(|| fail("the store contains no vault"))?;
        let vault = keys.open_vault_key(first)?;
        Ok(Self {
            store,
            keys,
            vault,
            device,
            password_keys,
            recovery_key,
        })
    }

    fn remote(&self) -> Result<Option<(Api<UreqTransport>, String)>> {
        match self.store.remote()? {
            Some((url, email)) => Ok(Some((Api::new(UreqTransport::new(&url)?), email))),
            None => Ok(None),
        }
    }

    fn remote_required(&self) -> Result<(Api<UreqTransport>, String)> {
        self.remote()?.ok_or_else(|| {
            fail("this vault is not registered on a server (use `lk register` or `lk login`)")
        })
    }

    fn full_session(&self, api: &Api<UreqTransport>, email: &str) -> Result<lk_sync::Session> {
        let keys = self.password_keys.as_ref().ok_or_else(|| {
            fail("this operation needs the master password, not the recovery key")
        })?;
        Ok(login_registered(api, email, keys, &self.device)?)
    }

    fn register(&mut self, input: &mut SecretInput, server: &str, email: &str) -> Result<()> {
        if self.store.remote()?.is_some() {
            return Err(fail("this vault is already registered on a server"));
        }
        let email = lk_auth::normalize_email(email).map_err(|_| fail("invalid e-mail address"))?;
        let password_keys = self
            .password_keys
            .as_ref()
            .ok_or_else(|| fail("registration needs the master password"))?;
        let recovery = RecoveryKey::parse(
            &input.read("Recovery key (to register the recovery credential): ")?,
        )?;
        let certificate = self
            .store
            .device_certificate()?
            .ok_or_else(|| fail("this device has no certificate"))?;
        let api = Api::new(UreqTransport::new(server)?);
        let bundle = self.store.account_bundle()?;
        register_account(
            &api,
            &email,
            password_keys,
            &recovery,
            &bundle,
            &certificate,
        )?;
        self.store
            .set_remote(&lk_sync::normalize_server_url(server)?, &email)?;
        println!("Registered {email} on {server}.");
        self.sync(false)?;
        Ok(())
    }

    fn sync(&mut self, reset: bool) -> Result<SyncReport> {
        let (api, email) = self.remote_required()?;
        let session = self.full_session(&api, &email)?;
        let mut total = SyncReport::default();
        if reset {
            println!("Full resynchronization: every item of this device is uploaded again.");
        }
        for wrapped in self.store.wrapped_vault_keys()? {
            let vault = self.keys.open_vault_key(&wrapped)?;
            let r = if reset {
                resync_vault(&api, &session, &mut self.store, &vault, &wrapped, now())?
            } else {
                sync_vault(&api, &session, &mut self.store, &vault, &wrapped, now())?
            };
            total.pulled = total.pulled.saturating_add(r.pulled);
            total.pushed = total.pushed.saturating_add(r.pushed);
            total.conflicts = total.conflicts.saturating_add(r.conflicts);
            total.conflict_copies.extend(r.conflict_copies);
        }
        let _ = api.logout(&session);
        println!(
            "Synchronized: {} received, {} sent, {} conflict(s){}",
            total.pulled,
            total.pushed,
            total.conflicts,
            if total.conflict_copies.is_empty() {
                String::new()
            } else {
                format!(
                    " — {} conflict copy(ies) created, nothing was lost",
                    total.conflict_copies.len()
                )
            }
        );
        Ok(total)
    }

    fn devices(&self) -> Result<()> {
        let (api, email) = self.remote_required()?;
        let session = self.full_session(&api, &email)?;
        let list = api.devices(&session)?;
        let _ = api.logout(&session);
        let certificates: Vec<_> = list.devices.iter().map(|d| d.certificate.clone()).collect();
        let revocations: Vec<_> = list
            .devices
            .iter()
            .filter_map(|d| d.revocation.clone())
            .collect();
        // Fail closed: one forged entry invalidates the whole list.
        let trusted = lk_core::trusted_devices(
            &self.keys.account_id(),
            &self.keys.signing_public_key(),
            &certificates,
            &revocations,
        )
        .map_err(|_| fail("the device list returned by the server failed verification"))?;
        for entry in &list.devices {
            let d = &entry.certificate.device;
            let status = if d.device_id == self.device.device_id() {
                "this device"
            } else if entry.revocation.is_some() {
                "revoked"
            } else if trusted.iter().any(|t| t.device_id == d.device_id) {
                "active"
            } else {
                "untrusted"
            };
            println!(
                "{}  {:<12} {:<20} {:?}, enrolled {}, last seen {}",
                d.device_id.to_string().chars().take(8).collect::<String>(),
                status,
                d.name,
                d.platform,
                utc(d.created_at_unix),
                entry.last_seen_unix.map_or_else(|| "never".to_owned(), utc)
            );
        }
        Ok(())
    }

    fn revoke(&self, reference: &str) -> Result<()> {
        let r = reference.trim().to_lowercase();
        if r.chars().count() < 4 {
            return Err(fail(
                "a device reference needs at least 4 characters of its ID",
            ));
        }
        let (api, email) = self.remote_required()?;
        let session = self.full_session(&api, &email)?;
        let list = api.devices(&session)?;
        let matches: Vec<_> = list
            .devices
            .iter()
            .filter(|d| d.certificate.device.device_id.to_string().starts_with(&r))
            .collect();
        let target = match matches.as_slice() {
            [one] => one.certificate.device.device_id,
            [] => return Err(fail(format!("no device matches {reference}"))),
            _ => {
                return Err(fail(format!(
                    "several devices match {reference}; give more characters"
                )));
            }
        };
        if target == self.device.device_id() {
            return Err(fail("this is the current device; it cannot revoke itself"));
        }
        let revocation = self.keys.revoke_device(target, now())?;
        api.revoke(&session, &revocation)?;
        let _ = api.logout(&session);
        println!("Device {target} revoked. It can no longer reach the server.");
        eprintln!(
            "Note: data that device already decrypted cannot be erased remotely; \
             key rotation after revocation arrives in a later version."
        );
        Ok(())
    }

    fn decrypted_items(&self) -> Result<Vec<(StoredItem, ItemData)>> {
        let mut out = Vec::new();
        for stored in self.store.items(&self.vault.vault_id())? {
            let data = codec::open(&self.vault, &stored.item)?;
            out.push((stored, data));
        }
        Ok(out)
    }

    fn resolve(&self, reference: &str) -> Result<(StoredItem, ItemData)> {
        let r = reference.trim().to_lowercase();
        if r.chars().count() < 4 {
            return Err(fail(
                "an item reference needs at least 4 characters of its ID",
            ));
        }
        let mut matches: Vec<StoredItem> = self
            .store
            .items(&self.vault.vault_id())?
            .into_iter()
            .filter(|s| s.item.item_id.to_string().starts_with(&r))
            .collect();
        match matches.len() {
            0 => Err(fail(format!("no item matches {reference}"))),
            1 => {
                let stored = matches.remove(0);
                let data = codec::open(&self.vault, &stored.item)?;
                Ok((stored, data))
            }
            n => Err(fail(format!(
                "{n} items match {reference}; give more characters"
            ))),
        }
    }

    fn save_new(&mut self, data: &ItemData) -> Result<()> {
        let sealed = codec::seal_new(&self.vault, data)?;
        self.store.upsert_item(&sealed, now())?;
        println!("Added {}  {}", short_id(&sealed.item_id), data.title);
        Ok(())
    }

    fn info(&self, path: &Path) -> Result<()> {
        let bundle = self.store.account_bundle()?;
        let params = bundle.kdf.params()?;
        println!("Vault file:     {}", path.display());
        println!("Account:        {}", self.keys.account_id());
        if let Some(cert) = self.store.device_certificate()? {
            println!(
                "Device:         {} ({}, {:?}, enrolled {})",
                cert.device.device_id,
                cert.device.name,
                cert.device.platform,
                utc(cert.device.created_at_unix)
            );
        }
        println!(
            "Key derivation: Argon2id, {} MiB, {} passes, {} lanes",
            params.memory_kib / 1024,
            params.iterations,
            params.parallelism
        );
        println!(
            "Recovery key:   {}",
            if bundle.account_key_by_recovery.is_some() {
                "configured"
            } else {
                "none"
            }
        );
        println!(
            "Items:          {}",
            self.store.items(&self.vault.vault_id())?.len()
        );
        println!(
            "Pending sync:   {} local changes (sync arrives in M3)",
            self.store.pending_changes()?.len()
        );
        println!(
            "Local protection: software — keys encrypted with the master password; no platform key store yet (M7)"
        );
        Ok(())
    }

    fn add(&mut self, add: &AddCommand, input: &mut SecretInput) -> Result<()> {
        let now = now();
        let data = match add {
            AddCommand::Login {
                title,
                username,
                urls,
                generate,
                length,
                totp,
                notes,
            } => {
                let password = if *generate {
                    Some(simple_password(*length)?)
                } else {
                    optional_secret(input, "Password (empty for none): ")?
                };
                let totp = if *totp {
                    Some(normalize_totp(
                        &input.read("TOTP secret or otpauth URI: ")?,
                    )?)
                } else {
                    None
                };
                let urls = urls
                    .iter()
                    .map(|u| normalize_url(u))
                    .collect::<lk_vault::Result<Vec<_>>>()?;
                let mut item = ItemData::new(
                    title,
                    ItemContent::Login(Login {
                        username: username.clone(),
                        password,
                        urls,
                        totp,
                        backup_codes: Vec::new(),
                    }),
                    now,
                )?;
                if *notes {
                    item.notes = optional_secret(input, "Notes: ")?;
                }
                item.validate()?;
                item
            }
            AddCommand::Note { title } => {
                let mut item = ItemData::new(title, ItemContent::SecureNote(SecureNote {}), now)?;
                item.notes = optional_secret(input, "Note: ")?;
                item.validate()?;
                item
            }
            AddCommand::Card {
                title,
                cardholder,
                expiry,
            } => {
                let number: String = input
                    .read("Card number: ")?
                    .chars()
                    .filter(|c| !c.is_whitespace() && *c != '-')
                    .collect();
                if !lk_vault::item::luhn_valid(&number) {
                    eprintln!("warning: the card number fails the Luhn check; saved anyway");
                }
                let (expiry_month, expiry_year) = match expiry {
                    Some(e) => parse_expiry(e)?,
                    None => (None, None),
                };
                ItemData::new(
                    title,
                    ItemContent::PaymentCard(PaymentCard {
                        cardholder_name: cardholder.clone(),
                        number: Some(SecretString::new(number)),
                        expiry_month,
                        expiry_year,
                        security_code: optional_secret(input, "Security code (empty for none): ")?,
                        ..PaymentCard::default()
                    }),
                    now,
                )?
            }
        };
        self.save_new(&data)
    }

    fn list(&self, query: Option<&str>) -> Result<()> {
        let mut rows: Vec<(StoredItem, ItemData)> = self
            .decrypted_items()?
            .into_iter()
            .filter(|(_, d)| d.matches(query.unwrap_or("")))
            .collect();
        rows.sort_by_key(|(_, d)| d.title.to_lowercase());
        for (stored, data) in &rows {
            let detail = match &data.content {
                ItemContent::Login(l) => l.username.clone().unwrap_or_default(),
                ItemContent::PaymentCard(c) => c.cardholder_name.clone().unwrap_or_default(),
                _ => String::new(),
            };
            println!(
                "{}  {:<12} {}{}",
                short_id(&stored.item.item_id),
                kind_name(data.kind()),
                data.title,
                if detail.is_empty() {
                    String::new()
                } else {
                    format!("  ({detail})")
                }
            );
        }
        if rows.is_empty() {
            eprintln!("No items.");
        }
        Ok(())
    }

    fn show(&self, reference: &str, reveal: bool) -> Result<()> {
        let (stored, data) = self.resolve(reference)?;
        let secret = |s: &SecretString| {
            if reveal {
                s.expose().to_owned()
            } else {
                "•••••••• (use --reveal)".to_owned()
            }
        };
        println!("ID:        {}", stored.item.item_id);
        println!("Type:      {}", kind_name(data.kind()));
        println!("Title:     {}", data.title);
        if data.favorite {
            println!("Favorite:  yes");
        }
        if let Some(folder) = &data.folder {
            println!("Folder:    {folder}");
        }
        if !data.tags.is_empty() {
            println!("Tags:      {}", data.tags.join(", "));
        }
        match &data.content {
            ItemContent::Login(l) => {
                if let Some(u) = &l.username {
                    println!("Username:  {u}");
                }
                if let Some(p) = &l.password {
                    println!("Password:  {}", secret(p));
                }
                for url in &l.urls {
                    println!("URL:       {url}");
                }
                if l.totp.is_some() {
                    println!(
                        "TOTP:      configured (`lk totp {}`)",
                        short_id(&stored.item.item_id)
                    );
                }
                if !l.backup_codes.is_empty() {
                    println!("Backup codes: {}", l.backup_codes.len());
                }
            }
            ItemContent::PaymentCard(c) => {
                if let Some(name) = &c.cardholder_name {
                    println!("Cardholder: {name}");
                }
                if let Some(n) = &c.number {
                    let last4: String = n
                        .expose()
                        .chars()
                        .rev()
                        .take(4)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    println!(
                        "Number:    {}",
                        if reveal {
                            n.expose().to_owned()
                        } else {
                            format!("•••• {last4}")
                        }
                    );
                }
                if let (Some(m), Some(y)) = (c.expiry_month, c.expiry_year) {
                    println!("Expiry:    {m:02}/{y}");
                }
                if let Some(code) = &c.security_code {
                    println!("Security code: {}", secret(code));
                }
            }
            ItemContent::SecureNote(_) | ItemContent::Identity(_) => {}
        }
        if let Some(notes) = &data.notes {
            println!("Notes:     {}", secret(notes));
        }
        for field in &data.custom_fields {
            println!("{}: {}", field.name, secret(&field.value));
        }
        if !data.password_history.is_empty() {
            println!(
                "History:   {} previous password(s)",
                data.password_history.len()
            );
        }
        println!("Created:   {}", utc(data.created_at));
        println!("Modified:  {}", utc(data.updated_at));
        Ok(())
    }

    fn edit(&mut self, args: &EditArgs, input: &mut SecretInput) -> Result<()> {
        let (stored, mut data) = self.resolve(&args.item)?;
        let now = now().max(data.updated_at);
        if let Some(title) = &args.title {
            data.title = title.trim().to_owned();
        }
        if let Some(favorite) = args.favorite {
            data.favorite = favorite;
        }
        if args.username.is_some() || !args.add_urls.is_empty() {
            let ItemContent::Login(login) = &mut data.content else {
                return Err(fail("--username and --add-url apply to logins only"));
            };
            if let Some(u) = &args.username {
                login.username = Some(u.clone()).filter(|u| !u.is_empty());
            }
            for url in &args.add_urls {
                let url = normalize_url(url)?;
                if !login.urls.contains(&url) {
                    login.urls.push(url);
                }
            }
        }
        if args.password {
            let new = input.read_confirmed("New password: ", "Repeat the new password: ")?;
            data.change_password(SecretString::new(new.as_str()), now)?;
        } else if args.generate {
            data.change_password(simple_password(args.length)?, now)?;
        }
        if let Some(index) = args.restore_password {
            data.restore_password(
                index
                    .checked_sub(1)
                    .ok_or_else(|| fail("history entries start at 1"))?,
                now,
            )?;
        }
        if let Some(index) = args.delete_history {
            data.delete_history_entry(
                index
                    .checked_sub(1)
                    .ok_or_else(|| fail("history entries start at 1"))?,
                now,
            )?;
        }
        data.updated_at = now;
        let sealed = codec::seal_update(&self.vault, &stored.item, &data)?;
        let revision = self.store.upsert_item(&sealed, now)?;
        println!(
            "Updated {}  {} (revision {revision})",
            short_id(&sealed.item_id),
            data.title
        );
        Ok(())
    }

    fn delete(&mut self, reference: &str) -> Result<()> {
        let (stored, data) = self.resolve(reference)?;
        self.store.delete_item(&stored.item.item_id, now())?;
        println!("Deleted {}  {}", short_id(&stored.item.item_id), data.title);
        Ok(())
    }

    fn history(&self, reference: &str, reveal: bool) -> Result<()> {
        let (_, data) = self.resolve(reference)?;
        if data.kind() != ItemKind::Login {
            return Err(fail("only logins have a password history"));
        }
        if data.password_history.is_empty() {
            eprintln!("No previous passwords.");
        }
        for (i, entry) in data.password_history.iter().enumerate() {
            let value = if reveal {
                entry.password.expose().to_owned()
            } else {
                "••••••••".to_owned()
            };
            println!(
                "{:>2}. replaced {}  {value}",
                i.saturating_add(1),
                utc(entry.replaced_at)
            );
        }
        Ok(())
    }

    fn totp(&self, reference: &str) -> Result<()> {
        let (_, data) = self.resolve(reference)?;
        let ItemContent::Login(Login {
            totp: Some(uri), ..
        }) = &data.content
        else {
            return Err(fail("this item has no TOTP configuration"));
        };
        let totp = Totp::from_uri(uri.expose())?;
        let now = now();
        let code = totp.code_at(now)?;
        println!("{}", code.as_str());
        eprintln!("valid for {} s", totp.seconds_remaining(now));
        Ok(())
    }

    /// Changes (or, unlocked with the recovery key, resets) the master
    /// password. When registered, the server credential is replaced first:
    /// if that fails, nothing changes locally.
    fn passwd(&mut self, input: &mut SecretInput) -> Result<()> {
        let new = read_new_master_password(input)?;
        let bundle = self.store.account_bundle()?;
        eprintln!("Deriving keys (Argon2id)...");
        let (updated, new_auth) =
            self.keys
                .change_password(&bundle, &new, KdfParams::recommended())?;
        if let Some((api, email)) = self.remote()? {
            let session = match &self.recovery_key {
                Some(rk) => api.login(
                    &email,
                    &rk.server_auth_key().map_err(lk_core::CoreError::from)?,
                    CredentialKind::Recovery,
                    self.device.device_id(),
                )?,
                None => self.full_session(&api, &email)?,
            };
            api.replace_credential(&session, CredentialKind::Password, &new_auth, &updated)?;
            if self.recovery_key.is_none() {
                let _ = api.logout(&session);
            }
        }
        self.store.replace_account_bundle(&updated, now())?;
        println!("Master password changed. Your recovery key is unchanged.");
        Ok(())
    }

    fn rotate_recovery(&mut self) -> Result<()> {
        let bundle = self.store.account_bundle()?;
        let (updated, recovery_key, new_auth) = self.keys.rotate_recovery_key(&bundle)?;
        if let Some((api, email)) = self.remote()? {
            let session = self.full_session(&api, &email)?;
            api.replace_credential(&session, CredentialKind::Recovery, &new_auth, &updated)?;
            let _ = api.logout(&session);
        }
        self.store.replace_account_bundle(&updated, now())?;
        println!("Recovery key replaced. The previous one no longer works.");
        print_recovery_key(&recovery_key)
    }
}

fn parse_expiry(text: &str) -> Result<(Option<u8>, Option<u16>)> {
    let (m, y) = text
        .split_once('/')
        .ok_or_else(|| fail("expiry must be MM/YYYY"))?;
    let month: u8 = m
        .trim()
        .parse()
        .map_err(|_| fail("expiry must be MM/YYYY"))?;
    let year: u16 = y
        .trim()
        .parse()
        .map_err(|_| fail("expiry must be MM/YYYY"))?;
    Ok((Some(month), Some(year)))
}

const fn kind_name(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "login",
        ItemKind::SecureNote => "note",
        ItemKind::PaymentCard => "card",
        ItemKind::Identity => "identity",
    }
}
