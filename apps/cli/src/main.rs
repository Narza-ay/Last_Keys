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
use lk_client::{Credential, DeviceStatus, MasterPassword, Platform, RecoveryKey, Vault};
use lk_generator::{PassphrasePolicy, PasswordPolicy, generate_passphrase, generate_password};
use lk_vault::{
    ItemContent, ItemData, ItemKind, Login, PaymentCard, SecretString, SecureNote, normalize_totp,
    normalize_url,
};

use crate::error::{Result, fail};
use crate::format::{short_id, utc};
use crate::input::SecretInput;

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
                Command::Info => session.info(),
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
                Command::Sync { reset } => session.sync(*reset),
                Command::Devices => session.devices(),
                Command::Revoke { device } => session.revoke(device),
                Command::Generate(_) | Command::Init { .. } | Command::Login { .. } => Ok(()),
            }
        }
    }
}

fn read_new_master_password(input: &mut SecretInput) -> Result<MasterPassword> {
    let pw = input.read_confirmed("New master password: ", "Repeat the master password: ")?;
    Ok(lk_client::new_master_password(&pw, &pw)?)
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

fn print_sync(summary: &lk_client::SyncSummary) {
    println!(
        "Synchronized: {} received, {} sent, {} conflict(s){}",
        summary.received,
        summary.sent,
        summary.conflicts,
        if summary.conflict_copies == 0 {
            String::new()
        } else {
            format!(
                " — {} conflict copy(ies) created, nothing was lost",
                summary.conflict_copies
            )
        }
    );
}

fn init(path: &Path, input: &mut SecretInput, device_name: &str) -> Result<()> {
    if path.exists() {
        return Err(lk_client::ClientError::VaultExists(path.to_path_buf()).into());
    }
    let password = read_new_master_password(input)?;
    eprintln!("Deriving keys (Argon2id)...");
    let created = Vault::create(path, &password, device_name, Platform::Cli, now())?;
    let info = created.vault.info()?;
    println!("Vault created: {}", path.display());
    println!("Account: {}", info.account_id);
    println!("Device:  {}", info.device_id);
    print_recovery_key(&created.recovery_key)
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
        return Err(lk_client::ClientError::VaultExists(path.to_path_buf()).into());
    }
    let password = MasterPassword::new(&input.read("Master password: ")?)?;
    eprintln!("Deriving keys (Argon2id)...");
    let enrolled = Vault::enroll(
        path,
        server,
        email,
        &password,
        device_name,
        Platform::Cli,
        now(),
    )?;
    let info = enrolled.vault.info()?;
    let remote = info.remote.as_ref().map_or("", |r| r.email.as_str());
    println!(
        "Device {} enrolled on {server} as {remote}.",
        info.device_id
    );
    println!(
        "Vault created: {} ({} item(s) received)",
        path.display(),
        enrolled.received
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

/// An unlocked vault (the application logic lives in `lk-client`).
struct Session {
    vault: Vault,
}

impl Session {
    fn open(path: &Path, input: &mut SecretInput, use_recovery_key: bool) -> Result<Self> {
        if !path.exists() {
            return Err(lk_client::ClientError::NoVault(path.to_path_buf()).into());
        }
        let vault = if use_recovery_key {
            let rk = RecoveryKey::parse(&input.read("Recovery key: ")?)?;
            Vault::unlock(path, &Credential::RecoveryKey(&rk))?
        } else {
            let pw = MasterPassword::new(&input.read("Master password: ")?)?;
            Vault::unlock(path, &Credential::MasterPassword(&pw))?
        };
        Ok(Self { vault })
    }

    fn register(&mut self, input: &mut SecretInput, server: &str, email: &str) -> Result<()> {
        if self.vault.remote_view()?.is_some() {
            return Err(lk_client::ClientError::AlreadyRegistered.into());
        }
        let recovery = RecoveryKey::parse(
            &input.read("Recovery key (to register the recovery credential): ")?,
        )?;
        let summary = self.vault.register(server, email, &recovery, now())?;
        let email = self
            .vault
            .remote_view()?
            .map_or_else(String::new, |r| r.email);
        println!("Registered {email} on {server}.");
        print_sync(&summary);
        Ok(())
    }

    fn sync(&mut self, reset: bool) -> Result<()> {
        if reset {
            println!("Full resynchronization: every item of this device is uploaded again.");
        }
        let summary = self.vault.sync(reset, now())?;
        print_sync(&summary);
        Ok(())
    }

    fn devices(&self) -> Result<()> {
        for d in self.vault.devices()? {
            let status = match d.status {
                DeviceStatus::ThisDevice => "this device",
                DeviceStatus::Active => "active",
                DeviceStatus::Revoked => "revoked",
            };
            println!(
                "{}  {:<12} {:<20} {:?}, enrolled {}, last seen {}",
                d.id.to_string().chars().take(8).collect::<String>(),
                status,
                d.name,
                d.platform,
                utc(d.enrolled_at),
                d.last_seen.map_or_else(|| "never".to_owned(), utc)
            );
        }
        Ok(())
    }

    fn revoke(&self, reference: &str) -> Result<()> {
        let target = self.vault.find_device(reference)?;
        self.vault.revoke_device(target, now())?;
        println!("Device {target} revoked. It can no longer reach the server.");
        eprintln!(
            "Note: data that device already decrypted cannot be erased remotely; \
             key rotation after revocation arrives in a later version."
        );
        Ok(())
    }

    fn resolve(&self, reference: &str) -> Result<(lk_client::ItemId, ItemData)> {
        let id = self.vault.find(reference)?;
        Ok((id, self.vault.item(&id)?))
    }

    fn info(&self) -> Result<()> {
        let info = self.vault.info()?;
        println!("Vault file:     {}", self.vault.path().display());
        println!("Account:        {}", info.account_id);
        println!(
            "Device:         {} ({}, {:?}, enrolled {})",
            info.device_id,
            info.device_name,
            info.platform,
            utc(info.enrolled_at)
        );
        println!(
            "Key derivation: Argon2id, {} MiB, {} passes, {} lanes",
            info.kdf.memory_kib / 1024,
            info.kdf.iterations,
            info.kdf.parallelism
        );
        println!(
            "Recovery key:   {}",
            if info.recovery_key_configured {
                "configured"
            } else {
                "none"
            }
        );
        println!("Items:          {}", info.items);
        match &info.remote {
            Some(r) => println!("Server:         {} ({})", r.server, r.email),
            None => println!("Server:         not registered"),
        }
        println!("Pending sync:   {} local change(s)", info.pending_changes);
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
                item
            }
            AddCommand::Note { title } => {
                let mut item = ItemData::new(title, ItemContent::SecureNote(SecureNote {}), now)?;
                item.notes = optional_secret(input, "Note: ")?;
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
        let id = self.vault.create_item(&data, now)?;
        println!("Added {}  {}", short_id(&id), data.title);
        Ok(())
    }

    fn list(&self, query: Option<&str>) -> Result<()> {
        let rows = self.vault.items(query.unwrap_or(""))?;
        for row in &rows {
            println!(
                "{}  {:<12} {}{}",
                short_id(&row.id),
                kind_name(row.kind),
                row.title,
                row.subtitle
                    .as_ref()
                    .map_or_else(String::new, |s| format!("  ({s})"))
            );
        }
        if rows.is_empty() {
            eprintln!("No items.");
        }
        Ok(())
    }

    fn show(&self, reference: &str, reveal: bool) -> Result<()> {
        let (id, data) = self.resolve(reference)?;
        let secret = |s: &SecretString| {
            if reveal {
                s.expose().to_owned()
            } else {
                "•••••••• (use --reveal)".to_owned()
            }
        };
        println!("ID:        {id}");
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
                    println!("TOTP:      configured (`lk totp {}`)", short_id(&id));
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
        let id = self.vault.find(&args.item)?;
        // Read every secret before modifying the item.
        let new_password = if args.password {
            let new = input.read_confirmed("New password: ", "Repeat the new password: ")?;
            Some(SecretString::new(new.as_str()))
        } else if args.generate {
            Some(simple_password(args.length)?)
        } else {
            None
        };
        let revision = self.vault.update_item(&id, now(), |data| {
            let now = now().max(data.updated_at);
            if let Some(title) = &args.title {
                data.title = title.trim().to_owned();
            }
            if let Some(favorite) = args.favorite {
                data.favorite = favorite;
            }
            if args.username.is_some() || !args.add_urls.is_empty() {
                let ItemContent::Login(login) = &mut data.content else {
                    return Err(lk_client::ClientError::InvalidDraft(
                        "--username and --add-url apply to logins only",
                    ));
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
            if let Some(password) = new_password {
                data.change_password(password, now)?;
            }
            if let Some(index) = args.restore_password {
                let index = index
                    .checked_sub(1)
                    .ok_or(lk_client::ClientError::InvalidDraft(
                        "history entries start at 1",
                    ))?;
                data.restore_password(index, now)?;
            }
            if let Some(index) = args.delete_history {
                let index = index
                    .checked_sub(1)
                    .ok_or(lk_client::ClientError::InvalidDraft(
                        "history entries start at 1",
                    ))?;
                data.delete_history_entry(index, now)?;
            }
            Ok(())
        })?;
        let title = self.vault.item(&id)?.title;
        println!("Updated {}  {title} (revision {revision})", short_id(&id));
        Ok(())
    }

    fn delete(&mut self, reference: &str) -> Result<()> {
        let (id, data) = self.resolve(reference)?;
        self.vault.delete_item(&id, now())?;
        println!("Deleted {}  {}", short_id(&id), data.title);
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
        let id = self.vault.find(reference)?;
        let code = self.vault.totp(&id, now())?;
        println!("{}", code.code);
        eprintln!("valid for {} s", code.remaining);
        Ok(())
    }

    /// Changes (or, unlocked with the recovery key, resets) the master
    /// password. When registered, the server credential is replaced first:
    /// if that fails, nothing changes locally.
    fn passwd(&mut self, input: &mut SecretInput) -> Result<()> {
        let new = read_new_master_password(input)?;
        eprintln!("Deriving keys (Argon2id)...");
        self.vault.change_master_password(&new, now())?;
        println!("Master password changed. Your recovery key is unchanged.");
        Ok(())
    }

    fn rotate_recovery(&mut self) -> Result<()> {
        let recovery_key = self.vault.rotate_recovery_key(now())?;
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
