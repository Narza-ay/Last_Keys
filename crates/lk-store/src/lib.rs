//! # lk-store
//!
//! Local encrypted store of a Last Keys device, backed by SQLite (bundled,
//! identical on every platform).
//!
//! The store only ever holds what `lk-core` produced: the encrypted account
//! bundle, the encrypted device identity, wrapped vault keys and encrypted
//! items. It never sees a key or a plaintext. Identifiers, revisions and
//! timestamps are stored in clear to allow indexing and synchronization
//! (see `docs/PRIVACY.md`).
//!
//! Durability and safety settings: WAL journal with `synchronous = FULL`,
//! foreign keys enforced, `secure_delete` on, temporary data in memory, every
//! mutation in a transaction, database files created with owner-only
//! permissions on Unix.
//!
//! Every local mutation also appends an entry to the offline change queue,
//! consumed by the synchronization engine (milestone M3).

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::path::Path;

use lk_core::{
    AccountKeyBundle, ChangeId, DeviceCertificate, EncryptedItem, ItemId, SealedDeviceIdentity,
    VaultId, WrappedVaultKey,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use thiserror::Error;

/// Database schema version written by this build.
pub const SCHEMA_VERSION: i64 = 2;

/// Forward-only migrations; entry `i` upgrades version `i` to `i + 1`.
const MIGRATIONS: &[&str] = &[
    r"
CREATE TABLE account (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    account_id  TEXT    NOT NULL,
    bundle      TEXT    NOT NULL,
    updated_at  INTEGER NOT NULL
);
CREATE TABLE device (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    device_id        TEXT    NOT NULL,
    sealed_identity  TEXT    NOT NULL,
    certificate      TEXT
);
CREATE TABLE vault_keys (
    vault_id  TEXT PRIMARY KEY,
    wrapped   TEXT NOT NULL
);
CREATE TABLE items (
    item_id     TEXT    PRIMARY KEY,
    vault_id    TEXT    NOT NULL REFERENCES vault_keys (vault_id),
    revision    INTEGER NOT NULL CHECK (revision > 0),
    deleted     INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    encrypted   TEXT,
    updated_at  INTEGER NOT NULL,
    CHECK ((deleted = 0 AND encrypted IS NOT NULL) OR (deleted = 1 AND encrypted IS NULL))
);
CREATE INDEX items_by_vault ON items (vault_id, deleted);
CREATE TABLE pending_changes (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    change_id   TEXT    NOT NULL UNIQUE,
    item_id     TEXT    NOT NULL,
    vault_id    TEXT    NOT NULL,
    revision    INTEGER NOT NULL,
    kind        TEXT    NOT NULL CHECK (kind IN ('upsert', 'delete')),
    created_at  INTEGER NOT NULL
);
",
    r"
-- v2: synchronization state (ADR-0008).
ALTER TABLE items ADD COLUMN server_revision INTEGER NOT NULL DEFAULT 0 CHECK (server_revision >= 0);
CREATE TABLE sync_state (
    vault_id  TEXT    PRIMARY KEY,
    cursor    INTEGER NOT NULL CHECK (cursor >= 0)
);
CREATE TABLE remote (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    server_url  TEXT NOT NULL,
    email       TEXT NOT NULL
);
",
];

/// Errors returned by `lk-store`. Messages never contain vault data (only
/// ciphertext ever reaches this layer).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// SQLite reported an error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    /// File-system error.
    #[error("file error: {0}")]
    Io(#[from] std::io::Error),
    /// A stored record could not be (de)serialized.
    #[error("stored record is malformed")]
    Serialization(#[from] serde_json::Error),
    /// [`Store::create`] was called on an existing file.
    #[error("a store already exists at this location")]
    AlreadyExists,
    /// The database was written by a newer version of Last Keys.
    #[error("store schema version {0} is newer than this version supports")]
    SchemaTooNew(i64),
    /// The store is incomplete or inconsistent.
    #[error("store is corrupted: {0}")]
    Corrupted(&'static str),
    /// The requested item does not exist (or is deleted).
    #[error("no such item")]
    NotFound,
    /// An object belongs to another account or vault than expected.
    #[error("object does not belong to this {0}")]
    Mismatch(&'static str),
    /// Identifier generation failed (OS RNG).
    #[error(transparent)]
    Core(#[from] lk_core::CoreError),
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, StoreError>;

/// An encrypted item with its local metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredItem {
    /// The encrypted item.
    pub item: EncryptedItem,
    /// Local revision (incremented by every local change).
    pub revision: u64,
    /// Last local modification time (Unix seconds).
    pub updated_at: u64,
}

/// Kind of a queued local change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// Item created or modified.
    Upsert,
    /// Item deleted (tombstone).
    Delete,
}

/// A local change waiting to be synchronized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingChange {
    /// Queue position.
    pub seq: u64,
    /// Unique change identifier (idempotency key for synchronization).
    pub change_id: ChangeId,
    /// Item concerned.
    pub item_id: ItemId,
    /// Vault of the item.
    pub vault_id: VaultId,
    /// Item revision produced by this change.
    pub revision: u64,
    /// Change kind.
    pub kind: ChangeKind,
    /// Creation time (Unix seconds).
    pub created_at: u64,
}

/// The local store of one device.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

fn to_i64(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| StoreError::Corrupted("value out of range"))
}

fn to_u64(v: i64) -> Result<u64> {
    u64::try_from(v).map_err(|_| StoreError::Corrupted("negative value"))
}

fn parse_id<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    Ok(serde_json::from_value(serde_json::Value::String(
        s.to_owned(),
    ))?)
}

impl Store {
    /// Creates a new store for a freshly created or enrolled account.
    /// Refuses to overwrite an existing file.
    ///
    /// # Errors
    /// [`StoreError::AlreadyExists`] if `path` exists; database or file errors.
    pub fn create(
        path: &Path,
        bundle: &AccountKeyBundle,
        device: &SealedDeviceIdentity,
        certificate: Option<&DeviceCertificate>,
        now_unix: u64,
    ) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StoreError::AlreadyExists);
            }
            Err(e) => return Err(e.into()),
        }
        let mut store = Self::connect(path)?;
        let tx = store.conn.transaction()?;
        tx.execute(
            "INSERT INTO account (id, account_id, bundle, updated_at) VALUES (1, ?1, ?2, ?3)",
            params![
                bundle.account_id.to_string(),
                serde_json::to_string(bundle)?,
                to_i64(now_unix)?
            ],
        )?;
        tx.execute(
            "INSERT INTO device (id, device_id, sealed_identity, certificate) VALUES (1, ?1, ?2, ?3)",
            params![
                device.device_id.to_string(),
                serde_json::to_string(device)?,
                certificate.map(serde_json::to_string).transpose()?
            ],
        )?;
        tx.commit()?;
        Ok(store)
    }

    /// Opens an existing store, applying pending migrations.
    ///
    /// # Errors
    /// [`StoreError::SchemaTooNew`] if written by a newer version;
    /// [`StoreError::Corrupted`] if the account or device record is missing.
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "store file not found",
            )));
        }
        let store = Self::connect(path)?;
        store.account_bundle()?;
        store.sealed_device()?;
        Ok(store)
    }

    fn connect(path: &Path) -> Result<Self> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut conn = Connection::open_with_flags(path, flags)?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Corrupted("WAL journal mode unavailable"));
        }
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        Self::migrate(&mut conn)?;
        Ok(Self { conn })
    }

    fn migrate(conn: &mut Connection) -> Result<()> {
        let current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if current > SCHEMA_VERSION {
            return Err(StoreError::SchemaTooNew(current));
        }
        let start =
            usize::try_from(current).map_err(|_| StoreError::Corrupted("schema version"))?;
        for (index, sql) in MIGRATIONS.iter().enumerate().skip(start) {
            let tx = conn.transaction()?;
            tx.execute_batch(sql)?;
            let next = i64::try_from(index)
                .ok()
                .and_then(|i| i.checked_add(1))
                .ok_or(StoreError::Corrupted("schema version"))?;
            tx.pragma_update(None, "user_version", next)?;
            tx.commit()?;
        }
        Ok(())
    }

    /// The encrypted account bundle.
    ///
    /// # Errors
    /// [`StoreError::Corrupted`] if missing.
    pub fn account_bundle(&self) -> Result<AccountKeyBundle> {
        let (account_id, json): (String, String) = self
            .conn
            .query_row(
                "SELECT account_id, bundle FROM account WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::Corrupted("account record missing"))?;
        let bundle: AccountKeyBundle = serde_json::from_str(&json)?;
        if bundle.account_id.to_string() != account_id {
            return Err(StoreError::Corrupted("account id mismatch"));
        }
        Ok(bundle)
    }

    /// Replaces the account bundle (after a password change or a recovery-key
    /// rotation). The account identifier must not change.
    ///
    /// # Errors
    /// [`StoreError::Mismatch`] for a bundle of another account.
    pub fn replace_account_bundle(
        &mut self,
        bundle: &AccountKeyBundle,
        now_unix: u64,
    ) -> Result<()> {
        let current = self.account_bundle()?;
        if current.account_id != bundle.account_id {
            return Err(StoreError::Mismatch("account"));
        }
        self.conn.execute(
            "UPDATE account SET bundle = ?1, updated_at = ?2 WHERE id = 1",
            params![serde_json::to_string(bundle)?, to_i64(now_unix)?],
        )?;
        Ok(())
    }

    /// The encrypted identity of this device.
    ///
    /// # Errors
    /// [`StoreError::Corrupted`] if missing.
    pub fn sealed_device(&self) -> Result<SealedDeviceIdentity> {
        let (device_id, json): (String, String) = self
            .conn
            .query_row(
                "SELECT device_id, sealed_identity FROM device WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::Corrupted("device record missing"))?;
        let sealed: SealedDeviceIdentity = serde_json::from_str(&json)?;
        if sealed.device_id.to_string() != device_id {
            return Err(StoreError::Corrupted("device id mismatch"));
        }
        Ok(sealed)
    }

    /// The account certificate of this device, if stored.
    ///
    /// # Errors
    /// Database or serialization errors.
    pub fn device_certificate(&self) -> Result<Option<DeviceCertificate>> {
        let json: Option<String> =
            self.conn
                .query_row("SELECT certificate FROM device WHERE id = 1", [], |r| {
                    r.get(0)
                })?;
        json.map(|j| serde_json::from_str(&j).map_err(StoreError::from))
            .transpose()
    }

    /// Stores (or replaces) a wrapped vault key.
    ///
    /// # Errors
    /// [`StoreError::Mismatch`] if it belongs to another account.
    pub fn put_wrapped_vault_key(&mut self, wrapped: &WrappedVaultKey) -> Result<()> {
        if wrapped.account_id != self.account_bundle()?.account_id {
            return Err(StoreError::Mismatch("account"));
        }
        self.conn.execute(
            "INSERT INTO vault_keys (vault_id, wrapped) VALUES (?1, ?2)
             ON CONFLICT (vault_id) DO UPDATE SET wrapped = excluded.wrapped",
            params![
                wrapped.vault_id.to_string(),
                serde_json::to_string(wrapped)?
            ],
        )?;
        Ok(())
    }

    /// Every wrapped vault key of the account.
    ///
    /// # Errors
    /// Database or serialization errors.
    pub fn wrapped_vault_keys(&self) -> Result<Vec<WrappedVaultKey>> {
        let mut stmt = self
            .conn
            .prepare("SELECT vault_id, wrapped FROM vault_keys ORDER BY vault_id")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (vault_id, json) = row?;
            let wrapped: WrappedVaultKey = serde_json::from_str(&json)?;
            if wrapped.vault_id.to_string() != vault_id {
                return Err(StoreError::Corrupted("vault id mismatch"));
            }
            out.push(wrapped);
        }
        Ok(out)
    }

    /// Inserts or updates an encrypted item and queues the change, atomically.
    /// Returns the new local revision.
    ///
    /// # Errors
    /// Database errors (including an unknown vault: the vault key must be
    /// stored first).
    pub fn upsert_item(&mut self, item: &EncryptedItem, now_unix: u64) -> Result<u64> {
        let json = serde_json::to_string(item)?;
        let tx = self.conn.transaction()?;
        let current = current_revision(&tx, &item.item_id)?;
        if let Some((_, vault_id)) = &current
            && *vault_id != item.vault_id.to_string()
        {
            return Err(StoreError::Mismatch("vault"));
        }
        let revision = current
            .map_or(0, |(r, _)| r)
            .checked_add(1)
            .ok_or(StoreError::Corrupted("revision overflow"))?;
        tx.execute(
            "INSERT INTO items (item_id, vault_id, revision, deleted, encrypted, updated_at)
             VALUES (?1, ?2, ?3, 0, ?4, ?5)
             ON CONFLICT (item_id) DO UPDATE SET
                revision = excluded.revision, deleted = 0,
                encrypted = excluded.encrypted, updated_at = excluded.updated_at",
            params![
                item.item_id.to_string(),
                item.vault_id.to_string(),
                to_i64(revision)?,
                json,
                to_i64(now_unix)?
            ],
        )?;
        queue_change(
            &tx,
            &item.item_id,
            &item.vault_id,
            revision,
            ChangeKind::Upsert,
            now_unix,
        )?;
        tx.commit()?;
        Ok(revision)
    }

    /// Deletes an item: its ciphertext is erased and a tombstone kept (so the
    /// deletion can be synchronized), atomically with queuing the change.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] if the item does not exist or is deleted.
    pub fn delete_item(&mut self, item_id: &ItemId, now_unix: u64) -> Result<()> {
        let tx = self.conn.transaction()?;
        let row: Option<(i64, String, bool)> = tx
            .query_row(
                "SELECT revision, vault_id, deleted FROM items WHERE item_id = ?1",
                params![item_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((revision, vault_id, false)) = row else {
            return Err(StoreError::NotFound);
        };
        let revision = to_u64(revision)?
            .checked_add(1)
            .ok_or(StoreError::Corrupted("revision overflow"))?;
        tx.execute(
            "UPDATE items SET deleted = 1, encrypted = NULL, revision = ?2, updated_at = ?3
             WHERE item_id = ?1",
            params![item_id.to_string(), to_i64(revision)?, to_i64(now_unix)?],
        )?;
        let vault_id: VaultId = parse_id(&vault_id)?;
        queue_change(
            &tx,
            item_id,
            &vault_id,
            revision,
            ChangeKind::Delete,
            now_unix,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// One live (non-deleted) item.
    ///
    /// # Errors
    /// Database errors or a corrupted record.
    pub fn item(&self, item_id: &ItemId) -> Result<Option<StoredItem>> {
        self.conn
            .query_row(
                "SELECT item_id, vault_id, revision, encrypted, updated_at
                 FROM items WHERE item_id = ?1 AND deleted = 0",
                params![item_id.to_string()],
                read_row,
            )
            .optional()?
            .map(decode_row)
            .transpose()
    }

    /// Every live item of a vault.
    ///
    /// # Errors
    /// Database errors or a corrupted record.
    pub fn items(&self, vault_id: &VaultId) -> Result<Vec<StoredItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT item_id, vault_id, revision, encrypted, updated_at
             FROM items WHERE vault_id = ?1 AND deleted = 0 ORDER BY item_id",
        )?;
        let rows = stmt.query_map(params![vault_id.to_string()], read_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(decode_row(row?)?);
        }
        Ok(out)
    }

    /// Changes waiting to be synchronized, oldest first.
    ///
    /// # Errors
    /// Database errors or a corrupted record.
    pub fn pending_changes(&self) -> Result<Vec<PendingChange>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, change_id, item_id, vault_id, revision, kind, created_at
             FROM pending_changes ORDER BY seq",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, change_id, item_id, vault_id, revision, kind, created_at) = row?;
            out.push(PendingChange {
                seq: to_u64(seq)?,
                change_id: parse_id(&change_id)?,
                item_id: parse_id(&item_id)?,
                vault_id: parse_id(&vault_id)?,
                revision: to_u64(revision)?,
                kind: match kind.as_str() {
                    "upsert" => ChangeKind::Upsert,
                    "delete" => ChangeKind::Delete,
                    _ => return Err(StoreError::Corrupted("unknown change kind")),
                },
                created_at: to_u64(created_at)?,
            });
        }
        Ok(out)
    }
}

/// Local view of an item, including deleted ones (for synchronization).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalItem {
    /// Item identifier.
    pub item_id: ItemId,
    /// Vault identifier.
    pub vault_id: VaultId,
    /// Encrypted content; `None` when deleted.
    pub item: Option<EncryptedItem>,
    /// Last server revision this device knows (0 if never synchronized).
    pub server_revision: u64,
}

/// An item state received from the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteState {
    /// Item identifier.
    pub item_id: ItemId,
    /// Server revision.
    pub revision: u64,
    /// Content; `None` for a tombstone.
    pub item: Option<EncryptedItem>,
}

impl Store {
    /// Server binding of this store (URL, account e-mail), if registered.
    ///
    /// # Errors
    /// Database errors.
    pub fn remote(&self) -> Result<Option<(String, String)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT server_url, email FROM remote WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// Records the server binding.
    ///
    /// # Errors
    /// Database errors.
    pub fn set_remote(&mut self, server_url: &str, email: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO remote (id, server_url, email) VALUES (1, ?1, ?2)
             ON CONFLICT (id) DO UPDATE SET server_url = excluded.server_url, email = excluded.email",
            params![server_url, email],
        )?;
        Ok(())
    }

    /// Pull cursor of a vault (0 before the first pull).
    ///
    /// # Errors
    /// Database errors.
    pub fn sync_cursor(&self, vault_id: &VaultId) -> Result<u64> {
        let cursor: Option<i64> = self
            .conn
            .query_row(
                "SELECT cursor FROM sync_state WHERE vault_id = ?1",
                params![vault_id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        cursor.map_or(Ok(0), to_u64)
    }

    /// Advances the pull cursor of a vault. A cursor never moves backwards.
    ///
    /// # Errors
    /// [`StoreError::Corrupted`] if `cursor` is lower than the stored one.
    pub fn set_sync_cursor(&mut self, vault_id: &VaultId, cursor: u64) -> Result<()> {
        if cursor < self.sync_cursor(vault_id)? {
            return Err(StoreError::Corrupted("sync cursor moved backwards"));
        }
        self.conn.execute(
            "INSERT INTO sync_state (vault_id, cursor) VALUES (?1, ?2)
             ON CONFLICT (vault_id) DO UPDATE SET cursor = excluded.cursor",
            params![vault_id.to_string(), to_i64(cursor)?],
        )?;
        Ok(())
    }

    /// An item including tombstones.
    ///
    /// # Errors
    /// Database errors or a corrupted record.
    pub fn local_item(&self, item_id: &ItemId) -> Result<Option<LocalItem>> {
        let row: Option<(String, String, Option<String>, i64)> = self
            .conn
            .query_row(
                "SELECT item_id, vault_id, encrypted, server_revision FROM items WHERE item_id = ?1",
                params![item_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((id, vault, json, server_revision)) = row else {
            return Ok(None);
        };
        let item: Option<EncryptedItem> = json.map(|j| serde_json::from_str(&j)).transpose()?;
        if let Some(i) = &item
            && (i.item_id.to_string() != id || i.vault_id.to_string() != vault)
        {
            return Err(StoreError::Corrupted("item index mismatch"));
        }
        Ok(Some(LocalItem {
            item_id: parse_id(&id)?,
            vault_id: parse_id(&vault)?,
            item,
            server_revision: to_u64(server_revision)?,
        }))
    }

    /// Writes a state received from the server and, in the same
    /// transaction, drops the local changes of that item queued up to
    /// `resolved_up_to_seq` (they are superseded or already applied).
    ///
    /// Refuses a state older than the revision already known for the item
    /// (rollback protection, ADR-0008).
    ///
    /// # Errors
    /// [`StoreError::Corrupted`] on a rollback or mismatched identifiers;
    /// database errors (e.g. unknown vault).
    pub fn apply_remote(
        &mut self,
        vault_id: &VaultId,
        state: &RemoteState,
        resolved_up_to_seq: Option<u64>,
        now_unix: u64,
    ) -> Result<()> {
        if let Some(item) = &state.item
            && (item.item_id != state.item_id || item.vault_id != *vault_id)
        {
            return Err(StoreError::Mismatch("vault"));
        }
        let tx = self.conn.transaction()?;
        let current: Option<(i64, i64, String)> = tx
            .query_row(
                "SELECT revision, server_revision, vault_id FROM items WHERE item_id = ?1",
                params![state.item_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((_, known, vault)) = &current {
            if *vault != vault_id.to_string() {
                return Err(StoreError::Mismatch("vault"));
            }
            if to_u64(*known)? > state.revision {
                return Err(StoreError::Corrupted("server returned an older revision"));
            }
        }
        let local_revision = current
            .as_ref()
            .map_or(0, |(r, _, _)| *r)
            .checked_add(1)
            .ok_or(StoreError::Corrupted("revision overflow"))?;
        let json = state.item.as_ref().map(serde_json::to_string).transpose()?;
        tx.execute(
            "INSERT INTO items (item_id, vault_id, revision, deleted, encrypted, updated_at, server_revision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (item_id) DO UPDATE SET
                revision = excluded.revision, deleted = excluded.deleted, encrypted = excluded.encrypted,
                updated_at = excluded.updated_at, server_revision = excluded.server_revision",
            params![
                state.item_id.to_string(),
                vault_id.to_string(),
                local_revision,
                state.item.is_none(),
                json,
                to_i64(now_unix)?,
                to_i64(state.revision)?
            ],
        )?;
        if let Some(seq) = resolved_up_to_seq {
            tx.execute(
                "DELETE FROM pending_changes WHERE item_id = ?1 AND seq <= ?2",
                params![state.item_id.to_string(), to_i64(seq)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Records that the local changes of an item up to `up_to_seq` were
    /// accepted by the server at `server_revision`.
    ///
    /// # Errors
    /// Database errors.
    pub fn mark_pushed(
        &mut self,
        item_id: &ItemId,
        server_revision: u64,
        up_to_seq: u64,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE items SET server_revision = ?2 WHERE item_id = ?1",
            params![item_id.to_string(), to_i64(server_revision)?],
        )?;
        tx.execute(
            "DELETE FROM pending_changes WHERE item_id = ?1 AND seq <= ?2",
            params![item_id.to_string(), to_i64(up_to_seq)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Forgets the known server revision of an item (the server no longer
    /// knows it), so that the next push re-creates it.
    ///
    /// # Errors
    /// Database errors.
    pub fn reset_server_revision(&mut self, item_id: &ItemId) -> Result<()> {
        self.conn.execute(
            "UPDATE items SET server_revision = 0 WHERE item_id = ?1",
            params![item_id.to_string()],
        )?;
        Ok(())
    }
}

type RawRow = (String, String, i64, String, i64);

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

fn decode_row((item_id, vault_id, revision, json, updated_at): RawRow) -> Result<StoredItem> {
    let item: EncryptedItem = serde_json::from_str(&json)?;
    // The indexed columns must agree with the authenticated content.
    if item.item_id.to_string() != item_id || item.vault_id.to_string() != vault_id {
        return Err(StoreError::Corrupted("item index mismatch"));
    }
    Ok(StoredItem {
        item,
        revision: to_u64(revision)?,
        updated_at: to_u64(updated_at)?,
    })
}

fn current_revision(tx: &Transaction<'_>, item_id: &ItemId) -> Result<Option<(u64, String)>> {
    let row: Option<(i64, String)> = tx
        .query_row(
            "SELECT revision, vault_id FROM items WHERE item_id = ?1",
            params![item_id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(r, v)| Ok((to_u64(r)?, v))).transpose()
}

fn queue_change(
    tx: &Transaction<'_>,
    item_id: &ItemId,
    vault_id: &VaultId,
    revision: u64,
    kind: ChangeKind,
    now_unix: u64,
) -> Result<()> {
    let kind = match kind {
        ChangeKind::Upsert => "upsert",
        ChangeKind::Delete => "delete",
    };
    tx.execute(
        "INSERT INTO pending_changes (change_id, item_id, vault_id, revision, kind, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            ChangeId::generate()?.to_string(),
            item_id.to_string(),
            vault_id.to_string(),
            to_i64(revision)?,
            kind,
            to_i64(now_unix)?
        ],
    )?;
    Ok(())
}
