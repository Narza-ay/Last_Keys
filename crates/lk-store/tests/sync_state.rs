//! Schema migration v1 → v2 (criterion V-S3) and synchronization state.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use lk_core::{DeviceIdentity, NewAccount, Platform, create_account};
use lk_crypto::{KdfParams, MasterPassword};
use lk_store::{RemoteState, SCHEMA_VERSION, Store, StoreError};

const NOW: u64 = 1_764_000_000;
const NOW_SQL: i64 = 1_764_000_000;

/// Frozen copy of schema version 1 (as released in M2). Never edit.
const SCHEMA_V1: &str = r"
CREATE TABLE account (id INTEGER PRIMARY KEY CHECK (id = 1), account_id TEXT NOT NULL, bundle TEXT NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE device (id INTEGER PRIMARY KEY CHECK (id = 1), device_id TEXT NOT NULL, sealed_identity TEXT NOT NULL, certificate TEXT);
CREATE TABLE vault_keys (vault_id TEXT PRIMARY KEY, wrapped TEXT NOT NULL);
CREATE TABLE items (
    item_id TEXT PRIMARY KEY, vault_id TEXT NOT NULL REFERENCES vault_keys (vault_id),
    revision INTEGER NOT NULL CHECK (revision > 0), deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    encrypted TEXT, updated_at INTEGER NOT NULL,
    CHECK ((deleted = 0 AND encrypted IS NOT NULL) OR (deleted = 1 AND encrypted IS NULL)));
CREATE INDEX items_by_vault ON items (vault_id, deleted);
CREATE TABLE pending_changes (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, change_id TEXT NOT NULL UNIQUE, item_id TEXT NOT NULL,
    vault_id TEXT NOT NULL, revision INTEGER NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('upsert', 'delete')),
    created_at INTEGER NOT NULL);
";

fn account() -> (NewAccount, DeviceIdentity) {
    let account = create_account(
        &MasterPassword::new("pw").unwrap(),
        KdfParams::recommended(),
    )
    .unwrap();
    (account, DeviceIdentity::generate().unwrap())
}

#[test]
fn version_1_store_is_migrated_without_data_loss() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.lkvault");
    let (account, device) = account();
    let sealed = account.keys.seal_device_identity(&device).unwrap();
    let (vault, wrapped) = account.keys.create_vault().unwrap();
    let item = vault.create_item(b"kept across the migration").unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute(
            "INSERT INTO account VALUES (1, ?1, ?2, ?3)",
            rusqlite::params![
                account.bundle.account_id.to_string(),
                serde_json::to_string(&account.bundle).unwrap(),
                NOW_SQL
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO device VALUES (1, ?1, ?2, NULL)",
            rusqlite::params![
                device.device_id().to_string(),
                serde_json::to_string(&sealed).unwrap()
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO vault_keys VALUES (?1, ?2)",
            rusqlite::params![
                wrapped.vault_id.to_string(),
                serde_json::to_string(&wrapped).unwrap()
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO items VALUES (?1, ?2, 1, 0, ?3, ?4)",
            rusqlite::params![
                item.item_id.to_string(),
                item.vault_id.to_string(),
                serde_json::to_string(&item).unwrap(),
                NOW_SQL
            ],
        )
        .unwrap();
    }
    let store = Store::open(&path).unwrap();
    let version: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, SCHEMA_VERSION);
    let local = store.local_item(&item.item_id).unwrap().unwrap();
    assert_eq!(local.server_revision, 0);
    assert_eq!(local.item.as_ref(), Some(&item));
    assert_eq!(
        vault.open_item(&local.item.unwrap()).unwrap().as_slice(),
        b"kept across the migration"
    );
    assert_eq!(store.sync_cursor(&vault.vault_id()).unwrap(), 0);
    assert!(store.remote().unwrap().is_none());
}

struct Fixture {
    _dir: tempfile::TempDir,
    _path: PathBuf,
    store: Store,
    vault: lk_core::VaultKey,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.lkvault");
    let (account, device) = account();
    let sealed = account.keys.seal_device_identity(&device).unwrap();
    let mut store = Store::create(&path, &account.bundle, &sealed, None, NOW).unwrap();
    let (vault, wrapped) = account.keys.create_vault().unwrap();
    store.put_wrapped_vault_key(&wrapped).unwrap();
    let _ = Platform::Cli;
    Fixture {
        _dir: dir,
        _path: path,
        store,
        vault,
    }
}

#[test]
fn remote_binding_and_cursor() {
    let mut f = fixture();
    f.store
        .set_remote("https://sync.example", "a@example.com")
        .unwrap();
    assert_eq!(
        f.store.remote().unwrap(),
        Some(("https://sync.example".into(), "a@example.com".into()))
    );
    let v = f.vault.vault_id();
    f.store.set_sync_cursor(&v, 5).unwrap();
    f.store.set_sync_cursor(&v, 5).unwrap();
    assert_eq!(f.store.sync_cursor(&v).unwrap(), 5);
    assert!(matches!(
        f.store.set_sync_cursor(&v, 4),
        Err(StoreError::Corrupted(_))
    ));
}

#[test]
fn remote_states_are_applied_and_rollbacks_refused() {
    let mut f = fixture();
    let v = f.vault.vault_id();
    let item = f.vault.create_item(b"from server").unwrap();
    let state = RemoteState {
        item_id: item.item_id,
        revision: 3,
        item: Some(item.clone()),
    };
    f.store.apply_remote(&v, &state, None, NOW).unwrap();
    let local = f.store.local_item(&item.item_id).unwrap().unwrap();
    assert_eq!(
        (local.server_revision, local.item.as_ref()),
        (3, Some(&item))
    );
    assert!(
        f.store.pending_changes().unwrap().is_empty(),
        "remote states are not re-queued"
    );

    // An older revision is a rollback.
    let old = RemoteState {
        revision: 2,
        ..state.clone()
    };
    assert!(matches!(
        f.store.apply_remote(&v, &old, None, NOW),
        Err(StoreError::Corrupted(_))
    ));

    // Tombstone.
    let tomb = RemoteState {
        item_id: item.item_id,
        revision: 4,
        item: None,
    };
    f.store.apply_remote(&v, &tomb, None, NOW).unwrap();
    let local = f.store.local_item(&item.item_id).unwrap().unwrap();
    assert!(local.item.is_none());
    assert!(f.store.item(&item.item_id).unwrap().is_none());
}

#[test]
fn pending_changes_are_resolved_atomically() {
    let mut f = fixture();
    let v = f.vault.vault_id();
    let item = f.vault.create_item(b"local").unwrap();
    f.store.upsert_item(&item, NOW).unwrap();
    let edited = f.vault.update_item(&item, b"local edit").unwrap();
    f.store.upsert_item(&edited, NOW).unwrap();
    let pending = f.store.pending_changes().unwrap();
    assert_eq!(pending.len(), 2);
    // Accepted by the server at revision 1: queue entries up to the last seq go away.
    f.store
        .mark_pushed(&item.item_id, 1, pending[1].seq)
        .unwrap();
    assert!(f.store.pending_changes().unwrap().is_empty());
    assert_eq!(
        f.store
            .local_item(&item.item_id)
            .unwrap()
            .unwrap()
            .server_revision,
        1
    );

    // A new local edit, then the server version wins: resolved in one step.
    let again = f.vault.update_item(&edited, b"another edit").unwrap();
    f.store.upsert_item(&again, NOW).unwrap();
    let seq = f.store.pending_changes().unwrap()[0].seq;
    let server = f.vault.update_item(&edited, b"server version").unwrap();
    f.store
        .apply_remote(
            &v,
            &RemoteState {
                item_id: item.item_id,
                revision: 2,
                item: Some(server.clone()),
            },
            Some(seq),
            NOW,
        )
        .unwrap();
    assert!(f.store.pending_changes().unwrap().is_empty());
    assert_eq!(
        f.store.local_item(&item.item_id).unwrap().unwrap().item,
        Some(server)
    );

    f.store.reset_server_revision(&item.item_id).unwrap();
    assert_eq!(
        f.store
            .local_item(&item.item_id)
            .unwrap()
            .unwrap()
            .server_revision,
        0
    );
}

#[test]
fn remote_state_for_another_vault_is_refused() {
    let mut f = fixture();
    let item = f.vault.create_item(b"x").unwrap();
    let other = lk_core::VaultId::generate().unwrap();
    let state = RemoteState {
        item_id: item.item_id,
        revision: 1,
        item: Some(item),
    };
    assert!(f.store.apply_remote(&other, &state, None, NOW).is_err());
}
