//! Local store tests, with the real key hierarchy.

// Test helpers outside `#[test]` functions: panicking is the intended outcome.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use lk_core::{DeviceIdentity, NewAccount, Platform, create_account};
use lk_crypto::{KdfParams, MasterPassword};
use lk_store::{ChangeKind, SCHEMA_VERSION, Store, StoreError};
use lk_vault::codec;
use lk_vault::{CustomField, FieldKind, ItemContent, ItemData, Login, normalize_url};

const NOW: u64 = 1_764_000_000;

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    account: NewAccount,
    store: Store,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.lkvault");
    let account = create_account(
        &MasterPassword::new("master pw").unwrap(),
        KdfParams::recommended(),
    )
    .unwrap();
    let device = DeviceIdentity::generate().unwrap();
    let info = device
        .public_info("Test device", Platform::Cli, NOW)
        .unwrap();
    let cert = account.keys.certify_device(info, NOW).unwrap();
    let sealed = account.keys.seal_device_identity(&device).unwrap();
    let store = Store::create(&path, &account.bundle, &sealed, Some(&cert), NOW).unwrap();
    Fixture {
        _dir: dir,
        path,
        account,
        store,
    }
}

fn login(title: &str, password: &str) -> ItemData {
    ItemData::new(
        title,
        ItemContent::Login(Login {
            username: Some("user".into()),
            password: Some(password.into()),
            urls: vec![normalize_url("example.com").unwrap()],
            ..Login::default()
        }),
        NOW,
    )
    .unwrap()
}

#[test]
fn create_open_and_refuse_overwrite() {
    let f = fixture();
    let bundle = f.store.account_bundle().unwrap();
    assert_eq!(bundle, f.account.bundle);
    let cert = f.store.device_certificate().unwrap().unwrap();
    drop(f.store);

    let reopened = Store::open(&f.path).unwrap();
    assert_eq!(reopened.account_bundle().unwrap(), f.account.bundle);
    assert_eq!(reopened.device_certificate().unwrap().unwrap(), cert);
    let sealed = reopened.sealed_device().unwrap();
    let keys = reopened
        .account_bundle()
        .unwrap()
        .unlock_with_password(&MasterPassword::new("master pw").unwrap())
        .unwrap();
    let device = keys.open_device_identity(&sealed).unwrap();
    assert_eq!(device.device_id(), cert.device.device_id);

    let again = Store::create(&f.path, &f.account.bundle, &sealed, None, NOW);
    assert!(matches!(again, Err(StoreError::AlreadyExists)));
    assert!(Store::open(&f.path.with_extension("missing")).is_err());
}

#[test]
fn encrypted_items_survive_reopen_and_unlock() {
    let mut f = fixture();
    let (vault, wrapped) = f.account.keys.create_vault().unwrap();
    f.store.put_wrapped_vault_key(&wrapped).unwrap();
    let items: Vec<ItemData> = (0..5)
        .map(|i| login(&format!("Site {i}"), &format!("pw{i}")))
        .collect();
    for item in &items {
        f.store
            .upsert_item(&codec::seal_new(&vault, item).unwrap(), NOW)
            .unwrap();
    }
    drop(f.store);

    // Fresh process: open, unlock with the master password, decrypt.
    let store = Store::open(&f.path).unwrap();
    let keys = store
        .account_bundle()
        .unwrap()
        .unlock_with_password(&MasterPassword::new("master pw").unwrap())
        .unwrap();
    let wrapped = store.wrapped_vault_keys().unwrap();
    assert_eq!(wrapped.len(), 1);
    let vault = keys.open_vault_key(&wrapped[0]).unwrap();
    let mut titles: Vec<String> = store
        .items(&vault.vault_id())
        .unwrap()
        .iter()
        .map(|s| codec::open(&vault, &s.item).unwrap().title)
        .collect();
    titles.sort();
    assert_eq!(titles, ["Site 0", "Site 1", "Site 2", "Site 3", "Site 4"]);
}

#[test]
fn revisions_tombstones_and_change_queue() {
    let mut f = fixture();
    let (vault, wrapped) = f.account.keys.create_vault().unwrap();
    f.store.put_wrapped_vault_key(&wrapped).unwrap();
    let mut data = login("Mail", "one");
    let v1 = codec::seal_new(&vault, &data).unwrap();
    assert_eq!(f.store.upsert_item(&v1, NOW).unwrap(), 1);
    data.change_password("two".into(), NOW + 1).unwrap();
    let v2 = codec::seal_update(&vault, &v1, &data).unwrap();
    assert_eq!(f.store.upsert_item(&v2, NOW + 1).unwrap(), 2);
    let stored = f.store.item(&v1.item_id).unwrap().unwrap();
    assert_eq!((stored.revision, stored.updated_at), (2, NOW + 1));
    assert_eq!(stored.item, v2);

    f.store.delete_item(&v1.item_id, NOW + 2).unwrap();
    assert!(f.store.item(&v1.item_id).unwrap().is_none());
    assert!(f.store.items(&vault.vault_id()).unwrap().is_empty());
    assert!(matches!(
        f.store.delete_item(&v1.item_id, NOW + 3),
        Err(StoreError::NotFound)
    ));

    let changes = f.store.pending_changes().unwrap();
    let summary: Vec<(u64, ChangeKind)> = changes.iter().map(|c| (c.revision, c.kind)).collect();
    assert_eq!(
        summary,
        [
            (1, ChangeKind::Upsert),
            (2, ChangeKind::Upsert),
            (3, ChangeKind::Delete)
        ]
    );
    assert!(
        changes
            .iter()
            .all(|c| c.item_id == v1.item_id && c.vault_id == vault.vault_id())
    );
    let mut ids: Vec<_> = changes.iter().map(|c| c.change_id).collect();
    ids.dedup();
    assert_eq!(ids.len(), 3, "change ids must be unique");
}

#[test]
fn failed_write_leaves_no_trace() {
    let mut f = fixture();
    // Vault key deliberately not stored: the foreign key rejects the item.
    let (vault, _) = f.account.keys.create_vault().unwrap();
    let item = codec::seal_new(&vault, &login("Orphan", "x")).unwrap();
    assert!(f.store.upsert_item(&item, NOW).is_err());
    assert!(
        f.store.pending_changes().unwrap().is_empty(),
        "transaction must roll back"
    );
    assert!(f.store.item(&item.item_id).unwrap().is_none());
}

#[test]
fn items_cannot_switch_vault() {
    let mut f = fixture();
    let (a, wa) = f.account.keys.create_vault().unwrap();
    let (b, wb) = f.account.keys.create_vault().unwrap();
    f.store.put_wrapped_vault_key(&wa).unwrap();
    f.store.put_wrapped_vault_key(&wb).unwrap();
    let item = codec::seal_new(&a, &login("A", "x")).unwrap();
    f.store.upsert_item(&item, NOW).unwrap();
    let mut moved = codec::seal_new(&b, &login("B", "y")).unwrap();
    moved.item_id = item.item_id;
    assert!(matches!(
        f.store.upsert_item(&moved, NOW),
        Err(StoreError::Mismatch("vault"))
    ));
}

#[test]
fn foreign_account_material_is_refused() {
    let mut f = fixture();
    let other = create_account(
        &MasterPassword::new("other").unwrap(),
        KdfParams::recommended(),
    )
    .unwrap();
    let (_, foreign_vault) = other.keys.create_vault().unwrap();
    assert!(matches!(
        f.store.put_wrapped_vault_key(&foreign_vault),
        Err(StoreError::Mismatch("account"))
    ));
    assert!(matches!(
        f.store.replace_account_bundle(&other.bundle, NOW),
        Err(StoreError::Mismatch("account"))
    ));
}

#[test]
fn password_change_is_persisted() {
    let mut f = fixture();
    let (new_bundle, _auth) = f
        .account
        .keys
        .change_password(
            &f.account.bundle,
            &MasterPassword::new("new pw").unwrap(),
            KdfParams::recommended(),
        )
        .unwrap();
    f.store
        .replace_account_bundle(&new_bundle, NOW + 5)
        .unwrap();
    drop(f.store);
    let store = Store::open(&f.path).unwrap();
    let bundle = store.account_bundle().unwrap();
    assert!(
        bundle
            .unlock_with_password(&MasterPassword::new("master pw").unwrap())
            .is_err()
    );
    bundle
        .unlock_with_password(&MasterPassword::new("new pw").unwrap())
        .unwrap();
}

#[test]
fn newer_schema_is_refused() {
    let f = fixture();
    drop(f.store);
    let conn = rusqlite::Connection::open(&f.path).unwrap();
    conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    drop(conn);
    assert!(
        matches!(Store::open(&f.path), Err(StoreError::SchemaTooNew(v)) if v == SCHEMA_VERSION + 1)
    );
}

#[test]
fn tampered_index_is_detected() {
    let mut f = fixture();
    let (vault, wrapped) = f.account.keys.create_vault().unwrap();
    f.store.put_wrapped_vault_key(&wrapped).unwrap();
    let a = codec::seal_new(&vault, &login("A", "x")).unwrap();
    let b = codec::seal_new(&vault, &login("B", "y")).unwrap();
    f.store.upsert_item(&a, NOW).unwrap();
    f.store.upsert_item(&b, NOW).unwrap();
    drop(f.store);
    // Swap the ciphertexts of two rows behind the store's back.
    let conn = rusqlite::Connection::open(&f.path).unwrap();
    let json_b: String = conn
        .query_row(
            "SELECT encrypted FROM items WHERE item_id = ?1",
            [b.item_id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute(
        "UPDATE items SET encrypted = ?1 WHERE item_id = ?2",
        [json_b, a.item_id.to_string()],
    )
    .unwrap();
    drop(conn);
    let store = Store::open(&f.path).unwrap();
    assert!(matches!(
        store.item(&a.item_id),
        Err(StoreError::Corrupted("item index mismatch"))
    ));
}

fn all_store_bytes(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let p = PathBuf::from(format!("{}{suffix}", path.display()));
        if let Ok(b) = std::fs::read(&p) {
            bytes.extend_from_slice(&b);
        }
    }
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Criterion V-S1: no plaintext vault data ever reaches the disk, including
/// the WAL, after creates, updates and deletes.
#[test]
fn no_plaintext_on_disk() {
    let mut f = fixture();
    let (vault, wrapped) = f.account.keys.create_vault().unwrap();
    f.store.put_wrapped_vault_key(&wrapped).unwrap();
    let canaries = [
        "CANARY-TITLE-7f3a",
        "CANARY-USER-91bc",
        "CANARY-PASSWORD-55de",
        "CANARY-NOTE-0a1b",
        "canary-site-4c2d.example",
        "CANARY-FIELD-8e9f",
        "CANARY-OLD-PASSWORD-3b7c",
    ];
    let mut item = ItemData::new(
        canaries[0],
        ItemContent::Login(Login {
            username: Some(canaries[1].into()),
            password: Some(canaries[6].into()),
            urls: vec![normalize_url(canaries[4]).unwrap()],
            ..Login::default()
        }),
        NOW,
    )
    .unwrap();
    item.notes = Some(canaries[3].into());
    item.custom_fields = vec![CustomField {
        name: "f".into(),
        value: canaries[5].into(),
        kind: FieldKind::Hidden,
    }];
    let v1 = codec::seal_new(&vault, &item).unwrap();
    f.store.upsert_item(&v1, NOW).unwrap();
    item.change_password(canaries[2].into(), NOW + 1).unwrap();
    let v2 = codec::seal_update(&vault, &v1, &item).unwrap();
    f.store.upsert_item(&v2, NOW + 1).unwrap();
    let doomed = codec::seal_new(&vault, &item).unwrap();
    f.store.upsert_item(&doomed, NOW + 2).unwrap();
    f.store.delete_item(&doomed.item_id, NOW + 3).unwrap();

    // Check while open (WAL populated) and after closing.
    for phase in ["open", "closed"] {
        if phase == "closed" {
            let store = std::mem::replace(&mut f.store, Store::open(&f.path).unwrap());
            drop(store);
        }
        let bytes = all_store_bytes(&f.path);
        assert!(
            contains(&bytes, v1.item_id.to_string().as_bytes()),
            "sanity: store files were read"
        );
        for canary in canaries {
            assert!(
                !contains(&bytes, canary.as_bytes()),
                "{canary} found on disk ({phase})"
            );
            assert!(
                !contains(&bytes, canary.to_lowercase().as_bytes()),
                "{canary} found on disk ({phase})"
            );
        }
        assert!(!contains(&bytes, b"master pw"));
    }
}

#[cfg(unix)]
#[test]
fn files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture();
    let mode = std::fs::metadata(&f.path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let wal = PathBuf::from(format!("{}-wal", f.path.display()));
    if let Ok(meta) = std::fs::metadata(&wal) {
        assert_eq!(
            meta.permissions().mode() & 0o077,
            0,
            "WAL readable by others"
        );
    }
}
