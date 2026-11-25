//! The client synchronization engine (`lk-sync`) against the real server,
//! over real HTTP, with several devices (ADR-0008 merge rules).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::PathBuf;

use common::*;
use lk_core::{
    AccountKeys, DeviceIdentity, PasswordKeys, Platform, VaultKey, WrappedVaultKey, create_account,
};
use lk_crypto::{KdfParams, MasterPassword};
use lk_store::Store;
use lk_sync::{
    Api, SyncError, SyncReport, UreqTransport, enroll_device, login_registered, register_account,
    sync_vault,
};
use lk_vault::{ItemContent, ItemData, SecureNote, codec};

const EMAIL: &str = "sync@example.com";
const PASSWORD: &str = "correct horse battery staple";

/// One client device: its local store, keys and identity.
struct Device {
    _dir: tempfile::TempDir,
    path: PathBuf,
    identity: DeviceIdentity,
    keys: AccountKeys,
    vault: VaultKey,
    wrapped: WrappedVaultKey,
}

fn note(title: &str, body: &str, now: u64) -> ItemData {
    let mut item = ItemData::new(title, ItemContent::SecureNote(SecureNote {}), now).unwrap();
    item.notes = Some(body.into());
    item
}

impl Device {
    fn store(&self) -> Store {
        Store::open(&self.path).unwrap()
    }

    fn add(&self, title: &str, body: &str) -> lk_core::ItemId {
        let sealed = codec::seal_new(&self.vault, &note(title, body, NOW)).unwrap();
        self.store().upsert_item(&sealed, NOW).unwrap();
        sealed.item_id
    }

    fn edit(&self, id: &lk_core::ItemId, body: &str) {
        let mut store = self.store();
        let stored = store.item(id).unwrap().expect("item exists locally");
        let mut data = codec::open(&self.vault, &stored.item).unwrap();
        data.notes = Some(body.into());
        data.updated_at = NOW + 1;
        let sealed = codec::seal_update(&self.vault, &stored.item, &data).unwrap();
        store.upsert_item(&sealed, NOW + 1).unwrap();
    }

    fn delete(&self, id: &lk_core::ItemId) {
        self.store().delete_item(id, NOW + 2).unwrap();
    }

    /// (title, notes) of every live item, sorted.
    fn contents(&self) -> Vec<(String, String)> {
        let store = self.store();
        let mut out: Vec<(String, String)> = store
            .items(&self.vault.vault_id())
            .unwrap()
            .iter()
            .map(|s| {
                let d = codec::open(&self.vault, &s.item).unwrap();
                (
                    d.title,
                    d.notes.map(|n| n.expose().to_owned()).unwrap_or_default(),
                )
            })
            .collect();
        out.sort();
        out
    }

    fn sync(&self, url: &str) -> Result<SyncReport, SyncError> {
        let api = Api::new(UreqTransport::new(url).unwrap());
        let store = self.store();
        let keys = PasswordKeys::derive(
            &MasterPassword::new(PASSWORD).unwrap(),
            &store.account_bundle().unwrap().kdf,
        )
        .unwrap();
        let session = login_registered(&api, EMAIL, &keys, &self.identity)?;
        let mut store = store;
        sync_vault(
            &api,
            &session,
            &mut store,
            &self.vault,
            &self.wrapped,
            NOW + 10,
        )
    }
}

/// Device A creates the account locally and registers it on the server.
fn first_device(url: &str) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.lkvault");
    let account = create_account(
        &MasterPassword::new(PASSWORD).unwrap(),
        KdfParams::recommended(),
    )
    .unwrap();
    let identity = DeviceIdentity::generate().unwrap();
    let cert = account
        .keys
        .certify_device(
            identity.public_info("A", Platform::Linux, NOW).unwrap(),
            NOW,
        )
        .unwrap();
    let sealed = account.keys.seal_device_identity(&identity).unwrap();
    let mut store = Store::create(&path, &account.bundle, &sealed, Some(&cert), NOW).unwrap();
    let (vault, wrapped) = account.keys.create_vault().unwrap();
    store.put_wrapped_vault_key(&wrapped).unwrap();
    let api = Api::new(UreqTransport::new(url).unwrap());
    let password_keys =
        PasswordKeys::derive(&MasterPassword::new(PASSWORD).unwrap(), &account.bundle.kdf).unwrap();
    register_account(
        &api,
        EMAIL,
        &password_keys,
        &account.recovery_key,
        &account.bundle,
        &cert,
    )
    .unwrap();
    store.set_remote(url, EMAIL).unwrap();
    Device {
        _dir: dir,
        path,
        identity,
        keys: account.keys,
        vault,
        wrapped,
    }
}

/// Device B knows only the e-mail and the password.
fn new_device(url: &str, name: &str) -> Device {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("{name}.lkvault"));
    let api = Api::new(UreqTransport::new(url).unwrap());
    let identity = DeviceIdentity::generate().unwrap();
    let e = enroll_device(
        &api,
        EMAIL,
        &MasterPassword::new(PASSWORD).unwrap(),
        &identity,
        name,
        Platform::Android,
        NOW,
    )
    .unwrap();
    let sealed = e.keys.seal_device_identity(&identity).unwrap();
    let mut store = Store::create(&path, &e.bundle, &sealed, Some(&e.certificate), NOW).unwrap();
    let wrapped = api.vault_keys(&e.session).unwrap().remove(0);
    store.put_wrapped_vault_key(&wrapped).unwrap();
    let vault = e.keys.open_vault_key(&wrapped).unwrap();
    store.set_remote(url, EMAIL).unwrap();
    Device {
        _dir: dir,
        path,
        identity,
        keys: e.keys,
        vault,
        wrapped,
    }
}

/// Runs blocking client code off the async runtime that serves HTTP.
async fn blocking<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    tokio::task::spawn_blocking(f).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_devices_converge_and_never_lose_a_version() {
    let server = TestServer::default().await;
    let url = server.serve_http().await;
    let result = blocking(move || {
        let a = first_device(&url);
        let bank = a.add("Bank", "pin 1234");
        a.add("Wifi", "hunter2");
        let r = a.sync(&url).unwrap();
        assert_eq!((r.pushed, r.conflicts), (2, 0));

        // A second device enrolls and receives everything.
        let b = new_device(&url, "B");
        let r = b.sync(&url).unwrap();
        assert_eq!(r.pulled, 2);
        assert_eq!(b.contents(), a.contents());

        // Edits and deletions propagate both ways.
        b.edit(&bank, "pin 5678");
        b.sync(&url).unwrap();
        a.sync(&url).unwrap();
        assert!(a.contents().contains(&("Bank".into(), "pin 5678".into())));

        // Concurrent offline edits of the same item: a conflict copy keeps
        // the losing version; both devices end with both versions.
        a.edit(&bank, "edited on A");
        b.edit(&bank, "edited on B");
        let ra = a.sync(&url).unwrap();
        assert_eq!(ra.conflicts, 0);
        let rb = b.sync(&url).unwrap();
        assert_eq!((rb.conflicts, rb.conflict_copies.len()), (1, 1));
        a.sync(&url).unwrap();
        let expected = vec![
            ("Bank".to_owned(), "edited on A".to_owned()),
            ("Bank (conflict copy)".to_owned(), "edited on B".to_owned()),
            ("Wifi".to_owned(), "hunter2".to_owned()),
        ];
        assert_eq!(a.contents(), expected);
        assert_eq!(b.contents(), expected);

        // The same edit on both devices is not a conflict copy.
        let wifi = a
            .store()
            .items(&a.vault.vault_id())
            .unwrap()
            .into_iter()
            .find(|s| codec::open(&a.vault, &s.item).unwrap().title == "Wifi")
            .unwrap()
            .item
            .item_id;
        a.edit(&wifi, "same new password");
        b.edit(&wifi, "same new password");
        a.sync(&url).unwrap();
        let r = b.sync(&url).unwrap();
        assert_eq!((r.conflicts, r.conflict_copies.len()), (1, 0));

        // Deletion propagates.
        a.delete(&wifi);
        a.sync(&url).unwrap();
        b.sync(&url).unwrap();
        assert!(!b.contents().iter().any(|(t, _)| t == "Wifi"));
        a.contents()
    })
    .await;
    assert_eq!(result.len(), 2);
    server.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_versus_edit_keeps_the_edit() {
    let server = TestServer::default().await;
    let url = server.serve_http().await;
    blocking(move || {
        let a = first_device(&url);
        let x = a.add("Doc", "v1");
        let y = a.add("Card", "v1");
        a.sync(&url).unwrap();
        let b = new_device(&url, "B");
        b.sync(&url).unwrap();

        // A deletes X while B edits it: B's edit survives (remote wins over
        // a local deletion).
        a.delete(&x);
        b.edit(&x, "v2 from B");
        b.sync(&url).unwrap();
        a.sync(&url).unwrap();
        assert!(a.contents().contains(&("Doc".into(), "v2 from B".into())));

        // B deletes Y while A edits it: when B pushed first, A's edit is kept
        // as a re-created copy.
        b.delete(&y);
        a.edit(&y, "v2 from A");
        b.sync(&url).unwrap();
        let r = a.sync(&url).unwrap();
        assert_eq!(r.conflict_copies.len(), 1);
        b.sync(&url).unwrap();
        assert!(
            b.contents()
                .contains(&("Card (conflict copy)".into(), "v2 from A".into()))
        );
        assert_eq!(a.contents(), b.contents());
    })
    .await;
    server.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_edits_are_folded_and_retries_are_safe() {
    let server = TestServer::default().await;
    let url = server.serve_http().await;
    blocking(move || {
        let a = first_device(&url);
        let id = a.add("Note", "1");
        for v in ["2", "3", "4"] {
            a.edit(&id, v);
        }
        let r = a.sync(&url).unwrap();
        assert_eq!(r.pushed, 1, "four local versions, one push");
        // A second pass has nothing to do.
        let r = a.sync(&url).unwrap();
        assert_eq!((r.pushed, r.pulled, r.conflicts), (0, 0, 0));
        assert!(a.store().pending_changes().unwrap().is_empty());
        // An item created and deleted offline never reaches the server.
        let ghost = a.add("Ghost", "x");
        a.delete(&ghost);
        assert_eq!(a.sync(&url).unwrap().pushed, 0);
    })
    .await;
    server.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_device_can_no_longer_sync() {
    let server = TestServer::default().await;
    let url = server.serve_http().await;
    blocking(move || {
        let a = first_device(&url);
        a.add("Secret", "s");
        a.sync(&url).unwrap();
        let b = new_device(&url, "B");
        b.sync(&url).unwrap();

        let api = Api::new(UreqTransport::new(&url).unwrap());
        let keys = PasswordKeys::derive(
            &MasterPassword::new(PASSWORD).unwrap(),
            &a.store().account_bundle().unwrap().kdf,
        )
        .unwrap();
        let session = login_registered(&api, EMAIL, &keys, &a.identity).unwrap();
        let revocation = a.keys.revoke_device(b.identity.device_id(), NOW).unwrap();
        api.revoke(&session, &revocation).unwrap();

        assert!(matches!(b.sync(&url), Err(SyncError::DeviceRevoked)));
        // A keeps working.
        a.add("After", "a");
        assert_eq!(a.sync(&url).unwrap().pushed, 1);
        // Hidden: B's keys are unused after revocation.
        let _ = &b.keys;
    })
    .await;
    server.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_cannot_enroll() {
    let server = TestServer::default().await;
    let url = server.serve_http().await;
    blocking(move || {
        let _a = first_device(&url);
        let api = Api::new(UreqTransport::new(&url).unwrap());
        let identity = DeviceIdentity::generate().unwrap();
        let result = enroll_device(
            &api,
            EMAIL,
            &MasterPassword::new("not the password").unwrap(),
            &identity,
            "X",
            Platform::Cli,
            NOW,
        );
        assert!(matches!(result, Err(SyncError::InvalidCredentials)));
        let unknown = enroll_device(
            &api,
            "nobody@example.com",
            &MasterPassword::new(PASSWORD).unwrap(),
            &identity,
            "X",
            Platform::Cli,
            NOW,
        );
        assert!(matches!(unknown, Err(SyncError::InvalidCredentials)));
    })
    .await;
    server.cleanup().await;
}
