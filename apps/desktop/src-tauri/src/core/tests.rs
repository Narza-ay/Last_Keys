//! Back-end behaviour without a window: lifecycle, locking, clipboard,
//! settings, sensitive operations, generator.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::{Duration, Instant};

use lk_client::{ContentView, Field, ItemDraft, Platform};
use serde_json::json;

use super::{DesktopCore, PassphraseOptions, PasswordOptions, Paths};
use crate::clipboard::MemoryClipboard;
use crate::settings::{Settings, Theme};

const PASSWORD: &str = "correct horse battery staple";

struct Fixture {
    _dir: tempfile::TempDir,
    core: DesktopCore,
    clipboard: MemoryClipboard,
    t0: Instant,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let clipboard = MemoryClipboard::default();
    let t0 = Instant::now();
    let core = DesktopCore::new(
        Paths::in_dir(dir.path()),
        Platform::Linux,
        Box::new(clipboard.clone()),
        t0,
    );
    Fixture {
        _dir: dir,
        core,
        clipboard,
        t0,
    }
}

fn created() -> (Fixture, String) {
    let mut f = fixture();
    let key = f
        .core
        .create_vault(PASSWORD, PASSWORD, "  Laptop  ", f.t0)
        .unwrap();
    (f, key)
}

fn login(core: &mut DesktopCore) -> lk_client::ItemId {
    let draft: ItemDraft = serde_json::from_value(json!({
        "title": "Bank",
        "content": {
            "type": "login", "username": "alice",
            "password": {"op": "set", "value": "s3cret-pw"},
            "totp": {"op": "set", "value": "JBSWY3DPEHPK3PXP"}
        }
    }))
    .unwrap();
    core.create_item(draft).unwrap()
}

#[test]
fn onboarding_lock_and_unlock() {
    let mut f = fixture();
    let status = f.core.status();
    assert!(!status.vault_exists && !status.unlocked);
    assert_eq!(f.core.list_items("").unwrap_err().kind, "locked");
    // Rules on the new master password.
    assert_eq!(
        f.core
            .create_vault("short", "short", "x", f.t0)
            .unwrap_err()
            .kind,
        "weak_master_password"
    );
    assert_eq!(
        f.core
            .create_vault(PASSWORD, "something else entirely", "x", f.t0)
            .unwrap_err()
            .kind,
        "password_mismatch"
    );
    let key = f
        .core
        .create_vault(PASSWORD, PASSWORD, "  Laptop  ", f.t0)
        .unwrap();
    assert!(key.starts_with("LK1-"), "recovery key shown once");
    assert!(f.core.status().unlocked && f.core.status().vault_exists);
    assert_eq!(f.core.info().unwrap().device_name, "Laptop");
    assert_eq!(
        f.core
            .create_vault(PASSWORD, PASSWORD, "x", f.t0)
            .unwrap_err()
            .kind,
        "vault_exists"
    );

    f.core.lock();
    assert!(!f.core.status().unlocked);
    assert_eq!(f.core.info().unwrap_err().kind, "locked");
    assert_eq!(
        f.core.unlock("wrong password here", f.t0).unwrap_err().kind,
        "invalid_credentials"
    );
    f.core.unlock(PASSWORD, f.t0).unwrap();
    f.core.lock();
    assert_eq!(
        f.core
            .unlock_with_recovery_key("not a key", f.t0)
            .unwrap_err()
            .kind,
        "invalid_recovery_key"
    );
    f.core
        .unlock_with_recovery_key(&key.to_lowercase(), f.t0)
        .unwrap();
    assert_eq!(
        f.core.info().unwrap().unlocked_with,
        lk_client::UnlockMethod::RecoveryKey
    );
}

#[test]
fn auto_lock_after_inactivity() {
    let (mut f, _) = created();
    let minute = Duration::from_secs(60);
    // Default: 5 minutes.
    assert!(!f.core.tick(f.t0 + 4 * minute));
    f.core.touch(f.t0 + 4 * minute);
    assert!(
        !f.core.tick(f.t0 + 8 * minute),
        "activity postponed the lock"
    );
    assert!(f.core.tick(f.t0 + 9 * minute));
    assert!(!f.core.status().unlocked);
    assert!(!f.core.tick(f.t0 + 20 * minute), "already locked");

    // A shorter delay applies at once.
    let t1 = f.t0 + 30 * minute;
    f.core.unlock(PASSWORD, t1).unwrap();
    let mut settings = f.core.settings();
    settings.auto_lock_minutes = 1;
    f.core.set_settings(settings).unwrap();
    assert!(f.core.tick(t1 + minute));
}

#[test]
fn secrets_are_copied_by_rust_and_cleared() {
    let (mut f, _) = created();
    let id = login(&mut f.core);

    // The view sent to the UI has no secret; a reveal is explicit.
    let view = f.core.get_item(&id).unwrap();
    assert!(matches!(
        view.content,
        ContentView::Login {
            has_password: true,
            ..
        }
    ));
    assert!(!serde_json::to_string(&view).unwrap().contains("s3cret-pw"));
    assert_eq!(
        f.core.reveal_field(&id, Field::Password).unwrap(),
        "s3cret-pw"
    );

    let copied = f.core.copy_field(&id, Field::Password, f.t0).unwrap();
    assert_eq!(copied.clears_in_seconds, 30);
    assert_eq!(f.clipboard.0.lock().unwrap().as_deref(), Some("s3cret-pw"));
    f.core.tick(f.t0 + Duration::from_secs(29));
    assert!(f.clipboard.0.lock().unwrap().is_some());
    f.core.tick(f.t0 + Duration::from_secs(30));
    assert_eq!(f.clipboard.0.lock().unwrap().as_deref(), None);

    // Copying a TOTP code, then locking: the clipboard is cleared at once.
    f.core.copy_field(&id, Field::TotpCode, f.t0).unwrap();
    assert_eq!(
        f.clipboard.0.lock().unwrap().as_deref().map(str::len),
        Some(6)
    );
    f.core.lock();
    assert_eq!(f.clipboard.0.lock().unwrap().as_deref(), None);
    assert_eq!(
        f.core
            .copy_field(&id, Field::Password, f.t0)
            .unwrap_err()
            .kind,
        "locked"
    );
}

#[test]
fn settings_are_validated_and_persisted() {
    let (mut f, _) = created();
    let mut s = f.core.settings();
    assert_eq!(s, Settings::default());
    s.theme = Theme::Dark;
    s.clipboard_clear_seconds = 60;
    f.core.set_settings(s.clone()).unwrap();
    s.auto_lock_minutes = 0;
    assert_eq!(f.core.set_settings(s).unwrap_err().kind, "invalid_setting");
    assert_eq!(f.core.settings().theme, Theme::Dark);
    // A restart reads them back.
    let restarted = DesktopCore::new(
        Paths::in_dir(f._dir.path()),
        Platform::Linux,
        Box::new(MemoryClipboard::default()),
        f.t0,
    );
    assert_eq!(restarted.settings().clipboard_clear_seconds, 60);
    assert!(!restarted.status().unlocked, "a restart starts locked");
}

#[test]
fn sensitive_operations_need_the_current_password() {
    let (mut f, key) = created();
    let new = "a brand new master password";
    assert_eq!(
        f.core
            .change_master_password(Some("wrong current password"), new, new)
            .unwrap_err()
            .kind,
        "invalid_credentials"
    );
    assert_eq!(
        f.core
            .change_master_password(None, new, new)
            .unwrap_err()
            .kind,
        "invalid_credentials"
    );
    f.core
        .change_master_password(Some(PASSWORD), new, new)
        .unwrap();
    assert_eq!(
        f.core.rotate_recovery_key(PASSWORD).unwrap_err().kind,
        "invalid_credentials",
        "the old password no longer works"
    );
    let rotated = f.core.rotate_recovery_key(new).unwrap();
    assert_ne!(rotated, key);
    f.core.lock();

    // Forgotten password: unlock with the recovery key, reset without the
    // current password.
    f.core.unlock_with_recovery_key(&rotated, f.t0).unwrap();
    let reset = "reset after forgetting it";
    f.core.change_master_password(None, reset, reset).unwrap();
    f.core.lock();
    f.core.unlock(reset, f.t0).unwrap();
}

#[test]
fn generator_and_items() {
    let (mut f, _) = created();
    let options = PasswordOptions {
        length: 24,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: false,
        exclude_ambiguous: true,
    };
    let generated = f.core.generate_password(&options).unwrap();
    assert_eq!(generated.value.chars().count(), 24);
    assert!(generated.value.chars().all(char::is_alphanumeric));
    assert!(generated.entropy_bits > 100.0);
    let none = PasswordOptions {
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: false,
        ..options
    };
    assert_eq!(
        f.core.generate_password(&none).unwrap_err().kind,
        "invalid_input"
    );
    let phrase = f
        .core
        .generate_passphrase(&PassphraseOptions {
            words: 5,
            separator: "-".to_owned(),
            capitalize: true,
            include_number: false,
        })
        .unwrap();
    assert_eq!(phrase.value.split('-').count(), 5);
    f.core.copy_text(&phrase.value, f.t0).unwrap();
    assert_eq!(
        f.clipboard.0.lock().unwrap().as_deref(),
        Some(phrase.value.as_str())
    );

    // Items through drafts, as the UI sends them.
    let id = login(&mut f.core);
    assert_eq!(f.core.list_items("bank").unwrap().len(), 1);
    assert_eq!(f.core.totp(&id).unwrap().code.len(), 6);
    let edit: ItemDraft = serde_json::from_value(json!({
        "title": "Bank", "content": {"type": "login", "password": {"op": "set", "value": "new-pw"}}
    }))
    .unwrap();
    f.core.update_item(&id, edit).unwrap();
    assert_eq!(f.core.get_item(&id).unwrap().history.len(), 1);
    f.core.restore_password(&id, 0).unwrap();
    assert_eq!(
        f.core.reveal_field(&id, Field::Password).unwrap(),
        "s3cret-pw"
    );
    f.core.delete_history_entry(&id, 0).unwrap();
    f.core.delete_item(&id).unwrap();
    assert_eq!(f.core.get_item(&id).unwrap_err().kind, "not_found");
    assert_eq!(f.core.sync(false).unwrap_err().kind, "not_registered");
    assert_eq!(f.core.devices().unwrap_err().kind, "not_registered");
}
