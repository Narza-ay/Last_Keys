//! Local vault operations of the application layer: lifecycle, items
//! through edit drafts, views without secrets, fields, TOTP, history.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use lk_client::{
    ClientError, ContentView, Credential, ErrorKind, Field, ItemDraft, MasterPassword, Platform,
    RecoveryKey, UnlockMethod, Vault, new_master_password,
};
use serde_json::json;

const NOW: u64 = 1_764_000_000;
const PASSWORD: &str = "correct horse battery staple";

struct Fixture {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    vault: Vault,
    recovery: RecoveryKey,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("vault.lkvault");
    let created = Vault::create(
        &path,
        &MasterPassword::new(PASSWORD).unwrap(),
        "Laptop",
        Platform::Linux,
        NOW,
    )
    .unwrap();
    Fixture {
        _dir: dir,
        path,
        vault: created.vault,
        recovery: created.recovery_key,
    }
}

fn draft(value: serde_json::Value) -> ItemDraft {
    serde_json::from_value(value).unwrap()
}

fn login_draft() -> ItemDraft {
    draft(json!({
        "title": "  Bank  ",
        "favorite": true,
        "folder": "Finance",
        "tags": ["money", " money ", "", "bank"],
        "notes": {"op": "set", "value": "branch 42"},
        "customFields": [
            {"name": "Customer ID", "kind": "text", "value": {"op": "set", "value": "C-123"}},
            {"name": "Answer", "kind": "hidden", "value": {"op": "set", "value": "blue"}}
        ],
        "content": {
            "type": "login",
            "username": "alice",
            "password": {"op": "set", "value": "s3cret-pw-1"},
            "urls": ["bank.example.com", "", "https://bank.example.com/"],
            "totp": {"op": "set", "value": "JBSWY3DPEHPK3PXP"},
            "backupCodes": {"op": "set", "values": ["1111", " ", "2222"]}
        }
    }))
}

#[test]
fn lifecycle_create_lock_unlock_and_credentials() {
    let f = fixture();
    let info = f.vault.info().unwrap();
    assert_eq!(info.device_name, "Laptop");
    assert_eq!(info.platform, Platform::Linux);
    assert!(info.recovery_key_configured);
    assert_eq!(info.items, 0);
    assert!(info.remote.is_none());
    assert_eq!(info.unlocked_with, UnlockMethod::MasterPassword);
    let account = info.account_id;
    drop(f.vault); // lock

    // A second creation at the same path is refused.
    let again = Vault::create(
        &f.path,
        &MasterPassword::new(PASSWORD).unwrap(),
        "X",
        Platform::Linux,
        NOW,
    );
    assert!(matches!(again, Err(ClientError::VaultExists(_))));

    let pw = MasterPassword::new(PASSWORD).unwrap();
    let vault = Vault::unlock(&f.path, &Credential::MasterPassword(&pw)).unwrap();
    assert_eq!(vault.info().unwrap().account_id, account);
    drop(vault);

    let wrong = MasterPassword::new("not the password at all").unwrap();
    let err = Vault::unlock(&f.path, &Credential::MasterPassword(&wrong)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidCredentials);

    let vault = Vault::unlock(&f.path, &Credential::RecoveryKey(&f.recovery)).unwrap();
    assert_eq!(vault.unlock_method(), UnlockMethod::RecoveryKey);

    let missing = f.path.with_file_name("missing.lkvault");
    let err = Vault::unlock(&missing, &Credential::MasterPassword(&pw)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NoVault);
}

#[test]
fn new_master_password_rules() {
    assert!(matches!(
        new_master_password("short", "short"),
        Err(ClientError::WeakMasterPassword { min: 12 })
    ));
    assert!(matches!(
        new_master_password("long enough password", "long enough passw0rd"),
        Err(ClientError::PasswordMismatch)
    ));
    assert!(new_master_password("long enough password", "long enough password").is_ok());
}

#[test]
fn login_draft_is_normalized_and_views_hide_secrets() {
    let mut f = fixture();
    let id = f.vault.create_from_draft(login_draft(), NOW).unwrap();

    let data = f.vault.item(&id).unwrap();
    assert_eq!(data.title, "Bank");
    assert_eq!(data.tags, vec!["money", "bank"]);

    let summary = f.vault.items("").unwrap();
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0].subtitle.as_deref(), Some("alice"));
    assert_eq!(summary[0].host.as_deref(), Some("bank.example.com"));
    assert!(summary[0].has_totp && summary[0].favorite);

    let view = f.vault.item_view(&id).unwrap();
    let ContentView::Login {
        username,
        has_password,
        urls,
        has_totp,
        backup_codes,
    } = &view.content
    else {
        panic!("not a login");
    };
    assert_eq!(username.as_deref(), Some("alice"));
    assert!(*has_password && *has_totp);
    assert_eq!(urls, &vec!["https://bank.example.com/".to_owned()]);
    assert_eq!(*backup_codes, 2);
    assert!(view.has_notes);
    assert_eq!(view.custom_fields[0].value.as_deref(), Some("C-123"));
    assert_eq!(
        view.custom_fields[1].value, None,
        "hidden field not included"
    );

    // The serialized view (what reaches a web view) contains no secret.
    let json = serde_json::to_string(&view).unwrap();
    for secret in [
        "s3cret-pw-1",
        "JBSWY3DPEHPK3PXP",
        "1111",
        "2222",
        "branch 42",
        "blue",
    ] {
        assert!(!json.contains(secret), "{secret} leaked into the view");
    }
    let json = serde_json::to_string(&summary).unwrap();
    assert!(!json.contains("s3cret-pw-1"));

    // Explicit field access.
    let value = |field| f.vault.field_value(&id, field, NOW).unwrap().to_string();
    assert_eq!(value(Field::Password), "s3cret-pw-1");
    assert_eq!(value(Field::Username), "alice");
    assert_eq!(value(Field::Notes), "branch 42");
    assert_eq!(value(Field::CustomField { index: 1 }), "blue");
    assert_eq!(value(Field::BackupCode { index: 1 }), "2222");
    assert_eq!(value(Field::Url { index: 0 }), "https://bank.example.com/");
    assert!(value(Field::TotpSecret).starts_with("otpauth://totp/"));
    assert_eq!(value(Field::TotpCode).len(), 6);
    assert!(matches!(
        f.vault.field_value(&id, Field::CardNumber, NOW),
        Err(ClientError::WrongItemType)
    ));
    assert!(matches!(
        f.vault
            .field_value(&id, Field::BackupCode { index: 9 }, NOW),
        Err(ClientError::NoSuchField)
    ));
}

#[test]
fn totp_matches_rfc_6238_vector() {
    let mut f = fixture();
    // RFC 6238 SHA-1 secret "12345678901234567890", 8 digits.
    let uri = "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30";
    let id = f
        .vault
        .create_from_draft(
            draft(json!({
                "title": "T",
                "content": {"type": "login", "totp": {"op": "set", "value": uri}}
            })),
            NOW,
        )
        .unwrap();
    let code = f.vault.totp(&id, 59).unwrap();
    assert_eq!(code.code, "94287082");
    assert_eq!((code.period, code.remaining), (30, 1));
    let note = f
        .vault
        .create_from_draft(
            draft(json!({"title": "N", "content": {"type": "secure_note"}})),
            NOW,
        )
        .unwrap();
    assert!(matches!(f.vault.totp(&note, 59), Err(ClientError::NoTotp)));
}

#[test]
fn editing_keeps_unchanged_secrets_and_records_history() {
    let mut f = fixture();
    let id = f.vault.create_from_draft(login_draft(), NOW).unwrap();
    // An editor that never loaded the secrets: everything kept.
    let keep_all = draft(json!({
        "title": "Bank (renamed)",
        "customFields": [
            {"name": "Answer", "kind": "hidden", "source": 1},
            {"name": "New", "kind": "text", "value": {"op": "set", "value": "x"}}
        ],
        "content": {"type": "login", "username": "alice2", "urls": ["bank.example.com"]}
    }));
    f.vault.update_from_draft(&id, keep_all, NOW + 10).unwrap();
    let data = f.vault.item(&id).unwrap();
    assert_eq!(data.title, "Bank (renamed)");
    assert!(!data.favorite, "favorite follows the draft");
    assert_eq!(data.folder, None);
    assert_eq!(data.custom_fields.len(), 2);
    assert_eq!(data.custom_fields[0].value.expose(), "blue");
    let value = |v: &Vault, field| v.field_value(&id, field, NOW).unwrap().to_string();
    assert_eq!(value(&f.vault, Field::Password), "s3cret-pw-1");
    assert_eq!(value(&f.vault, Field::Notes), "branch 42");
    assert_eq!(value(&f.vault, Field::BackupCode { index: 0 }), "1111");
    assert!(data.password_history.is_empty());
    assert_eq!(data.updated_at, NOW + 10);

    // New password: the previous one goes to the history.
    let set = |pw: serde_json::Value| {
        draft(json!({"title": "Bank", "content": {"type": "login", "password": pw}}))
    };
    f.vault
        .update_from_draft(&id, set(json!({"op": "set", "value": "pw-2"})), NOW + 20)
        .unwrap();
    // Setting the same password again changes nothing in the history.
    f.vault
        .update_from_draft(&id, set(json!({"op": "set", "value": "pw-2"})), NOW + 30)
        .unwrap();
    let view = f.vault.item_view(&id).unwrap();
    assert_eq!(view.history.len(), 1);
    assert_eq!(view.history[0].replaced_at, NOW + 20);
    assert_eq!(
        value(&f.vault, Field::HistoryPassword { index: 0 }),
        "s3cret-pw-1"
    );
    // Removing the password keeps it in the history too.
    f.vault
        .update_from_draft(&id, set(json!({"op": "clear"})), NOW + 40)
        .unwrap();
    let data = f.vault.item(&id).unwrap();
    assert_eq!(data.password_history.len(), 2);
    assert!(matches!(
        f.vault.field_value(&id, Field::Password, NOW),
        Err(ClientError::NoSuchField)
    ));
    // Restore the most recent previous password, then delete an entry.
    f.vault.restore_password(&id, 0, NOW + 50).unwrap();
    assert_eq!(value(&f.vault, Field::Password), "pw-2");
    f.vault.delete_history_entry(&id, 0, NOW + 60).unwrap();
    assert_eq!(f.vault.item(&id).unwrap().password_history.len(), 0);
    assert!(f.vault.delete_history_entry(&id, 5, NOW + 70).is_err());
}

#[test]
fn invalid_drafts_are_refused() {
    let mut f = fixture();
    let id = f.vault.create_from_draft(login_draft(), NOW).unwrap();
    // Kept custom field without a source.
    let bad = draft(json!({
        "title": "Bank",
        "customFields": [{"name": "Lost", "kind": "hidden"}],
        "content": {"type": "login"}
    }));
    assert!(matches!(
        f.vault.update_from_draft(&id, bad, NOW),
        Err(ClientError::InvalidDraft(_))
    ));
    // Changing the type of an item.
    let card = draft(json!({"title": "Bank", "content": {"type": "payment_card"}}));
    assert!(matches!(
        f.vault.update_from_draft(&id, card, NOW),
        Err(ClientError::WrongItemType)
    ));
    // Validation errors (empty title, bad URL, bad TOTP, bad month).
    for value in [
        json!({"title": " ", "content": {"type": "secure_note"}}),
        json!({"title": "x", "content": {"type": "login", "urls": ["javascript:alert(1)"]}}),
        json!({"title": "x", "content": {"type": "login", "totp": {"op": "set", "value": "not base32!"}}}),
        json!({"title": "x", "content": {"type": "payment_card", "expiryMonth": 13}}),
    ] {
        let err = f.vault.create_from_draft(draft(value), NOW).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "{err}");
    }
    // Unknown fields are rejected at deserialization.
    assert!(
        serde_json::from_value::<ItemDraft>(json!({
            "title": "x", "content": {"type": "login"}, "unexpected": true
        }))
        .is_err()
    );
    // Nothing was changed by the failed edits.
    assert_eq!(f.vault.item(&id).unwrap().title, "Bank");
}

#[test]
fn cards_identities_and_notes() {
    let mut f = fixture();
    let card = f
        .vault
        .create_from_draft(
            draft(json!({
                "title": "Visa",
                "content": {
                    "type": "payment_card",
                    "cardholderName": "Alice Martin",
                    "number": {"op": "set", "value": "4111 1111-1111 1111"},
                    "expiryMonth": 12, "expiryYear": 2030,
                    "securityCode": {"op": "set", "value": "123"},
                    "billingAddress": {"city": " Lyon ", "country": "fr"}
                }
            })),
            NOW,
        )
        .unwrap();
    let view = f.vault.item_view(&card).unwrap();
    let ContentView::PaymentCard {
        number_last4,
        has_security_code,
        has_pin,
        billing_address,
        ..
    } = &view.content
    else {
        panic!("not a card");
    };
    assert_eq!(number_last4.as_deref(), Some("1111"));
    assert!(*has_security_code && !*has_pin);
    let address = billing_address.as_ref().unwrap();
    assert_eq!(
        (address.city.as_deref(), address.country.as_deref()),
        (Some("Lyon"), Some("FR"))
    );
    assert_eq!(
        f.vault
            .field_value(&card, Field::CardNumber, NOW)
            .unwrap()
            .as_str(),
        "4111111111111111"
    );
    assert!(
        !serde_json::to_string(&view)
            .unwrap()
            .contains("4111111111111111")
    );
    let summary = f.vault.items("visa").unwrap();
    assert_eq!(
        summary[0].subtitle.as_deref(),
        Some("Alice Martin · •••• 1111")
    );

    let identity = f
        .vault
        .create_from_draft(
            draft(json!({
                "title": "Me",
                "content": {
                    "type": "identity",
                    "firstName": "Alice", "lastName": "Martin", "email": "alice@example.com",
                    "documents": [{"kind": "passport", "number": {"op": "set", "value": "X1234567"}, "issuingCountry": "fr"}]
                }
            })),
            NOW,
        )
        .unwrap();
    // Keep the document number while changing its expiry.
    f.vault
        .update_from_draft(
            &identity,
            draft(json!({
                "title": "Me",
                "content": {
                    "type": "identity", "firstName": "Alice", "lastName": "Martin",
                    "documents": [{"kind": "passport", "source": 0, "issuingCountry": "fr", "expiryDate": "2031-01-01"}]
                }
            })),
            NOW + 1,
        )
        .unwrap();
    assert_eq!(
        f.vault
            .field_value(&identity, Field::DocumentNumber { index: 0 }, NOW)
            .unwrap()
            .as_str(),
        "X1234567"
    );
    let view = f.vault.item_view(&identity).unwrap();
    let ContentView::Identity {
        documents, email, ..
    } = &view.content
    else {
        panic!("not an identity");
    };
    assert_eq!(documents[0].issuing_country.as_deref(), Some("FR"));
    assert_eq!(documents[0].expiry_date.as_deref(), Some("2031-01-01"));
    assert_eq!(email, &None, "the draft is the new state");

    let note = f
        .vault
        .create_from_draft(
            draft(json!({"title": "Wifi", "notes": {"op": "set", "value": "hunter2"}, "content": {"type": "secure_note"}})),
            NOW,
        )
        .unwrap();
    assert!(f.vault.item_view(&note).unwrap().has_notes);

    // Listing, search (never over secrets) and ordering.
    let titles: Vec<String> = f
        .vault
        .items("")
        .unwrap()
        .into_iter()
        .map(|s| s.title)
        .collect();
    assert_eq!(titles, vec!["Me", "Visa", "Wifi"]);
    assert!(f.vault.items("hunter2").unwrap().is_empty());
    assert_eq!(f.vault.items("martin").unwrap().len(), 2);

    // References and deletion.
    let prefix: String = note.to_string().chars().take(8).collect();
    assert_eq!(f.vault.find(&prefix).unwrap(), note);
    assert_eq!(
        f.vault.find("abc").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    f.vault.delete_item(&note, NOW + 2).unwrap();
    assert!(matches!(
        f.vault.item(&note),
        Err(ClientError::ItemNotFound)
    ));
    assert!(matches!(
        f.vault.delete_item(&note, NOW + 3),
        Err(ClientError::ItemNotFound)
    ));
    assert_eq!(f.vault.info().unwrap().items, 2);
}

#[test]
fn local_password_change_and_recovery_rotation() {
    let mut f = fixture();
    f.vault.create_from_draft(login_draft(), NOW).unwrap();
    let new =
        new_master_password("a brand new master password", "a brand new master password").unwrap();
    f.vault.change_master_password(&new, NOW + 1).unwrap();
    let rotated = f.vault.rotate_recovery_key(NOW + 2).unwrap();
    drop(f.vault);

    let old = MasterPassword::new(PASSWORD).unwrap();
    assert_eq!(
        Vault::unlock(&f.path, &Credential::MasterPassword(&old))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidCredentials
    );
    assert_eq!(
        Vault::unlock(&f.path, &Credential::RecoveryKey(&f.recovery))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidCredentials,
        "the previous recovery key no longer works"
    );
    let vault = Vault::unlock(&f.path, &Credential::MasterPassword(&new)).unwrap();
    assert_eq!(vault.items("").unwrap().len(), 1);
    drop(vault);

    // Reset a forgotten password with the recovery key.
    let mut vault = Vault::unlock(&f.path, &Credential::RecoveryKey(&rotated)).unwrap();
    assert!(matches!(
        vault.rotate_recovery_key(NOW + 3),
        Err(ClientError::NeedsMasterPassword)
    ));
    let reset = MasterPassword::new("reset with the recovery key").unwrap();
    vault.change_master_password(&reset, NOW + 4).unwrap();
    assert_eq!(vault.unlock_method(), UnlockMethod::MasterPassword);
    drop(vault);
    assert!(Vault::unlock(&f.path, &Credential::MasterPassword(&reset)).is_ok());
}

#[test]
fn server_operations_need_a_registration() {
    let mut f = fixture();
    assert!(matches!(
        f.vault.sync(false, NOW),
        Err(ClientError::NotRegistered)
    ));
    assert!(matches!(f.vault.devices(), Err(ClientError::NotRegistered)));
    let err = f
        .vault
        .register("http://sync.example", "a@example.com", &f.recovery, NOW)
        .unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidServerUrl,
        "plain HTTP to a remote host"
    );
    let other = RecoveryKey::generate().unwrap();
    let err = f
        .vault
        .register("https://sync.example", "a@example.com", &other, NOW)
        .unwrap_err();
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidCredentials,
        "another account's recovery key"
    );
    let err = f
        .vault
        .register("https://sync.example", "not an e-mail", &f.recovery, NOW)
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(f.vault.remote_view().unwrap().is_none());
}
