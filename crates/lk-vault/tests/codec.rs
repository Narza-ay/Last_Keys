//! Item encoding/decoding and encryption through the real key hierarchy.

// Test helpers outside `#[test]` functions: panicking is the intended outcome.
#![allow(clippy::unwrap_used)]

use lk_core::create_account;
use lk_crypto::{KdfParams, MasterPassword};
use lk_vault::codec::{self, MAX_ITEM_BYTES};
use lk_vault::{
    CustomField, FieldKind, ItemContent, ItemData, Login, SecureNote, VaultError, normalize_totp,
    normalize_url,
};

fn sample_login() -> ItemData {
    let mut item = ItemData::new(
        "Example",
        ItemContent::Login(Login {
            username: Some("bob".into()),
            password: Some("p4ss".into()),
            urls: vec![normalize_url("example.com").unwrap()],
            totp: Some(normalize_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap()),
            backup_codes: vec!["1111-2222".into()],
        }),
        1_700_000_000,
    )
    .unwrap();
    item.tags = vec!["work".into()];
    item.folder = Some("Pro".into());
    item.custom_fields = vec![CustomField {
        name: "PIN".into(),
        value: "0000".into(),
        kind: FieldKind::Hidden,
    }];
    item
}

#[test]
fn json_round_trip() {
    let item = sample_login();
    let bytes = codec::encode(&item).unwrap();
    assert_eq!(codec::decode(&bytes).unwrap(), item);
}

#[test]
fn encrypted_round_trip_and_update() {
    let account = create_account(
        &MasterPassword::new("pw").unwrap(),
        KdfParams::recommended(),
    )
    .unwrap();
    let (vault, _) = account.keys.create_vault().unwrap();
    let mut item = sample_login();
    let sealed = codec::seal_new(&vault, &item).unwrap();
    assert_eq!(codec::open(&vault, &sealed).unwrap(), item);

    item.change_password("n3w".into(), 1_700_000_100).unwrap();
    let updated = codec::seal_update(&vault, &sealed, &item).unwrap();
    assert_eq!(updated.item_id, sealed.item_id);
    let opened = codec::open(&vault, &updated).unwrap();
    assert_eq!(opened.password_history.len(), 1);
    assert_eq!(opened, item);
}

#[test]
fn newer_schema_is_reported_as_unsupported() {
    let json = br#"{"schema":2,"title":"x","created_at":0,"updated_at":0,"content":{"type":"secure_note"},"future_field":1}"#;
    assert_eq!(codec::decode(json), Err(VaultError::UnsupportedSchema(2)));
}

#[test]
fn unknown_fields_in_current_schema_are_rejected() {
    let top = br#"{"schema":1,"title":"x","created_at":0,"updated_at":0,"content":{"type":"secure_note"},"surprise":1}"#;
    assert_eq!(codec::decode(top), Err(VaultError::Corrupted));
    let nested = br#"{"schema":1,"title":"x","created_at":0,"updated_at":0,"content":{"type":"login","surprise":1}}"#;
    assert_eq!(codec::decode(nested), Err(VaultError::Corrupted));
    let unknown_type =
        br#"{"schema":1,"title":"x","created_at":0,"updated_at":0,"content":{"type":"spaceship"}}"#;
    assert_eq!(codec::decode(unknown_type), Err(VaultError::Corrupted));
}

#[test]
fn decoded_items_are_validated() {
    // Well-formed JSON but an invalid (non-normalized) URL and empty title.
    let bad_url = br#"{"schema":1,"title":"x","created_at":0,"updated_at":0,"content":{"type":"login","urls":["javascript:alert(1)"]}}"#;
    assert!(matches!(
        codec::decode(bad_url),
        Err(VaultError::Invalid { .. })
    ));
    let no_title = br#"{"schema":1,"title":" ","created_at":0,"updated_at":0,"content":{"type":"secure_note"}}"#;
    assert!(matches!(
        codec::decode(no_title),
        Err(VaultError::Invalid { .. })
    ));
}

#[test]
fn oversized_items_are_rejected() {
    let mut note = ItemData::new("big", ItemContent::SecureNote(SecureNote {}), 0).unwrap();
    note.custom_fields = (0..64)
        .map(|i| CustomField {
            name: format!("f{i}"),
            value: "v".repeat(8 * 1024).into(),
            kind: FieldKind::Text,
        })
        .collect();
    // 64 × 8 KiB = 512 KiB: valid and under the limit.
    codec::encode(&note).unwrap();
    assert_eq!(
        codec::decode(&vec![b' '; MAX_ITEM_BYTES + 1]),
        Err(VaultError::TooLarge)
    );
}

#[test]
fn garbage_is_corrupted_not_a_panic() {
    for input in [
        &b""[..],
        b"null",
        b"[]",
        b"{",
        b"{\"schema\":\"1\"}",
        b"\xff\xfe",
    ] {
        assert!(codec::decode(input).is_err());
    }
}
