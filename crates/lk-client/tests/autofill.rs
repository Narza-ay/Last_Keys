//! Autofill operations (ADR-0011, criteria V-A1 and V-A2): candidates for a
//! page, origin-checked fills and copies, frames of another origin, save
//! proposals and saving.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use lk_client::{
    ClientError, ErrorKind, Field, FillTarget, ItemDraft, ItemId, MasterPassword, MatchKind,
    Platform, SaveProposal, Vault,
};
use serde_json::json;

const NOW: u64 = 1_764_000_000;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let created = Vault::create(
        &dir.path().join("vault.lkvault"),
        &MasterPassword::new("correct horse battery staple").unwrap(),
        "Laptop",
        Platform::Linux,
        NOW,
    )
    .unwrap();
    Fixture {
        _dir: dir,
        vault: created.vault,
    }
}

fn login(vault: &mut Vault, title: &str, username: &str, password: &str, urls: &[&str]) -> ItemId {
    let draft: ItemDraft = serde_json::from_value(json!({
        "title": title,
        "content": {
            "type": "login",
            "username": username,
            "password": {"op": "set", "value": password},
            "urls": urls,
        }
    }))
    .unwrap();
    vault.create_from_draft(draft, NOW).unwrap()
}

fn target<'a>(page: &'a str, frame: &'a str, confirmed: bool) -> FillTarget<'a> {
    FillTarget {
        page_url: page,
        frame_url: frame,
        cross_origin_confirmed: confirmed,
    }
}

#[test]
fn candidates_match_the_page_only() {
    let mut f = fixture();
    let exact = login(
        &mut f.vault,
        "Example",
        "alice",
        "pw-1",
        &["https://example.com/login"],
    );
    let site = login(
        &mut f.vault,
        "Example (www)",
        "bob",
        "pw-2",
        &["https://www.example.com"],
    );
    login(
        &mut f.vault,
        "Look-alike",
        "alice",
        "pw-3",
        &["https://example.com.evil.net"],
    );
    login(
        &mut f.vault,
        "Other user's pages",
        "alice",
        "pw-4",
        &["https://bob.github.io"],
    );
    login(&mut f.vault, "No URL", "alice", "pw-5", &[]);
    let note: ItemDraft = serde_json::from_value(json!({
        "title": "https://example.com",
        "notes": {"op": "set", "value": "example.com"},
        "content": {"type": "secure_note"}
    }))
    .unwrap();
    f.vault.create_from_draft(note, NOW).unwrap();

    let rows = f
        .vault
        .autofill_candidates("https://example.com/account?x=1")
        .unwrap();
    let ids: Vec<_> = rows.iter().map(|r| (r.id, r.matched)).collect();
    assert_eq!(
        ids,
        vec![(exact, MatchKind::ExactHost), (site, MatchKind::SameSite)]
    );
    assert_eq!(rows[0].username.as_deref(), Some("alice"));
    assert!(rows[0].has_password && !rows[0].has_totp);
    // The secrets never appear in candidates.
    let text = serde_json::to_string(&rows).unwrap();
    assert!(!text.contains("pw-1") && text.contains("\"matched\":\"exact_host\""));

    assert!(
        f.vault
            .autofill_candidates("https://alice.github.io/")
            .unwrap()
            .is_empty()
    );
    assert!(
        f.vault
            .autofill_candidates("http://example.com/")
            .unwrap()
            .is_empty()
    );
    for page in [
        "file:///tmp/login.html",
        "chrome://settings",
        "about:blank",
        "nonsense ::",
    ] {
        let e = f.vault.autofill_candidates(page).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::IneligiblePage, "{page}");
    }
}

#[test]
fn candidates_are_ordered_exact_then_favorite_then_title() {
    let mut f = fixture();
    let b = login(&mut f.vault, "b", "u1", "p", &["https://example.com"]);
    let a = login(&mut f.vault, "A", "u2", "p", &["https://example.com"]);
    let site = login(
        &mut f.vault,
        "0 site",
        "u3",
        "p",
        &["https://login.example.com"],
    );
    let fav = login(
        &mut f.vault,
        "z favorite",
        "u4",
        "p",
        &["https://example.com"],
    );
    f.vault
        .update_item(&fav, NOW, |d| {
            d.favorite = true;
            Ok(())
        })
        .unwrap();
    let rows = f.vault.autofill_candidates("https://example.com").unwrap();
    let ids: Vec<_> = rows.iter().map(|r| r.id).collect();
    assert_eq!(ids, vec![fav, a, b, site]);
}

#[test]
fn fills_are_checked_against_page_and_frame() {
    let mut f = fixture();
    let id = login(
        &mut f.vault,
        "Example",
        "alice",
        "s3cret",
        &["https://example.com"],
    );
    let totp: ItemDraft = serde_json::from_value(json!({
        "title": "With TOTP",
        "content": {
            "type": "login",
            "password": {"op": "set", "value": "pw"},
            "urls": ["https://example.com"],
            "totp": {"op": "set", "value": "JBSWY3DPEHPK3PXP"}
        }
    }))
    .unwrap();
    let with_totp = f.vault.create_from_draft(totp, NOW).unwrap();

    let page = "https://example.com/login";
    let creds = f
        .vault
        .autofill_credentials(&id, &target(page, page, false), NOW)
        .unwrap();
    assert_eq!(creds.username.as_deref(), Some("alice"));
    assert_eq!(
        creds.password.as_deref().map(String::as_str),
        Some("s3cret")
    );
    assert!(creds.totp.is_none());
    let json = serde_json::to_value(&creds).unwrap();
    assert_eq!(
        json,
        json!({"username": "alice", "password": "s3cret", "totp": null})
    );

    let creds = f
        .vault
        .autofill_credentials(&with_totp, &target(page, page, false), NOW)
        .unwrap();
    assert!(creds.username.is_none());
    let code = creds.totp.unwrap();
    assert_eq!(code.len(), 6);
    assert_eq!(*code, f.vault.totp(&with_totp, NOW).unwrap().code);

    // Another site, a look-alike or a downgrade to http: refused.
    for other in [
        "https://evil.com/",
        "https://xn--xample-2of.com/",
        "http://example.com/",
    ] {
        let e = f
            .vault
            .autofill_credentials(&id, &target(other, other, true), NOW)
            .unwrap_err();
        assert!(matches!(e, ClientError::OriginMismatch), "{other}: {e}");
    }
    // A matching page with a frame of another site: refused even when
    // confirmed.
    let e = f
        .vault
        .autofill_credentials(&id, &target(page, "https://evil.com/frame", true), NOW)
        .unwrap_err();
    assert!(matches!(e, ClientError::OriginMismatch));
    // A frame of the same site but another origin: needs confirmation.
    let frame = "https://login.example.com/embedded";
    let e = f
        .vault
        .autofill_credentials(&id, &target(page, frame, false), NOW)
        .unwrap_err();
    assert!(matches!(e, ClientError::ConfirmationRequired));
    assert_eq!(e.kind(), ErrorKind::ConfirmationRequired);
    assert!(
        f.vault
            .autofill_credentials(&id, &target(page, frame, true), NOW)
            .is_ok()
    );
    // Same origin written differently (default port, case): no confirmation.
    assert!(
        f.vault
            .autofill_credentials(&id, &target(page, "https://EXAMPLE.com:443/x", false), NOW)
            .is_ok()
    );
    // Ineligible frame.
    let e = f
        .vault
        .autofill_credentials(&id, &target(page, "about:blank", true), NOW)
        .unwrap_err();
    assert!(matches!(e, ClientError::IneligiblePage));
}

#[test]
fn fills_refuse_other_item_types_and_unknown_items() {
    let mut f = fixture();
    let card: ItemDraft = serde_json::from_value(json!({
        "title": "Card",
        "content": {"type": "payment_card", "number": {"op": "set", "value": "4111111111111111"}}
    }))
    .unwrap();
    let card = f.vault.create_from_draft(card, NOW).unwrap();
    let page = "https://example.com";
    let e = f
        .vault
        .autofill_credentials(&card, &target(page, page, false), NOW)
        .unwrap_err();
    assert!(matches!(e, ClientError::WrongItemType));
    let id = login(&mut f.vault, "x", "u", "p", &[page]);
    f.vault.delete_item(&id, NOW).unwrap();
    let e = f
        .vault
        .autofill_credentials(&id, &target(page, page, false), NOW)
        .unwrap_err();
    assert!(matches!(e, ClientError::ItemNotFound));
}

#[test]
fn copies_are_limited_to_matching_logins_and_login_fields() {
    let mut f = fixture();
    let id = login(
        &mut f.vault,
        "Example",
        "alice",
        "s3cret",
        &["https://example.com"],
    );
    let page = "https://www.example.com/";
    assert_eq!(
        *f.vault
            .autofill_field(&id, page, Field::Password, NOW)
            .unwrap(),
        "s3cret"
    );
    assert_eq!(
        *f.vault
            .autofill_field(&id, page, Field::Username, NOW)
            .unwrap(),
        "alice"
    );
    assert!(matches!(
        f.vault
            .autofill_field(&id, page, Field::TotpCode, NOW)
            .unwrap_err(),
        ClientError::NoTotp
    ));
    assert!(matches!(
        f.vault
            .autofill_field(&id, page, Field::Notes, NOW)
            .unwrap_err(),
        ClientError::NoSuchField
    ));
    assert!(matches!(
        f.vault
            .autofill_field(&id, "https://evil.com", Field::Password, NOW)
            .unwrap_err(),
        ClientError::OriginMismatch
    ));
}

#[test]
fn save_proposals() {
    let mut f = fixture();
    let id = login(
        &mut f.vault,
        "Example",
        "Alice@Example.com",
        "old",
        &["https://example.com"],
    );
    let page = "https://login.example.com/signin";

    assert_eq!(
        f.vault
            .save_proposal(page, Some(" alice@example.com "), "old")
            .unwrap(),
        SaveProposal::Unchanged { id }
    );
    assert_eq!(
        f.vault
            .save_proposal(page, Some("alice@example.com"), "new")
            .unwrap(),
        SaveProposal::UpdatePassword {
            id,
            title: "Example".to_owned()
        }
    );
    assert_eq!(
        f.vault.save_proposal(page, Some("bob"), "new").unwrap(),
        SaveProposal::New {
            title: "example.com".to_owned(),
            url: "https://login.example.com/".to_owned()
        }
    );
    // A look-alike page never proposes to update the genuine login.
    assert!(matches!(
        f.vault
            .save_proposal(
                "https://\u{0435}xample.com/",
                Some("alice@example.com"),
                "new"
            )
            .unwrap(),
        SaveProposal::New { .. }
    ));
    // Password-only forms match logins without a username.
    let no_user = login(
        &mut f.vault,
        "PIN site",
        "",
        "1234",
        &["https://pin.example.org"],
    );
    assert_eq!(
        f.vault
            .save_proposal("https://pin.example.org/", None, "5678")
            .unwrap(),
        SaveProposal::UpdatePassword {
            id: no_user,
            title: "PIN site".to_owned()
        }
    );
    // The exact host is preferred over the same site.
    let exact = login(
        &mut f.vault,
        "Login host",
        "alice@example.com",
        "x",
        &[page],
    );
    assert_eq!(
        f.vault
            .save_proposal(page, Some("alice@example.com"), "new")
            .unwrap(),
        SaveProposal::UpdatePassword {
            id: exact,
            title: "Login host".to_owned()
        }
    );
    let json =
        serde_json::to_value(f.vault.save_proposal(page, Some("bob"), "p").unwrap()).unwrap();
    assert_eq!(
        json,
        json!({"action": "new", "title": "example.com", "url": "https://login.example.com/"})
    );
    assert!(matches!(
        f.vault.save_proposal(page, Some("bob"), "").unwrap_err(),
        ClientError::InvalidDraft(_)
    ));
    assert!(matches!(
        f.vault
            .save_proposal("javascript:alert(1)", Some("bob"), "p")
            .unwrap_err(),
        ClientError::IneligiblePage
    ));
}

#[test]
fn saving_new_logins_and_new_passwords() {
    let mut f = fixture();
    let page = "https://accounts.example.co.uk:8443/register?step=2";
    let id = f
        .vault
        .save_login(page, Some(" carol "), "first-pw", None, NOW)
        .unwrap();
    let data = f.vault.item(&id).unwrap();
    assert_eq!(data.title, "example.co.uk");
    let view = f.vault.item_view(&id).unwrap();
    let text = serde_json::to_string(&view).unwrap();
    assert!(
        text.contains("https://accounts.example.co.uk:8443/"),
        "{text}"
    );
    assert!(text.contains("\"carol\""));
    assert_eq!(
        f.vault
            .save_proposal(page, Some("carol"), "first-pw")
            .unwrap(),
        SaveProposal::Unchanged { id }
    );
    let rows = f.vault.autofill_candidates(page).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].matched, MatchKind::ExactHost);

    // Update: the previous password goes to the history.
    f.vault
        .save_login(page, Some("Carol"), "second-pw", Some(&id), NOW + 10)
        .unwrap();
    assert_eq!(
        *f.vault.field_value(&id, Field::Password, NOW).unwrap(),
        "second-pw"
    );
    assert_eq!(
        *f.vault
            .field_value(&id, Field::HistoryPassword { index: 0 }, NOW)
            .unwrap(),
        "first-pw"
    );
    // An update must concern a login of this page and this username.
    assert!(matches!(
        f.vault
            .save_login("https://evil.com", Some("carol"), "x", Some(&id), NOW)
            .unwrap_err(),
        ClientError::OriginMismatch
    ));
    assert!(matches!(
        f.vault
            .save_login(page, Some("mallory"), "x", Some(&id), NOW)
            .unwrap_err(),
        ClientError::OriginMismatch
    ));
    assert!(matches!(
        f.vault.save_login(page, None, "", None, NOW).unwrap_err(),
        ClientError::InvalidDraft(_)
    ));
    // Password-only and IP-address pages.
    let ip = f
        .vault
        .save_login("http://192.168.1.1/admin", None, "router-pw", None, NOW)
        .unwrap();
    let data = f.vault.item(&ip).unwrap();
    assert_eq!(data.title, "192.168.1.1");
    assert_eq!(
        f.vault.autofill_candidates("http://192.168.1.1/").unwrap()[0].id,
        ip
    );
}
