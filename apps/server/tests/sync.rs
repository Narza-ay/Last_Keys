//! Synchronization (ADR-0008) and credential changes against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use common::*;
use lk_auth::start_registration;
use lk_core::{EncryptedItem, ItemId, KdfConfig, PasswordKeys};
use lk_crypto::{KdfParams, MasterPassword};
use lk_protocol::{CredentialKind, PullResponse, PushOutcome, PushResponse};
use serde_json::{Value, json};

fn outcomes(body: Value) -> Vec<PushOutcome> {
    serde_json::from_value::<PushResponse>(body)
        .unwrap()
        .results
}

#[tokio::test]
async fn push_pull_round_trip_and_decryption_elsewhere() {
    let server = TestServer::default().await;
    let client = new_client("alice@example.com", "alice master password");
    let token = enrolled(&server, &client).await;
    let vault = create_vault(&server, &client, &token).await;
    let item = vault
        .create_item(b"secret note: CANARY-PLAINTEXT-42")
        .unwrap();

    let (status, body) = push(
        &server,
        &token,
        &vault.vault_id(),
        vec![change(item.item_id, 0, Some(&item))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let PushOutcome::Accepted { state } = &outcomes(body)[0] else {
        panic!("expected acceptance")
    };
    assert_eq!((state.revision, state.seq), (1, 1));

    let (status, body) = server
        .get(
            &format!("/v1/vaults/{}/changes?since=0", vault.vault_id()),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let pull: PullResponse = serde_json::from_value(body).unwrap();
    assert_eq!(
        (pull.items.len(), pull.next_since, pull.more),
        (1, 1, false)
    );
    // Another device of the account unwraps the vault key and decrypts.
    let (_, vaults) = server.get("/v1/vaults", Some(&token)).await;
    let wrapped: lk_core::WrappedVaultKey =
        serde_json::from_value(vaults["vaults"][0].clone()).unwrap();
    let keys_elsewhere = client
        .account
        .bundle
        .unlock_with_password(&MasterPassword::new(&client.password).unwrap())
        .unwrap();
    let vault_elsewhere = keys_elsewhere.open_vault_key(&wrapped).unwrap();
    let pulled = pull.items[0].item.as_ref().unwrap();
    assert_eq!(
        vault_elsewhere.open_item(pulled).unwrap().as_slice(),
        b"secret note: CANARY-PLAINTEXT-42"
    );

    // V-Y1: the plaintext never reaches the database.
    let dump: Vec<String> = sqlx::query_scalar(
        "SELECT encrypted::text FROM items UNION ALL SELECT bundle::text FROM accounts
         UNION ALL SELECT wrapped::text FROM vault_keys UNION ALL SELECT outcome::text FROM applied_changes",
    )
    .fetch_all(&server.pool)
    .await
    .unwrap();
    let all = dump.join("\n");
    assert!(!all.contains("CANARY-PLAINTEXT-42") && !all.contains(&client.password));
    assert!(
        all.contains(&item.item_id.to_string()),
        "sanity: rows were read"
    );
    server.cleanup().await;
}

#[tokio::test]
async fn replays_are_idempotent() {
    let server = TestServer::default().await;
    let client = new_client("bob@example.com", "bob master password");
    let token = enrolled(&server, &client).await;
    let vault = create_vault(&server, &client, &token).await;
    let item = vault.create_item(b"v1").unwrap();
    let c = change(item.item_id, 0, Some(&item));
    let first = outcomes(
        push(&server, &token, &vault.vault_id(), vec![c.clone()])
            .await
            .1,
    );
    let second = outcomes(
        push(&server, &token, &vault.vault_id(), vec![c.clone(), c])
            .await
            .1,
    );
    assert_eq!(second, vec![first[0].clone(), first[0].clone()]);
    let last_seq: i64 = sqlx::query_scalar("SELECT last_seq FROM account_seq")
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(last_seq, 1, "replays must not create new changes");
    // Reusing a change id for another item is refused.
    let other = vault.create_item(b"other").unwrap();
    let mut reused = change(other.item_id, 0, Some(&other));
    reused["change_id"] = first_change_id(&server).await;
    assert_eq!(
        push(&server, &token, &vault.vault_id(), vec![reused])
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    server.cleanup().await;
}

async fn first_change_id(server: &TestServer) -> Value {
    let id: uuid::Uuid = sqlx::query_scalar("SELECT change_id FROM applied_changes LIMIT 1")
        .fetch_one(&server.pool)
        .await
        .unwrap();
    json!(id)
}

#[tokio::test]
async fn concurrent_edits_conflict_instead_of_overwriting() {
    let server = TestServer::default().await;
    let client = new_client("carol@example.com", "carol master password");
    let token = enrolled(&server, &client).await;
    let vault = create_vault(&server, &client, &token).await;
    let v1 = vault.create_item(b"v1").unwrap();
    push(
        &server,
        &token,
        &vault.vault_id(),
        vec![change(v1.item_id, 0, Some(&v1))],
    )
    .await;

    // Two devices edit revision 1 concurrently.
    let edit_a = vault.update_item(&v1, b"edit from A").unwrap();
    let edit_b = vault.update_item(&v1, b"edit from B").unwrap();
    let a = outcomes(
        push(
            &server,
            &token,
            &vault.vault_id(),
            vec![change(v1.item_id, 1, Some(&edit_a))],
        )
        .await
        .1,
    );
    assert!(matches!(&a[0], PushOutcome::Accepted { state } if state.revision == 2));
    let b = outcomes(
        push(
            &server,
            &token,
            &vault.vault_id(),
            vec![change(v1.item_id, 1, Some(&edit_b))],
        )
        .await
        .1,
    );
    let PushOutcome::Conflict { current } = &b[0] else {
        panic!("expected a conflict")
    };
    assert_eq!(current.revision, 2);
    // The server kept A's version, and B received it to merge.
    assert_eq!(
        vault
            .open_item(current.item.as_ref().unwrap())
            .unwrap()
            .as_slice(),
        b"edit from A"
    );
    // Unknown item with a non-zero base revision: conflict with an empty state.
    let ghost = vault.create_item(b"ghost").unwrap();
    let g = outcomes(
        push(
            &server,
            &token,
            &vault.vault_id(),
            vec![change(ghost.item_id, 3, Some(&ghost))],
        )
        .await
        .1,
    );
    assert!(
        matches!(&g[0], PushOutcome::Conflict { current } if current.revision == 0 && current.item.is_none())
    );
    server.cleanup().await;
}

#[tokio::test]
async fn deletions_leave_tombstones() {
    let server = TestServer::default().await;
    let client = new_client("dave@example.com", "dave master password");
    let token = enrolled(&server, &client).await;
    let vault = create_vault(&server, &client, &token).await;
    let item = vault.create_item(b"to delete").unwrap();
    push(
        &server,
        &token,
        &vault.vault_id(),
        vec![change(item.item_id, 0, Some(&item))],
    )
    .await;
    let d = outcomes(
        push(
            &server,
            &token,
            &vault.vault_id(),
            vec![change(item.item_id, 1, None)],
        )
        .await
        .1,
    );
    assert!(
        matches!(&d[0], PushOutcome::Accepted { state } if state.revision == 2 && state.item.is_none())
    );
    let (_, body) = server
        .get(
            &format!("/v1/vaults/{}/changes?since=1", vault.vault_id()),
            Some(&token),
        )
        .await;
    let pull: PullResponse = serde_json::from_value(body).unwrap();
    assert_eq!(pull.items.len(), 1);
    assert!(
        pull.items[0].item.is_none(),
        "tombstone carries no ciphertext"
    );
    // Deleting an item that never existed is an error.
    let never = ItemId::generate().unwrap();
    assert_eq!(
        push(
            &server,
            &token,
            &vault.vault_id(),
            vec![change(never, 0, None)]
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    server.cleanup().await;
}

#[tokio::test]
async fn malformed_and_misplaced_items_are_refused() {
    let server = TestServer::default().await;
    let client = new_client("erin@example.com", "erin master password");
    let token = enrolled(&server, &client).await;
    let vault = create_vault(&server, &client, &token).await;
    let other_vault = create_vault(&server, &client, &token).await;
    let item = vault.create_item(b"x").unwrap();

    // Item of vault A pushed to vault B.
    assert_eq!(
        push(
            &server,
            &token,
            &other_vault.vault_id(),
            vec![change(item.item_id, 0, Some(&item))]
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    // Change for another item id than the body.
    assert_eq!(
        push(
            &server,
            &token,
            &vault.vault_id(),
            vec![change(ItemId::generate().unwrap(), 0, Some(&item))]
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    // Envelopes swapped (wrong purposes).
    let swapped = EncryptedItem {
        wrapped_item_key: item.content.clone(),
        content: item.wrapped_item_key.clone(),
        ..item.clone()
    };
    assert_eq!(
        push(
            &server,
            &token,
            &vault.vault_id(),
            vec![change(item.item_id, 0, Some(&swapped))]
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    // Garbage envelope.
    let garbage = EncryptedItem {
        content: vec![1, 2, 3].into(),
        ..item.clone()
    };
    assert_eq!(
        push(
            &server,
            &token,
            &vault.vault_id(),
            vec![change(item.item_id, 0, Some(&garbage))]
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    // Unknown vault.
    let (ghost_vault, _) = client.account.keys.create_vault().unwrap();
    let ghost_item = ghost_vault.create_item(b"g").unwrap();
    assert_eq!(
        push(
            &server,
            &token,
            &ghost_vault.vault_id(),
            vec![change(ghost_item.item_id, 0, Some(&ghost_item))]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // Nothing was stored.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM items")
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    server.cleanup().await;
}

#[tokio::test]
async fn accounts_are_isolated() {
    let server = TestServer::default().await;
    let alice = new_client("alice@example.com", "alice master password");
    let mallory = new_client("mallory@example.com", "mallory master password");
    let token_a = enrolled(&server, &alice).await;
    let token_m = enrolled(&server, &mallory).await;
    let vault = create_vault(&server, &alice, &token_a).await;
    let item = vault.create_item(b"alice's secret").unwrap();
    push(
        &server,
        &token_a,
        &vault.vault_id(),
        vec![change(item.item_id, 0, Some(&item))],
    )
    .await;

    // Mallory knows the vault id but sees nothing and cannot write.
    let (status, body) = server
        .get(
            &format!("/v1/vaults/{}/changes?since=0", vault.vault_id()),
            Some(&token_m),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    let edit = vault.update_item(&item, b"overwritten by mallory").unwrap();
    assert_eq!(
        push(
            &server,
            &token_m,
            &vault.vault_id(),
            vec![change(item.item_id, 1, Some(&edit))]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // Mallory cannot plant a vault key in Alice's account.
    let (_, wrapped) = alice.account.keys.create_vault().unwrap();
    let (status, _) = server
        .call(
            axum::http::Method::PUT,
            &format!("/v1/vaults/{}/key", wrapped.vault_id),
            Some(&token_m),
            Some(serde_json::to_value(&wrapped).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, vaults) = server.get("/v1/vaults", Some(&token_m)).await;
    assert_eq!(vaults["vaults"].as_array().unwrap().len(), 0);
    server.cleanup().await;
}

#[tokio::test]
async fn pagination_and_large_items() {
    let server = TestServer::default().await;
    let client = new_client("frank@example.com", "frank master password");
    let token = enrolled(&server, &client).await;
    let vault = create_vault(&server, &client, &token).await;
    let changes: Vec<Value> = (0..5)
        .map(|i| {
            let item = vault.create_item(format!("item {i}").as_bytes()).unwrap();
            change(item.item_id, 0, Some(&item))
        })
        .collect();
    push(&server, &token, &vault.vault_id(), changes).await;
    let mut since = 0;
    let mut seen = 0;
    loop {
        let (_, body) = server
            .get(
                &format!(
                    "/v1/vaults/{}/changes?since={since}&limit=2",
                    vault.vault_id()
                ),
                Some(&token),
            )
            .await;
        let page: PullResponse = serde_json::from_value(body).unwrap();
        seen += page.items.len();
        since = page.next_since;
        if !page.more {
            break;
        }
    }
    assert_eq!((seen, since), (5, 5));

    // A 400 KiB item exceeds the default request limit but not the push limit.
    let big = vault.create_item(&vec![b'x'; 400 * 1024]).unwrap();
    let (status, body) = push(
        &server,
        &token,
        &vault.vault_id(),
        vec![change(big.item_id, 0, Some(&big))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    server.cleanup().await;
}

#[tokio::test]
async fn oversized_requests_are_refused() {
    let server = TestServer::default().await;
    let client = new_client("ivan@example.com", "ivan master password");
    let token = enrolled(&server, &client).await;
    let vault = create_vault(&server, &client, &token).await;

    // Authentication and account endpoints: 256 KiB.
    let padding = "x".repeat(300 * 1024);
    let (status, _) = server
        .post(
            "/v1/accounts/prelogin",
            None,
            &json!({ "email": padding.clone() }),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, _) = server
        .post(
            "/v1/devices",
            Some(&token),
            &json!({ "certificate": padding }),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // Push: 32 MiB, refused before anything is stored. Two valid 13 MiB
    // items (about 17.3 MiB each once base64-encoded) exceed it together.
    let changes: Vec<Value> = (0..2)
        .map(|_| {
            let item = vault.create_item(&vec![b'x'; 13 * 1024 * 1024]).unwrap();
            change(item.item_id, 0, Some(&item))
        })
        .collect();
    let (status, _) = push(&server, &token, &vault.vault_id(), changes).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (_, body) = server
        .get(
            &format!("/v1/vaults/{}/changes?since=0", vault.vault_id()),
            Some(&token),
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    server.cleanup().await;
}

#[tokio::test]
async fn password_change_and_recovery_reset() {
    let server = TestServer::default().await;
    let client = new_client("grace@example.com", "grace master password");
    let token = enrolled(&server, &client).await;

    // Password change from a full session.
    let new_password = MasterPassword::new("grace NEW master password").unwrap();
    let (new_bundle, new_auth) = client
        .account
        .keys
        .change_password(
            &client.account.bundle,
            &new_password,
            KdfParams::recommended(),
        )
        .unwrap();
    replace_password(&server, &token, &new_auth, &new_bundle).await;
    assert!(matches!(
        login(
            &server,
            &client.email,
            &client.account.auth_key,
            CredentialKind::Password,
            client.device.device_id()
        )
        .await,
        LoginOutcome::ClientRejected
    ));
    let (_, prelogin) = server
        .post(
            "/v1/accounts/prelogin",
            None,
            &json!({ "email": client.email }),
        )
        .await;
    let kdf: KdfConfig = serde_json::from_value(prelogin["kdf"].clone()).unwrap();
    assert_eq!(kdf, new_bundle.kdf);
    let keys = PasswordKeys::derive(&new_password, &kdf).unwrap();
    assert!(matches!(
        login(
            &server,
            &client.email,
            keys.auth_key(),
            CredentialKind::Password,
            client.device.device_id()
        )
        .await,
        LoginOutcome::Ok { .. }
    ));

    // Forgotten password: recovery session → new password → every session ends.
    let LoginOutcome::Ok {
        token: recovery_token,
        ..
    } = login(
        &server,
        &client.email,
        &client.account.recovery_auth_key,
        CredentialKind::Recovery,
        client.device.device_id(),
    )
    .await
    else {
        panic!("recovery login failed")
    };
    // A recovery session cannot read vaults.
    assert_eq!(
        server.get("/v1/vaults", Some(&recovery_token)).await.0,
        StatusCode::FORBIDDEN
    );
    let recovered = new_bundle
        .unlock_with_recovery_key(&client.account.recovery_key)
        .unwrap();
    let reset_password = MasterPassword::new("grace RESET master password").unwrap();
    let (reset_bundle, reset_auth) = recovered
        .change_password(&new_bundle, &reset_password, KdfParams::recommended())
        .unwrap();
    replace_password(&server, &recovery_token, &reset_auth, &reset_bundle).await;
    assert_eq!(
        server
            .get("/v1/auth/session", Some(&recovery_token))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server.get("/v1/auth/session", Some(&token)).await.0,
        StatusCode::UNAUTHORIZED,
        "old sessions end after a reset"
    );
    assert!(matches!(
        login(
            &server,
            &client.email,
            &reset_auth,
            CredentialKind::Password,
            client.device.device_id()
        )
        .await,
        LoginOutcome::Ok { .. }
    ));
    server.cleanup().await;
}

async fn replace_password(
    server: &TestServer,
    token: &str,
    auth: &lk_crypto::AuthKey,
    bundle: &lk_core::AccountKeyBundle,
) {
    let (flow, request) = start_registration(auth).unwrap();
    let (status, start) = server
        .post(
            "/v1/account/credentials/start",
            Some(token),
            &json!({ "credential": "password", "request": b64(&request) }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{start}");
    let upload = flow.finish(auth, &unb64(&start["response"])).unwrap();
    let (status, body) = server
        .post(
            "/v1/account/credentials/finish",
            Some(token),
            &json!({ "credential": "password", "upload": b64(&upload), "bundle": bundle }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
async fn bundle_identity_cannot_be_swapped() {
    let server = TestServer::default().await;
    let client = new_client("heidi@example.com", "heidi master password");
    let token = enrolled(&server, &client).await;
    let attacker = new_client("x@example.com", "attacker master password");
    let mut forged = client.account.bundle.clone();
    forged.signing_public_key = attacker.account.bundle.signing_public_key.clone();
    let (flow, request) = start_registration(&client.account.auth_key).unwrap();
    let (_, start) = server
        .post(
            "/v1/account/credentials/start",
            Some(&token),
            &json!({ "credential": "password", "request": b64(&request) }),
        )
        .await;
    let upload = flow
        .finish(&client.account.auth_key, &unb64(&start["response"]))
        .unwrap();
    let (status, _) = server
        .post(
            "/v1/account/credentials/finish",
            Some(&token),
            &json!({ "credential": "password", "upload": b64(&upload), "bundle": forged }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Recovery sessions cannot replace the recovery credential itself.
    let LoginOutcome::Ok {
        token: recovery_token,
        ..
    } = login(
        &server,
        &client.email,
        &client.account.recovery_auth_key,
        CredentialKind::Recovery,
        client.device.device_id(),
    )
    .await
    else {
        panic!("recovery login failed")
    };
    let (_, request) = start_registration(&client.account.auth_key).unwrap();
    let (status, _) = server
        .post(
            "/v1/account/credentials/start",
            Some(&recovery_token),
            &json!({ "credential": "recovery", "request": b64(&request) }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    server.cleanup().await;
}
