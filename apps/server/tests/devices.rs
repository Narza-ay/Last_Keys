//! Device enrollment, listing and revocation against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use common::*;
use lk_core::{AccountKeyBundle, DeviceIdentity, PasswordKeys, Platform};
use lk_crypto::MasterPassword;
use lk_protocol::{CredentialKind, DeviceList, SessionKind};
use serde_json::json;

/// A second device enrolls with the master password: enrollment session →
/// download bundle → unlock → self-certify with the account key → register.
async fn enroll_second_device(
    server: &TestServer,
    client: &ClientAccount,
) -> (DeviceIdentity, String) {
    let device = DeviceIdentity::generate().unwrap();
    let (_, prelogin) = server
        .post(
            "/v1/accounts/prelogin",
            None,
            &json!({ "email": client.email }),
        )
        .await;
    let kdf = serde_json::from_value(prelogin["kdf"].clone()).unwrap();
    let keys = PasswordKeys::derive(&MasterPassword::new(&client.password).unwrap(), &kdf).unwrap();
    let LoginOutcome::Ok { token, response } = login(
        server,
        &client.email,
        keys.auth_key(),
        CredentialKind::Password,
        device.device_id(),
    )
    .await
    else {
        panic!("login of the new device failed");
    };
    assert_eq!(response.session, SessionKind::Enrollment);
    // Enrollment sessions cannot read vaults yet.
    assert_eq!(
        server.get("/v1/vaults", Some(&token)).await.0,
        StatusCode::FORBIDDEN
    );

    let (status, bundle) = server.get("/v1/account/bundle", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let bundle: AccountKeyBundle = serde_json::from_value(bundle).unwrap();
    let account_keys = bundle.unlock_with_password_keys(&keys).unwrap();
    let cert = account_keys
        .certify_device(
            device.public_info("second", Platform::Linux, NOW).unwrap(),
            NOW,
        )
        .unwrap();
    let (status, body) = server
        .post("/v1/devices", Some(&token), &json!({ "certificate": cert }))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    // The same session is now a full session.
    let (_, session) = server.get("/v1/auth/session", Some(&token)).await;
    assert_eq!(session["session"], "full");
    (device, token)
}

#[tokio::test]
async fn second_device_enrollment() {
    let server = TestServer::default().await;
    let client = new_client("alice@example.com", "alice master password");
    let token_a = enrolled(&server, &client).await;
    let (device_b, _) = enroll_second_device(&server, &client).await;

    let (status, list) = server.get("/v1/devices", Some(&token_a)).await;
    assert_eq!(status, StatusCode::OK);
    let list: DeviceList = serde_json::from_value(list).unwrap();
    assert_eq!(list.devices.len(), 2);
    // Clients verify the list themselves with the account key.
    let certs: Vec<_> = list.devices.iter().map(|d| d.certificate.clone()).collect();
    let trusted = lk_core::trusted_devices(
        &client.account.keys.account_id(),
        &client.account.keys.signing_public_key(),
        &certs,
        &[],
    )
    .unwrap();
    assert!(trusted.iter().any(|d| d.device_id == device_b.device_id()));
    server.cleanup().await;
}

#[tokio::test]
async fn enrollment_sessions_cannot_register_other_devices_or_foreign_certificates() {
    let server = TestServer::default().await;
    let client = new_client("bob@example.com", "bob master password");
    enrolled(&server, &client).await;
    let newcomer = DeviceIdentity::generate().unwrap();
    let LoginOutcome::Ok { token, .. } = login(
        &server,
        &client.email,
        &client.account.auth_key,
        CredentialKind::Password,
        newcomer.device_id(),
    )
    .await
    else {
        panic!("login failed");
    };
    // Certificate for a different device.
    let other = DeviceIdentity::generate().unwrap();
    let cert_other = client
        .account
        .keys
        .certify_device(other.public_info("x", Platform::Cli, NOW).unwrap(), NOW)
        .unwrap();
    assert_eq!(
        server
            .post(
                "/v1/devices",
                Some(&token),
                &json!({ "certificate": cert_other })
            )
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    // Certificate signed by another account.
    let foreign = new_client("x@example.com", "x master password");
    let cert_foreign = foreign
        .account
        .keys
        .certify_device(newcomer.public_info("n", Platform::Cli, NOW).unwrap(), NOW)
        .unwrap();
    assert_eq!(
        server
            .post(
                "/v1/devices",
                Some(&token),
                &json!({ "certificate": cert_foreign })
            )
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    server.cleanup().await;
}

#[tokio::test]
async fn revocation_ends_access_immediately_and_permanently() {
    let server = TestServer::default().await;
    let client = new_client("carol@example.com", "carol master password");
    let token_a = enrolled(&server, &client).await;
    let (device_b, token_b) = enroll_second_device(&server, &client).await;
    assert_eq!(
        server.get("/v1/vaults", Some(&token_b)).await.0,
        StatusCode::OK
    );

    let revocation = client
        .account
        .keys
        .revoke_device(device_b.device_id(), NOW)
        .unwrap();
    let path = format!("/v1/devices/{}/revoke", device_b.device_id());
    let (status, body) = server
        .post(&path, Some(&token_a), &json!({ "revocation": revocation }))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // The revoked device's session is refused at its very next request.
    let (status, body) = server.get("/v1/vaults", Some(&token_b)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "session must be gone: {body}"
    );
    // It cannot log in again with valid credentials...
    match login(
        &server,
        &client.email,
        &client.account.auth_key,
        CredentialKind::Password,
        device_b.device_id(),
    )
    .await
    {
        LoginOutcome::Server(status, body) => {
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"], "device_revoked");
        }
        _ => panic!("a revoked device must not log in"),
    }
    // ...and the revocation is visible to clients.
    let (_, list) = server.get("/v1/devices", Some(&token_a)).await;
    let list: DeviceList = serde_json::from_value(list).unwrap();
    let revoked: Vec<_> = list
        .devices
        .iter()
        .filter_map(|d| d.revocation.clone())
        .collect();
    assert_eq!(revoked.len(), 1);
    // Revoking twice is harmless.
    assert_eq!(
        server
            .post(&path, Some(&token_a), &json!({ "revocation": revocation }))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    server.cleanup().await;
}

#[tokio::test]
async fn invalid_revocations_are_refused() {
    let server = TestServer::default().await;
    let client = new_client("dave@example.com", "dave master password");
    let token = enrolled(&server, &client).await;
    let (device_b, _) = enroll_second_device(&server, &client).await;
    let path = format!("/v1/devices/{}/revoke", device_b.device_id());
    // Forged by another account.
    let mallory = new_client("m@example.com", "mallory master password");
    let mut forged = mallory
        .account
        .keys
        .revoke_device(device_b.device_id(), NOW)
        .unwrap();
    forged.account_id = client.account.keys.account_id();
    assert_eq!(
        server
            .post(&path, Some(&token), &json!({ "revocation": forged }))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    // Mismatched device.
    let other = client
        .account
        .keys
        .revoke_device(client.device.device_id(), NOW)
        .unwrap();
    assert_eq!(
        server
            .post(&path, Some(&token), &json!({ "revocation": other }))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    // Self-revocation.
    let self_path = format!("/v1/devices/{}/revoke", client.device.device_id());
    assert_eq!(
        server
            .post(&self_path, Some(&token), &json!({ "revocation": other }))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    // Unknown device.
    let ghost = DeviceIdentity::generate().unwrap();
    let ghost_rev = client
        .account
        .keys
        .revoke_device(ghost.device_id(), NOW)
        .unwrap();
    let ghost_path = format!("/v1/devices/{}/revoke", ghost.device_id());
    assert_eq!(
        server
            .post(
                &ghost_path,
                Some(&token),
                &json!({ "revocation": ghost_rev })
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    server.cleanup().await;
}

#[tokio::test]
async fn device_keys_cannot_be_replaced() {
    let server = TestServer::default().await;
    let client = new_client("erin@example.com", "erin master password");
    let token = enrolled(&server, &client).await;
    let impostor = DeviceIdentity::generate().unwrap();
    let mut info = impostor.public_info("same id", Platform::Cli, NOW).unwrap();
    info.device_id = client.device.device_id();
    let cert = client.account.keys.certify_device(info, NOW).unwrap();
    assert_eq!(
        server
            .post("/v1/devices", Some(&token), &json!({ "certificate": cert }))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    server.cleanup().await;
}
