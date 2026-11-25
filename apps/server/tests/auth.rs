//! Accounts, OPAQUE login and sessions against a real PostgreSQL database.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use axum::http::StatusCode;
use common::*;
use lk_core::{DeviceIdentity, PasswordKeys};
use lk_crypto::{KdfParams, MasterPassword};
use lk_protocol::{CredentialKind, PreloginResponse, SessionKind};
use lk_server::Config;
use serde_json::json;

#[tokio::test]
async fn health_reports_database_ok() {
    let server = TestServer::default().await;
    let (status, body) = server.get("/v1/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    server.cleanup().await;
}

#[tokio::test]
async fn register_and_login_on_the_registering_device() {
    let server = TestServer::default().await;
    let client = new_client("Alice@Example.com", "correct horse battery staple");
    let (status, body) = register(&server, &client).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["account_id"],
        client.account.keys.account_id().to_string()
    );

    let (token, response) = login_ok(&server, &client).await;
    assert_eq!(response.session, SessionKind::Full);
    let (status, session) = server.get("/v1/auth/session", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["session"], "full");
    assert_eq!(session["device_id"], client.device.device_id().to_string());

    // The server stores only the token's hash.
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("SELECT verifier FROM sessions")
        .fetch_all(&server.pool)
        .await
        .unwrap();
    assert_eq!(stored, vec![token_verifier(&token).to_vec()]);
    server.cleanup().await;
}

#[tokio::test]
async fn new_device_logs_in_from_prelogin_and_gets_an_enrollment_session() {
    let server = TestServer::default().await;
    let client = new_client("bob@example.com", "a long master password");
    assert_eq!(register(&server, &client).await.0, StatusCode::OK);

    // A brand-new device knows only the e-mail and the password.
    let (status, body) = server
        .post(
            "/v1/accounts/prelogin",
            None,
            &json!({ "email": "BOB@example.com " }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let prelogin: PreloginResponse = serde_json::from_value(body).unwrap();
    assert_eq!(prelogin.kdf, client.account.bundle.kdf);
    let keys = PasswordKeys::derive(
        &MasterPassword::new("a long master password").unwrap(),
        &prelogin.kdf,
    )
    .unwrap();
    let new_device = DeviceIdentity::generate().unwrap();
    match login(
        &server,
        "bob@example.com",
        keys.auth_key(),
        CredentialKind::Password,
        new_device.device_id(),
    )
    .await
    {
        LoginOutcome::Ok { response, .. } => assert_eq!(response.session, SessionKind::Enrollment),
        _ => panic!("login from a new device must succeed with an enrollment session"),
    }
    server.cleanup().await;
}

#[tokio::test]
async fn wrong_password_unknown_account_and_forged_finalization_fail() {
    let server = TestServer::default().await;
    let client = new_client("carol@example.com", "the right password");
    assert_eq!(register(&server, &client).await.0, StatusCode::OK);
    let device = client.device.device_id();

    // Wrong key: the client detects it; the server never issues a session.
    let wrong = lk_crypto::RecoveryKey::generate()
        .unwrap()
        .server_auth_key()
        .unwrap();
    assert!(matches!(
        login(
            &server,
            &client.email,
            &wrong,
            CredentialKind::Password,
            device
        )
        .await,
        LoginOutcome::ClientRejected
    ));
    // Unknown account: same behaviour, response of the same length.
    assert!(matches!(
        login(
            &server,
            "nobody@example.com",
            &wrong,
            CredentialKind::Password,
            device
        )
        .await,
        LoginOutcome::ClientRejected
    ));
    // A forged finalization is refused by the server.
    let (_, request) = lk_auth::start_login(&wrong).unwrap();
    let (_, start) = server
        .post(
            "/v1/auth/login/start",
            None,
            &json!({ "email": client.email, "credential": "password", "device_id": device, "request": b64(&request) }),
        )
        .await;
    let (status, body) = server
        .post(
            "/v1/auth/login/finish",
            None,
            &json!({ "login_id": start["login_id"], "finalization": b64(&[0u8; 64]) }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        body["error"] == "invalid_credentials"
            || body["error"] == "bad_request"
            || body["error"] == "unauthorized",
        "{body}"
    );
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0);
    server.cleanup().await;
}

#[tokio::test]
async fn prelogin_does_not_reveal_unknown_accounts() {
    let server = TestServer::default().await;
    let (s1, a) = server
        .post(
            "/v1/accounts/prelogin",
            None,
            &json!({ "email": "ghost@example.com" }),
        )
        .await;
    let (s2, b) = server
        .post(
            "/v1/accounts/prelogin",
            None,
            &json!({ "email": "ghost@example.com" }),
        )
        .await;
    let (_, c) = server
        .post(
            "/v1/accounts/prelogin",
            None,
            &json!({ "email": "other@example.com" }),
        )
        .await;
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
    assert_eq!(a, b, "fake configuration must be deterministic");
    assert_ne!(
        a["kdf"]["salt"], c["kdf"]["salt"],
        "fake salts must differ per e-mail"
    );
    let kdf: lk_core::KdfConfig = serde_json::from_value(a["kdf"].clone()).unwrap();
    assert_eq!(kdf.params().unwrap(), KdfParams::recommended());
    server.cleanup().await;
}

#[tokio::test]
async fn duplicate_email_and_closed_registration() {
    let server = TestServer::default().await;
    let first = new_client("dave@example.com", "first password!");
    assert_eq!(register(&server, &first).await.0, StatusCode::OK);
    let second = new_client("DAVE@example.com", "second password!");
    let (status, body) = register(&server, &second).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "email_taken");
    server.cleanup().await;

    let closed = TestServer::start(Config {
        allow_registration: false,
        ..Config::default()
    })
    .await;
    let (status, body) = register(&closed, &new_client("erin@example.com", "some password")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "registration_closed");
    closed.cleanup().await;
}

#[tokio::test]
async fn hostile_registrations_are_refused() {
    let server = TestServer::default().await;
    // Certificate signed by another account.
    let mut client = new_client("frank@example.com", "frank's password");
    let other = new_client("x@example.com", "other password");
    client.certificate = other
        .account
        .keys
        .certify_device(
            client
                .device
                .public_info("d", lk_core::Platform::Cli, NOW)
                .unwrap(),
            NOW,
        )
        .unwrap();
    let (status, body) = register(&server, &client).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Bundle with KDF parameters below the floor.
    let mut weak = new_client("grace@example.com", "grace's password");
    weak.account.bundle.kdf.memory_kib = 1024;
    let (status, body) = register(&server, &weak).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "bad_request");

    // Nothing was stored.
    let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM accounts")
        .fetch_one(&server.pool)
        .await
        .unwrap();
    assert_eq!(accounts, 0);
    server.cleanup().await;
}

#[tokio::test]
async fn login_attempts_are_single_use_and_expire() {
    let server = TestServer::start(Config {
        login_attempt_ttl_secs: 0,
        ..Config::default()
    })
    .await;
    let client = new_client("heidi@example.com", "heidi's password");
    assert_eq!(register(&server, &client).await.0, StatusCode::OK);
    // TTL 0: the attempt is already expired when finishing.
    match login(
        &server,
        &client.email,
        &client.account.auth_key,
        CredentialKind::Password,
        client.device.device_id(),
    )
    .await
    {
        LoginOutcome::Server(status, body) => {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["error"], "expired");
        }
        _ => panic!("expired attempt must be refused"),
    }
    server.cleanup().await;

    let server = TestServer::default().await;
    assert_eq!(register(&server, &client).await.0, StatusCode::OK);
    let (flow, request) = lk_auth::start_login(&client.account.auth_key).unwrap();
    let (_, start) = server
        .post(
            "/v1/auth/login/start",
            None,
            &json!({ "email": client.email, "credential": "password", "device_id": client.device.device_id(), "request": b64(&request) }),
        )
        .await;
    let (finalization, _) = flow
        .finish(&client.account.auth_key, &unb64(&start["response"]))
        .unwrap();
    let body = json!({ "login_id": start["login_id"], "finalization": b64(&finalization) });
    assert_eq!(
        server.post("/v1/auth/login/finish", None, &body).await.0,
        StatusCode::OK
    );
    let (status, replay) = server.post("/v1/auth/login/finish", None, &body).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "replayed finalization must fail"
    );
    assert_eq!(replay["error"], "expired");
    server.cleanup().await;
}

#[tokio::test]
async fn recovery_credential_gives_a_recovery_session() {
    let server = TestServer::default().await;
    let client = new_client("ivan@example.com", "ivan's password");
    assert_eq!(register(&server, &client).await.0, StatusCode::OK);
    match login(
        &server,
        &client.email,
        &client.account.recovery_auth_key,
        CredentialKind::Recovery,
        client.device.device_id(),
    )
    .await
    {
        LoginOutcome::Ok { response, .. } => assert_eq!(response.session, SessionKind::Recovery),
        _ => panic!("recovery login must succeed"),
    }
    // The password key does not work on the recovery credential.
    assert!(matches!(
        login(
            &server,
            &client.email,
            &client.account.auth_key,
            CredentialKind::Recovery,
            client.device.device_id()
        )
        .await,
        LoginOutcome::ClientRejected
    ));
    server.cleanup().await;
}

#[tokio::test]
async fn sessions_require_a_valid_token_and_end_at_logout() {
    let server = TestServer::default().await;
    assert_eq!(
        server.get("/v1/auth/session", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server.get("/v1/auth/session", Some("not-a-token")).await.0,
        StatusCode::UNAUTHORIZED
    );
    let forged = lk_auth::SessionToken::from_text(&b64(&[9u8; 32])).unwrap();
    assert_eq!(
        server
            .get("/v1/auth/session", Some(&forged.to_text()))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    let client = new_client("judy@example.com", "judy's password");
    assert_eq!(register(&server, &client).await.0, StatusCode::OK);
    let (token, _) = login_ok(&server, &client).await;
    assert_eq!(
        server.get("/v1/auth/session", Some(&token)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        server
            .post("/v1/auth/logout", Some(&token), &json!({}))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        server.get("/v1/auth/session", Some(&token)).await.0,
        StatusCode::UNAUTHORIZED
    );
    server.cleanup().await;
}

#[tokio::test]
async fn authentication_endpoints_are_rate_limited() {
    let server = TestServer::start(Config {
        auth_rate_limit_per_minute: 3,
        ..Config::default()
    })
    .await;
    let body = json!({ "email": "mallory@example.com" });
    for _ in 0..3 {
        assert_eq!(
            server.post("/v1/accounts/prelogin", None, &body).await.0,
            StatusCode::OK
        );
    }
    let (status, response) = server.post("/v1/accounts/prelogin", None, &body).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response["error"], "rate_limited");
    server.cleanup().await;
}

#[tokio::test]
async fn malformed_requests_are_rejected() {
    let server = TestServer::default().await;
    let (status, _) = server
        .post(
            "/v1/accounts/prelogin",
            None,
            &json!({ "email": "not-an-email" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = server
        .post("/v1/accounts/prelogin", None, &json!({ "unexpected": 1 }))
        .await;
    assert!(status.is_client_error());
    let (status, _) = server
        .post(
            "/v1/auth/login/start",
            None,
            &json!({ "email": "a@b.c", "credential": "password", "device_id": DeviceIdentity::generate().unwrap().device_id(), "request": b64(b"junk") }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    server.cleanup().await;
}
