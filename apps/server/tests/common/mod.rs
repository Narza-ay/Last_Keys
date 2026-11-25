//! Test harness: a fresh PostgreSQL database per test, the real router, and a
//! simulated client built from the real client crates (lk-core, lk-auth).

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use lk_auth::{SessionToken, start_login, start_registration};
use lk_core::{DeviceCertificate, DeviceIdentity, NewAccount, Platform, create_account};
use lk_crypto::{AuthKey, KdfParams, MasterPassword};
use lk_protocol::{CredentialKind, LoginFinishResponse};
use lk_server::{AppState, Config};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

pub const NOW: u64 = 1_764_000_000;

pub struct TestServer {
    pub router: Router,
    pub pool: PgPool,
    db_name: String,
    admin_url: String,
}

fn base_url() -> String {
    std::env::var("LK_TEST_DATABASE_URL").expect(
        "LK_TEST_DATABASE_URL must point to a PostgreSQL database with CREATEDB rights \
         (e.g. postgres://lastkeys:lastkeys-dev@127.0.0.1/postgres)",
    )
}

impl TestServer {
    pub async fn start(config: Config) -> Self {
        let admin_url = base_url();
        let admin = PgPool::connect(&admin_url).await.unwrap();
        let suffix = data_encoding::HEXLOWER.encode(&lk_crypto::rng::random_array::<8>().unwrap());
        let db_name = format!("lk_test_{suffix}");
        // `db_name` is generated here from hexadecimal random bytes only.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db_name}")))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
        let (prefix, _) = admin_url.rsplit_once('/').unwrap();
        let url = format!("{prefix}/{db_name}");
        let pool = lk_server::connect_and_migrate(&url).await.unwrap();
        let state = AppState::new(pool.clone(), lk_auth::ServerSecret::generate(), config).unwrap();
        Self {
            router: lk_server::router(state),
            pool,
            db_name,
            admin_url,
        }
    }

    pub async fn default() -> Self {
        Self::start(Config::default()).await
    }

    pub async fn cleanup(self) {
        self.pool.close().await;
        let admin = PgPool::connect(&self.admin_url).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {} WITH (FORCE)",
            self.db_name
        )))
        .execute(&admin)
        .await
        .unwrap();
        admin.close().await;
    }

    pub async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(t) = token {
            builder = builder.header("authorization", format!("Bearer {t}"));
        }
        let request = match body {
            Some(b) => builder
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&b).unwrap()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 << 20)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    pub async fn post<T: Serialize>(
        &self,
        path: &str,
        token: Option<&str>,
        body: &T,
    ) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            path,
            token,
            Some(serde_json::to_value(body).unwrap()),
        )
        .await
    }

    pub async fn get(&self, path: &str, token: Option<&str>) -> (StatusCode, Value) {
        self.call(Method::GET, path, token, None).await
    }
}

/// A client-side account, built exactly as a real client does.
pub struct ClientAccount {
    pub email: String,
    pub password: String,
    pub account: NewAccount,
    pub device: DeviceIdentity,
    pub certificate: DeviceCertificate,
}

pub fn new_client(email: &str, password: &str) -> ClientAccount {
    let account = create_account(
        &MasterPassword::new(password).unwrap(),
        KdfParams::recommended(),
    )
    .unwrap();
    let device = DeviceIdentity::generate().unwrap();
    let info = device
        .public_info("test device", Platform::Cli, NOW)
        .unwrap();
    let certificate = account.keys.certify_device(info, NOW).unwrap();
    ClientAccount {
        email: email.to_owned(),
        password: password.to_owned(),
        account,
        device,
        certificate,
    }
}

pub async fn register(server: &TestServer, client: &ClientAccount) -> (StatusCode, Value) {
    let (pflow, preq) = start_registration(&client.account.auth_key).unwrap();
    let (rflow, rreq) = start_registration(&client.account.recovery_auth_key).unwrap();
    let (status, start) = server
        .post(
            "/v1/accounts/register/start",
            None,
            &json!({ "email": client.email, "password_request": b64(&preq), "recovery_request": b64(&rreq) }),
        )
        .await;
    if status != StatusCode::OK {
        return (status, start);
    }
    let pupload = pflow
        .finish(
            &client.account.auth_key,
            &unb64(&start["password_response"]),
        )
        .unwrap();
    let rupload = rflow
        .finish(
            &client.account.recovery_auth_key,
            &unb64(&start["recovery_response"]),
        )
        .unwrap();
    server
        .post(
            "/v1/accounts/register/finish",
            None,
            &json!({
                "email": client.email,
                "password_upload": b64(&pupload),
                "recovery_upload": b64(&rupload),
                "bundle": client.account.bundle,
                "device_certificate": client.certificate,
            }),
        )
        .await
}

pub enum LoginOutcome {
    Ok {
        token: String,
        response: LoginFinishResponse,
    },
    ClientRejected,
    Server(StatusCode, Value),
}

pub async fn login(
    server: &TestServer,
    email: &str,
    key: &AuthKey,
    credential: CredentialKind,
    device_id: lk_core::DeviceId,
) -> LoginOutcome {
    let (flow, request) = start_login(key).unwrap();
    let (status, start) = server
        .post(
            "/v1/auth/login/start",
            None,
            &json!({ "email": email, "credential": credential, "device_id": device_id, "request": b64(&request) }),
        )
        .await;
    if status != StatusCode::OK {
        return LoginOutcome::Server(status, start);
    }
    let Ok((finalization, token)) = flow.finish(key, &unb64(&start["response"])) else {
        return LoginOutcome::ClientRejected;
    };
    let (status, body) = server
        .post(
            "/v1/auth/login/finish",
            None,
            &json!({ "login_id": start["login_id"], "finalization": b64(&finalization) }),
        )
        .await;
    if status != StatusCode::OK {
        return LoginOutcome::Server(status, body);
    }
    LoginOutcome::Ok {
        token: token.to_text().to_string(),
        response: serde_json::from_value(body).unwrap(),
    }
}

pub async fn login_ok(
    server: &TestServer,
    client: &ClientAccount,
) -> (String, LoginFinishResponse) {
    match login(
        server,
        &client.email,
        &client.account.auth_key,
        CredentialKind::Password,
        client.device.device_id(),
    )
    .await
    {
        LoginOutcome::Ok { token, response } => (token, response),
        LoginOutcome::ClientRejected => panic!("client rejected the login"),
        LoginOutcome::Server(s, b) => panic!("server rejected the login: {s} {b}"),
    }
}

pub fn b64(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

pub fn unb64(v: &Value) -> Vec<u8> {
    data_encoding::BASE64URL_NOPAD
        .decode(v.as_str().unwrap().as_bytes())
        .unwrap()
}

pub fn token_verifier(token: &str) -> [u8; 32] {
    SessionToken::from_text(token).unwrap().verifier()
}

/// Registers the client and logs in from its registering device.
pub async fn enrolled(server: &TestServer, client: &ClientAccount) -> String {
    let (status, body) = register(server, client).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    login_ok(server, client).await.0
}

/// Creates a vault on the client and uploads its wrapped key.
pub async fn create_vault(
    server: &TestServer,
    client: &ClientAccount,
    token: &str,
) -> lk_core::VaultKey {
    let (vault, wrapped) = client.account.keys.create_vault().unwrap();
    let (status, body) = server
        .call(
            Method::PUT,
            &format!("/v1/vaults/{}/key", vault.vault_id()),
            Some(token),
            Some(serde_json::to_value(&wrapped).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    vault
}

/// One change in the wire format.
pub fn change(
    item_id: lk_core::ItemId,
    base_revision: u64,
    item: Option<&lk_core::EncryptedItem>,
) -> Value {
    json!({
        "change_id": lk_core::ChangeId::generate().unwrap(),
        "item_id": item_id,
        "base_revision": base_revision,
        "item": item,
    })
}

pub async fn push(
    server: &TestServer,
    token: &str,
    vault: &lk_core::VaultId,
    changes: Vec<Value>,
) -> (StatusCode, Value) {
    server
        .post(
            &format!("/v1/vaults/{vault}/changes"),
            Some(token),
            &json!({ "changes": changes }),
        )
        .await
}

impl TestServer {
    /// Serves the same router over real TCP on 127.0.0.1 (random port), for
    /// clients using the real HTTP transport. Returns the base URL.
    pub async fn serve_http(&self) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = self.router.clone();
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        format!("http://{addr}")
    }
}
