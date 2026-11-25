//! # lk-server
//!
//! Last Keys synchronization server (ADR-0009). It stores only ciphertext
//! produced by clients, authenticates with OPAQUE (ADR-0005) and never holds
//! a key that decrypts vault data.

#![forbid(unsafe_code)]

mod account;
mod auth;
pub mod config;
mod error;
mod ratelimit;
mod session;
mod sync;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use hkdf::Hkdf;
use lk_auth::ServerSecret;
use lk_protocol::HealthResponse;
use sha2::Sha256;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower_http::trace::TraceLayer;

pub use crate::config::Config;
use crate::error::{ApiError, ApiResult};
use crate::ratelimit::RateLimiter;

/// Embedded, forward-only database migrations.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Maximum body size of authentication and account requests.
const SMALL_BODY_LIMIT: usize = 256 * 1024;
/// Maximum body size of a push (500 changes of bounded size would exceed it;
/// clients split large pushes).
const PUSH_BODY_LIMIT: usize = 32 * 1024 * 1024;

/// Shared server state.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    db: PgPool,
    secret: ServerSecret,
    prelogin_key: [u8; 32],
    config: Config,
    auth_limiter: RateLimiter,
}

impl AppState {
    /// Builds the state from a database pool, the OPAQUE server secret and
    /// the configuration.
    ///
    /// # Errors
    /// Fails only if key derivation fails (not expected).
    pub fn new(db: PgPool, secret: ServerSecret, config: Config) -> Result<Self, String> {
        let mut prelogin_key = [0u8; 32];
        Hkdf::<Sha256>::new(None, &secret.to_bytes())
            .expand(b"lastkeys/v1/server/prelogin-key", &mut prelogin_key)
            .map_err(|_| "prelogin key derivation failed".to_owned())?;
        let auth_limiter =
            RateLimiter::new(config.auth_rate_limit_per_minute, Duration::from_secs(60));
        Ok(Self {
            inner: Arc::new(Inner {
                db,
                secret,
                prelogin_key,
                config,
                auth_limiter,
            }),
        })
    }

    pub(crate) fn db(&self) -> &PgPool {
        &self.inner.db
    }

    pub(crate) fn secret(&self) -> &ServerSecret {
        &self.inner.secret
    }

    pub(crate) fn config(&self) -> &Config {
        &self.inner.config
    }

    pub(crate) fn prelogin_key(&self) -> &[u8; 32] {
        &self.inner.prelogin_key
    }

    /// Applies the authentication rate limit to every given key.
    pub(crate) fn check_rate(&self, keys: &[String]) -> ApiResult<()> {
        // Every key is charged, even after one is over its limit (no
        // short-circuit), so an attacker cannot spare one window by
        // exhausting another.
        let mut allowed = true;
        for key in keys {
            if !self.inner.auth_limiter.allow(key) {
                allowed = false;
            }
        }
        if allowed {
            Ok(())
        } else {
            Err(ApiError::rate_limited())
        }
    }
}

/// Connects to PostgreSQL and applies pending migrations.
///
/// # Errors
/// Connection or migration errors.
pub async fn connect_and_migrate(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await?;
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}

/// Current Unix time in seconds.
pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The peer address, when the server runs with connection info (absent in
/// in-process tests).
pub(crate) struct ClientAddr(Option<SocketAddr>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ClientAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0),
        ))
    }
}

/// Best-effort client address for rate limiting.
pub(crate) fn client_ip(state: &AppState, headers: &HeaderMap, addr: &ClientAddr) -> String {
    if state.config().trust_proxy_headers
        && let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
    {
        return forwarded.trim().to_owned();
    }
    addr.0
        .map_or_else(|| "unknown".to_owned(), |a| a.ip().to_string())
}

async fn health(State(state): State<AppState>) -> ApiResult<axum::Json<HealthResponse>> {
    sqlx::query("SELECT 1").execute(state.db()).await?;
    Ok(axum::Json(HealthResponse {
        status: "ok".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    }))
}

/// Builds the HTTP router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/accounts/prelogin", post(auth::prelogin))
        .route("/v1/accounts/register/start", post(auth::register_start))
        .route("/v1/accounts/register/finish", post(auth::register_finish))
        .route("/v1/auth/login/start", post(auth::login_start))
        .route("/v1/auth/login/finish", post(auth::login_finish))
        .route("/v1/auth/session", get(auth::current_session))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/account/bundle", get(account::get_bundle))
        .route(
            "/v1/account/credentials/start",
            post(account::credential_start),
        )
        .route(
            "/v1/account/credentials/finish",
            post(account::credential_finish),
        )
        .route(
            "/v1/devices",
            get(account::list_devices).post(account::register_device),
        )
        .route(
            "/v1/devices/{device_id}/revoke",
            post(account::revoke_device),
        )
        .route("/v1/vaults", get(sync::list_vault_keys))
        .route(
            "/v1/vaults/{vault_id}/key",
            axum::routing::put(sync::put_vault_key),
        )
        .route(
            "/v1/vaults/{vault_id}/changes",
            post(sync::push)
                .get(sync::pull)
                .layer(DefaultBodyLimit::max(PUSH_BODY_LIMIT)),
        )
        .layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
