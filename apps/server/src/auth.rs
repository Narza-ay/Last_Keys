//! Pre-login, registration and OPAQUE login (ADR-0005).

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use hkdf::Hkdf;
use lk_auth::{
    PasswordFile, ServerLoginState, login_finish as opaque_login_finish,
    login_start as opaque_login_start, normalize_email, password_credential_id,
    recovery_credential_id, registration_finish, registration_response,
};
use lk_core::{AccountId, AccountKeyBundle, Bytes, KdfConfig};
use lk_crypto::KdfParams;
use lk_protocol::{
    CredentialKind, ErrorCode, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse, PreloginRequest, PreloginResponse, RegisterFinishRequest,
    RegisterFinishResponse, RegisterStartRequest, RegisterStartResponse, SessionKind,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::types::Json as DbJson;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::session::{Session, kind_str, uuid_of};
use crate::{AppState, ClientAddr, client_ip, now};

fn email_or_400(email: &str) -> ApiResult<String> {
    normalize_email(email).map_err(|_| ApiError::bad_request("invalid e-mail address"))
}

fn email_key(email: &str) -> String {
    data_encoding::HEXLOWER.encode(
        Sha256::digest(email.as_bytes())
            .get(..12)
            .unwrap_or_default(),
    )
}

const fn credential_str(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::Password => "password",
        CredentialKind::Recovery => "recovery",
    }
}

fn credential_id(kind: CredentialKind, email: &str) -> ApiResult<Vec<u8>> {
    match kind {
        CredentialKind::Password => password_credential_id(email),
        CredentialKind::Recovery => recovery_credential_id(email),
    }
    .map_err(|_| ApiError::bad_request("invalid e-mail address"))
}

/// Deterministic fake KDF configuration for unknown e-mails (no enumeration).
fn fake_kdf(state: &AppState, email: &str) -> ApiResult<KdfConfig> {
    let mut salt = [0u8; 16];
    Hkdf::<Sha256>::new(None, state.prelogin_key())
        .expand(
            &[b"lastkeys/v1/server/fake-salt/", email.as_bytes()].concat(),
            &mut salt,
        )
        .map_err(|_| ApiError::internal())?;
    let p = KdfParams::recommended();
    Ok(KdfConfig {
        algorithm: p.algorithm.id(),
        memory_kib: p.memory_kib,
        iterations: p.iterations,
        parallelism: p.parallelism,
        salt: Bytes::from(salt),
    })
}

pub(crate) async fn prelogin(
    State(state): State<AppState>,
    headers: HeaderMap,
    addr: ClientAddr,
    Json(req): Json<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    let email = email_or_400(&req.email)?;
    let ip = client_ip(&state, &headers, &addr);
    state.check_rate(&[
        format!("prelogin:ip:{ip}"),
        format!("prelogin:email:{}", email_key(&email)),
    ])?;
    let row = sqlx::query("SELECT bundle FROM accounts WHERE email = $1")
        .bind(&email)
        .fetch_optional(state.db())
        .await?;
    let kdf = match row {
        Some(row) => {
            let DbJson(bundle): DbJson<AccountKeyBundle> = row.try_get("bundle")?;
            bundle.kdf
        }
        None => fake_kdf(&state, &email)?,
    };
    Ok(Json(PreloginResponse { kdf }))
}

pub(crate) async fn register_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    addr: ClientAddr,
    Json(req): Json<RegisterStartRequest>,
) -> ApiResult<Json<RegisterStartResponse>> {
    if !state.config().allow_registration {
        return Err(registration_closed());
    }
    let email = email_or_400(&req.email)?;
    let ip = client_ip(&state, &headers, &addr);
    state.check_rate(&[format!("register:ip:{ip}")])?;
    let password_response = registration_response(
        state.secret(),
        req.password_request.as_slice(),
        &credential_id(CredentialKind::Password, &email)?,
    )
    .map_err(|_| ApiError::bad_request("malformed registration request"))?;
    let recovery_response = registration_response(
        state.secret(),
        req.recovery_request.as_slice(),
        &credential_id(CredentialKind::Recovery, &email)?,
    )
    .map_err(|_| ApiError::bad_request("malformed registration request"))?;
    Ok(Json(RegisterStartResponse {
        password_response: password_response.into(),
        recovery_response: recovery_response.into(),
    }))
}

fn registration_closed() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        ErrorCode::RegistrationClosed,
        "registration is closed on this server",
    )
}

/// Structural validation of a bundle received from a client: the server
/// cannot decrypt it, but refuses anything malformed or below the KDF floor.
pub(crate) fn validate_bundle(bundle: &AccountKeyBundle) -> ApiResult<[u8; 32]> {
    if bundle.format_version != lk_core::ACCOUNT_BUNDLE_VERSION {
        return Err(ApiError::bad_request("unsupported bundle version"));
    }
    bundle
        .kdf
        .params()
        .map_err(|_| ApiError::bad_request("KDF parameters below the accepted floor"))?;
    bundle
        .kdf
        .salt()
        .map_err(|_| ApiError::bad_request("invalid KDF salt"))?;
    let signing = bundle
        .signing_public_key()
        .map_err(|_| ApiError::bad_request("invalid account signing key"))?;
    bundle
        .encryption_public_key()
        .map_err(|_| ApiError::bad_request("invalid account encryption key"))?;
    for envelope in [
        &bundle.account_key_by_password,
        &bundle.signing_private_key,
        &bundle.encryption_private_key,
    ]
    .into_iter()
    .chain(bundle.account_key_by_recovery.as_ref())
    {
        lk_crypto::Envelope::from_bytes(envelope.as_slice())
            .map_err(|_| ApiError::bad_request("malformed envelope in bundle"))?;
    }
    Ok(signing.to_bytes())
}

pub(crate) async fn register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    addr: ClientAddr,
    Json(req): Json<RegisterFinishRequest>,
) -> ApiResult<Json<RegisterFinishResponse>> {
    if !state.config().allow_registration {
        return Err(registration_closed());
    }
    let email = email_or_400(&req.email)?;
    let ip = client_ip(&state, &headers, &addr);
    state.check_rate(&[format!("register:ip:{ip}")])?;
    let password_file = registration_finish(req.password_upload.as_slice())
        .map_err(|_| ApiError::bad_request("malformed registration upload"))?;
    let recovery_file = registration_finish(req.recovery_upload.as_slice())
        .map_err(|_| ApiError::bad_request("malformed registration upload"))?;
    let signing_key = validate_bundle(&req.bundle)?;
    let account_id = req.bundle.account_id;
    let cert = &req.device_certificate;
    cert.verify(
        &account_id,
        &req.bundle
            .signing_public_key()
            .map_err(|_| ApiError::bad_request("invalid account signing key"))?,
    )
    .map_err(|_| ApiError::bad_request("device certificate is not signed by this account"))?;

    let now = now();
    let mut tx = state.db().begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO accounts (id, email, bundle, signing_public_key, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)
         ON CONFLICT DO NOTHING",
    )
    .bind(account_id.as_uuid())
    .bind(&email)
    .bind(DbJson(&req.bundle))
    .bind(signing_key.as_slice())
    .bind(now)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::EmailTaken,
            "this e-mail address is already registered",
        ));
    }
    for (kind, file) in [("password", &password_file), ("recovery", &recovery_file)] {
        sqlx::query(
            "INSERT INTO credentials (account_id, kind, password_file, updated_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(account_id.as_uuid())
        .bind(kind)
        .bind(file.as_bytes())
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("INSERT INTO account_seq (account_id, last_seq) VALUES ($1, 0)")
        .bind(account_id.as_uuid())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO devices (id, account_id, certificate, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(cert.device.device_id.as_uuid())
    .bind(account_id.as_uuid())
    .bind(DbJson(cert))
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(account = %account_id, "account registered");
    Ok(Json(RegisterFinishResponse { account_id }))
}

pub(crate) async fn login_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    addr: ClientAddr,
    Json(req): Json<LoginStartRequest>,
) -> ApiResult<Json<LoginStartResponse>> {
    let email = email_or_400(&req.email)?;
    let ip = client_ip(&state, &headers, &addr);
    state.check_rate(&[
        format!("login:ip:{ip}"),
        format!("login:email:{}", email_key(&email)),
    ])?;
    let cid = credential_id(req.credential, &email)?;
    let row = sqlx::query(
        "SELECT a.id, c.password_file FROM accounts a
         JOIN credentials c ON c.account_id = a.id AND c.kind = $2
         WHERE a.email = $1",
    )
    .bind(&email)
    .bind(credential_str(req.credential))
    .fetch_optional(state.db())
    .await?;
    let (account_id, file) = match row {
        Some(row) => {
            let bytes: Vec<u8> = row.try_get("password_file")?;
            let file = PasswordFile::from_bytes(&bytes).map_err(|_| ApiError::internal())?;
            (Some(uuid_of(&row, "id")?), Some(file))
        }
        None => (None, None),
    };
    let (login_state, response) =
        opaque_login_start(state.secret(), file.as_ref(), req.request.as_slice(), &cid)
            .map_err(|_| ApiError::bad_request("malformed login request"))?;
    let login_id =
        Uuid::from_bytes(lk_crypto::rng::random_array().map_err(|_| ApiError::internal())?);
    let now = now();
    sqlx::query("DELETE FROM login_attempts WHERE expires_at < $1")
        .bind(now)
        .execute(state.db())
        .await?;
    sqlx::query(
        "INSERT INTO login_attempts (id, account_id, device_id, credential, state, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(login_id)
    .bind(account_id)
    .bind(req.device_id.as_uuid())
    .bind(credential_str(req.credential))
    .bind(login_state.as_bytes())
    .bind(now.saturating_add(state.config().login_attempt_ttl_secs))
    .execute(state.db())
    .await?;
    Ok(Json(LoginStartResponse {
        login_id,
        response: response.into(),
    }))
}

pub(crate) async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishRequest>,
) -> ApiResult<Json<LoginFinishResponse>> {
    // Single use: the attempt is deleted whatever the outcome.
    let row = sqlx::query(
        "DELETE FROM login_attempts WHERE id = $1
         RETURNING account_id, device_id, credential, state, expires_at",
    )
    .bind(req.login_id)
    .fetch_optional(state.db())
    .await?
    .ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Expired,
            "unknown or expired login attempt",
        )
    })?;
    let expires_at: i64 = row.try_get("expires_at")?;
    // Same rule as sessions: invalid from the expiry instant on.
    if expires_at <= now() {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Expired,
            "login attempt expired",
        ));
    }
    let state_bytes: Vec<u8> = row.try_get("state")?;
    let token = opaque_login_finish(
        &ServerLoginState::from_bytes(&state_bytes),
        req.finalization.as_slice(),
    )
    .map_err(|_| ApiError::invalid_credentials())?;
    let account_id: Option<Uuid> = row.try_get("account_id")?;
    let account_id = account_id.ok_or_else(ApiError::invalid_credentials)?;
    let device_id = uuid_of(&row, "device_id")?;
    let credential: String = row.try_get("credential")?;

    let device = sqlx::query("SELECT revoked_at FROM devices WHERE id = $1 AND account_id = $2")
        .bind(device_id)
        .bind(account_id)
        .fetch_optional(state.db())
        .await?;
    let device_revoked = match &device {
        Some(row) => row.try_get::<Option<i64>, _>("revoked_at")?.is_some(),
        None => false,
    };
    if device_revoked {
        return Err(ApiError::device_revoked());
    }
    let kind = if credential == "recovery" {
        SessionKind::Recovery
    } else if device.is_some() {
        SessionKind::Full
    } else {
        SessionKind::Enrollment
    };
    let now = now();
    let expires_at = now.saturating_add(state.config().session_ttl_secs);
    sqlx::query("DELETE FROM sessions WHERE expires_at < $1")
        .bind(now)
        .execute(state.db())
        .await?;
    sqlx::query(
        "INSERT INTO sessions (verifier, account_id, device_id, kind, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(token.verifier().as_slice())
    .bind(account_id)
    .bind(device_id)
    .bind(kind_str(kind))
    .bind(now)
    .bind(expires_at)
    .execute(state.db())
    .await?;
    tracing::info!(account = %account_id, device = %device_id, session = kind_str(kind), "login");
    Ok(Json(LoginFinishResponse {
        account_id: AccountId::from_uuid(account_id),
        session: kind,
        expires_at_unix: u64::try_from(expires_at).unwrap_or(0),
    }))
}

#[derive(Serialize)]
pub(crate) struct SessionInfo {
    account_id: AccountId,
    device_id: lk_core::DeviceId,
    session: SessionKind,
}

pub(crate) async fn current_session(session: Session) -> Json<SessionInfo> {
    Json(SessionInfo {
        account_id: session.account_id,
        device_id: session.device_id,
        session: session.kind,
    })
}

pub(crate) async fn logout(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM sessions WHERE verifier = $1")
        .bind(&session.verifier)
        .execute(state.db())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
