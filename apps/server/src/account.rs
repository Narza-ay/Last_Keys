//! Account bundle, credential replacement, devices and revocation.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use lk_auth::{
    password_credential_id, recovery_credential_id, registration_finish, registration_response,
};
use lk_core::{AccountKeyBundle, DeviceCertificate, DeviceId, DeviceRevocation};
use lk_crypto::VerifyingKey;
use lk_protocol::{
    CredentialFinishRequest, CredentialKind, CredentialStartRequest, CredentialStartResponse,
    DeviceEntry, DeviceList, RegisterDeviceRequest, RevokeDeviceRequest, SessionKind,
};
use sqlx::Row;
use sqlx::types::Json as DbJson;
use uuid::Uuid;

use crate::auth::validate_bundle;
use crate::error::{ApiError, ApiResult};
use crate::session::Session;
use crate::{AppState, now};

pub(crate) async fn load_bundle(
    state: &AppState,
    account: &Uuid,
) -> ApiResult<(String, AccountKeyBundle)> {
    let row = sqlx::query("SELECT email, bundle FROM accounts WHERE id = $1")
        .bind(account)
        .fetch_optional(state.db())
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    let DbJson(bundle): DbJson<AccountKeyBundle> = row.try_get("bundle")?;
    Ok((row.try_get("email")?, bundle))
}

async fn account_signing_key(state: &AppState, account: &Uuid) -> ApiResult<VerifyingKey> {
    let (_, bundle) = load_bundle(state, account).await?;
    bundle
        .signing_public_key()
        .map_err(|_| ApiError::internal())
}

/// `GET /v1/account/bundle` — any session (enrollment and recovery sessions
/// need it to unlock).
pub(crate) async fn get_bundle(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<AccountKeyBundle>> {
    let (_, bundle) = load_bundle(&state, session.account_id.as_uuid()).await?;
    Ok(Json(bundle))
}

fn check_credential_permission(session: &Session, credential: CredentialKind) -> ApiResult<()> {
    match (session.kind, credential) {
        (SessionKind::Full, _) | (SessionKind::Recovery, CredentialKind::Password) => Ok(()),
        _ => Err(ApiError::forbidden(
            "this session cannot replace this credential",
        )),
    }
}

fn credential_id(kind: CredentialKind, email: &str) -> ApiResult<Vec<u8>> {
    match kind {
        CredentialKind::Password => password_credential_id(email),
        CredentialKind::Recovery => recovery_credential_id(email),
    }
    .map_err(|_| ApiError::internal())
}

/// `POST /v1/account/credentials/start`.
pub(crate) async fn credential_start(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<CredentialStartRequest>,
) -> ApiResult<Json<CredentialStartResponse>> {
    check_credential_permission(&session, req.credential)?;
    let (email, _) = load_bundle(&state, session.account_id.as_uuid()).await?;
    let response = registration_response(
        state.secret(),
        req.request.as_slice(),
        &credential_id(req.credential, &email)?,
    )
    .map_err(|_| ApiError::bad_request("malformed registration request"))?;
    Ok(Json(CredentialStartResponse {
        response: response.into(),
    }))
}

/// `POST /v1/account/credentials/finish`: replaces one credential and the
/// bundle atomically. The account identity (id, public keys) must not change.
/// After a recovery (password reset), every session of the account ends.
pub(crate) async fn credential_finish(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<CredentialFinishRequest>,
) -> ApiResult<StatusCode> {
    check_credential_permission(&session, req.credential)?;
    let account = *session.account_id.as_uuid();
    let file = registration_finish(req.upload.as_slice())
        .map_err(|_| ApiError::bad_request("malformed registration upload"))?;
    validate_bundle(&req.bundle)?;
    let (_, current) = load_bundle(&state, &account).await?;
    if req.bundle.account_id != current.account_id
        || req.bundle.signing_public_key != current.signing_public_key
        || req.bundle.encryption_public_key != current.encryption_public_key
    {
        return Err(ApiError::bad_request(
            "the bundle must keep the account identity",
        ));
    }
    let kind = match req.credential {
        CredentialKind::Password => "password",
        CredentialKind::Recovery => "recovery",
    };
    let now = now();
    let mut tx = state.db().begin().await?;
    sqlx::query("UPDATE credentials SET password_file = $1, updated_at = $2 WHERE account_id = $3 AND kind = $4")
        .bind(file.as_bytes())
        .bind(now)
        .bind(account)
        .bind(kind)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE accounts SET bundle = $1, updated_at = $2 WHERE id = $3")
        .bind(DbJson(&req.bundle))
        .bind(now)
        .bind(account)
        .execute(&mut *tx)
        .await?;
    if session.kind == SessionKind::Recovery {
        sqlx::query("DELETE FROM sessions WHERE account_id = $1")
            .bind(account)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    tracing::info!(account = %account, credential = kind, "credential replaced");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/devices`: registers a device certified by the account key.
/// An enrollment session may only register its own device, and is upgraded
/// to a full session on success. A revoked device can never re-register.
pub(crate) async fn register_device(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<RegisterDeviceRequest>,
) -> ApiResult<StatusCode> {
    let cert: DeviceCertificate = req.certificate;
    let device_id = *cert.device.device_id.as_uuid();
    match session.kind {
        SessionKind::Full => {}
        SessionKind::Enrollment if cert.device.device_id == session.device_id => {}
        _ => {
            return Err(ApiError::forbidden(
                "this session cannot register this device",
            ));
        }
    }
    let account = *session.account_id.as_uuid();
    let signing = account_signing_key(&state, &account).await?;
    cert.verify(&session.account_id, &signing)
        .map_err(|_| ApiError::bad_request("device certificate is not signed by this account"))?;

    let mut tx = state.db().begin().await?;
    let existing = sqlx::query(
        "SELECT account_id, certificate, revoked_at FROM devices WHERE id = $1 FOR UPDATE",
    )
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = existing {
        let owner: Uuid = row.try_get("account_id")?;
        let revoked_at: Option<i64> = row.try_get("revoked_at")?;
        let DbJson(stored): DbJson<DeviceCertificate> = row.try_get("certificate")?;
        if owner != account {
            return Err(ApiError::bad_request("device identifier already in use"));
        }
        if revoked_at.is_some() {
            return Err(ApiError::device_revoked());
        }
        if stored.device.signing_public_key != cert.device.signing_public_key
            || stored.device.encryption_public_key != cert.device.encryption_public_key
        {
            return Err(ApiError::bad_request("device keys cannot change"));
        }
    } else {
        sqlx::query(
            "INSERT INTO devices (id, account_id, certificate, created_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(device_id)
        .bind(account)
        .bind(DbJson(&cert))
        .bind(now())
        .execute(&mut *tx)
        .await?;
    }
    if session.kind == SessionKind::Enrollment {
        sqlx::query("UPDATE sessions SET kind = 'full' WHERE verifier = $1")
            .bind(&session.verifier)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    tracing::info!(account = %account, device = %device_id, "device registered");
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/devices`.
pub(crate) async fn list_devices(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<DeviceList>> {
    session.require_full()?;
    let rows = sqlx::query("SELECT certificate, revocation, last_seen_at FROM devices WHERE account_id = $1 ORDER BY created_at, id")
        .bind(session.account_id.as_uuid())
        .fetch_all(state.db())
        .await?;
    let mut devices = Vec::with_capacity(rows.len());
    for row in rows {
        let DbJson(certificate): DbJson<DeviceCertificate> = row.try_get("certificate")?;
        let revocation: Option<DbJson<DeviceRevocation>> = row.try_get("revocation")?;
        let last_seen: Option<i64> = row.try_get("last_seen_at")?;
        devices.push(DeviceEntry {
            certificate,
            revocation: revocation.map(|DbJson(r)| r),
            last_seen_unix: last_seen.and_then(|t| u64::try_from(t).ok()),
        });
    }
    Ok(Json(DeviceList { devices }))
}

/// `POST /v1/devices/{device_id}/revoke`: records an account-signed
/// revocation and immediately ends every session of that device.
pub(crate) async fn revoke_device(
    State(state): State<AppState>,
    session: Session,
    Path(device_id): Path<Uuid>,
    Json(req): Json<RevokeDeviceRequest>,
) -> ApiResult<StatusCode> {
    session.require_full()?;
    let revocation = req.revocation;
    let target = DeviceId::from_uuid(device_id);
    if revocation.device_id != target {
        return Err(ApiError::bad_request(
            "revocation does not match the device",
        ));
    }
    if target == session.device_id {
        return Err(ApiError::bad_request(
            "a device cannot revoke itself; log out instead",
        ));
    }
    let account = *session.account_id.as_uuid();
    let signing = account_signing_key(&state, &account).await?;
    revocation
        .verify(&session.account_id, &signing)
        .map_err(|_| ApiError::bad_request("revocation is not signed by this account"))?;
    let mut tx = state.db().begin().await?;
    let updated = sqlx::query(
        "UPDATE devices SET revocation = $1, revoked_at = $2
         WHERE id = $3 AND account_id = $4 AND revoked_at IS NULL",
    )
    .bind(DbJson(&revocation))
    .bind(now())
    .bind(device_id)
    .bind(account)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM devices WHERE id = $1 AND account_id = $2")
                .bind(device_id)
                .bind(account)
                .fetch_optional(&mut *tx)
                .await?;
        if exists.is_none() {
            return Err(ApiError::not_found("no such device"));
        }
    }
    sqlx::query("DELETE FROM sessions WHERE device_id = $1 AND account_id = $2")
        .bind(device_id)
        .bind(account)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!(account = %account, device = %device_id, "device revoked");
    Ok(StatusCode::NO_CONTENT)
}
