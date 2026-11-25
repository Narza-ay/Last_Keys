//! Session authentication: `Authorization: Bearer <token>` → account and
//! device, with the device's revocation status checked on every request.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use lk_auth::SessionToken;
use lk_core::{AccountId, DeviceId};
use lk_protocol::SessionKind;
use sqlx::Row;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiError;

/// An authenticated session.
#[derive(Clone, Debug)]
pub(crate) struct Session {
    pub(crate) verifier: Vec<u8>,
    pub(crate) account_id: AccountId,
    pub(crate) device_id: DeviceId,
    pub(crate) kind: SessionKind,
}

pub(crate) const fn kind_str(kind: SessionKind) -> &'static str {
    match kind {
        SessionKind::Full => "full",
        SessionKind::Enrollment => "enrollment",
        SessionKind::Recovery => "recovery",
    }
}

fn parse_kind(s: &str) -> Option<SessionKind> {
    match s {
        "full" => Some(SessionKind::Full),
        "enrollment" => Some(SessionKind::Enrollment),
        "recovery" => Some(SessionKind::Recovery),
        _ => None,
    }
}

impl Session {
    /// Requires a full session (registered, non-revoked device).
    pub(crate) fn require_full(&self) -> Result<(), ApiError> {
        if self.kind == SessionKind::Full {
            Ok(())
        } else {
            Err(ApiError::forbidden(
                "this operation requires a fully enrolled device",
            ))
        }
    }
}

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(ApiError::unauthorized)?;
        let token_text = header
            .strip_prefix("Bearer ")
            .ok_or_else(ApiError::unauthorized)?;
        let token =
            SessionToken::from_text(token_text.trim()).map_err(|_| ApiError::unauthorized())?;
        let verifier = token.verifier().to_vec();

        let row = sqlx::query(
            "SELECT s.account_id, s.device_id, s.kind, s.expires_at, d.revoked_at
             FROM sessions s
             LEFT JOIN devices d ON d.id = s.device_id AND d.account_id = s.account_id
             WHERE s.verifier = $1",
        )
        .bind(&verifier)
        .fetch_optional(state.db())
        .await?
        .ok_or_else(ApiError::unauthorized)?;

        let expires_at: i64 = row.try_get("expires_at")?;
        let revoked_at: Option<i64> = row.try_get("revoked_at")?;
        if expires_at <= crate::now() || revoked_at.is_some() {
            sqlx::query("DELETE FROM sessions WHERE verifier = $1")
                .bind(&verifier)
                .execute(state.db())
                .await?;
            return Err(if revoked_at.is_some() {
                ApiError::device_revoked()
            } else {
                ApiError::unauthorized()
            });
        }
        let kind: String = row.try_get("kind")?;
        let account_id: Uuid = row.try_get("account_id")?;
        let device_id: Uuid = row.try_get("device_id")?;
        let session = Self {
            verifier,
            account_id: AccountId::from_uuid(account_id),
            device_id: DeviceId::from_uuid(device_id),
            kind: parse_kind(&kind).ok_or_else(ApiError::internal)?,
        };
        if session.kind == SessionKind::Full {
            sqlx::query("UPDATE devices SET last_seen_at = $1 WHERE id = $2")
                .bind(crate::now())
                .bind(device_id)
                .execute(state.db())
                .await?;
        }
        Ok(session)
    }
}

/// Reads a column into a typed row value (helper for handlers).
pub(crate) fn uuid_of(row: &sqlx::postgres::PgRow, column: &str) -> Result<Uuid, ApiError> {
    Ok(row.try_get::<Uuid, _>(column)?)
}
