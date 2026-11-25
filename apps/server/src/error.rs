//! API errors: stable codes, HTTP statuses, no secrets in messages.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use lk_protocol::{ErrorBody, ErrorCode};

/// An error returned to the client.
#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: ErrorCode,
    message: String,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::BadRequest, message)
    }

    pub(crate) fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "missing or invalid session",
        )
    }

    pub(crate) fn invalid_credentials() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::InvalidCredentials,
            "authentication failed",
        )
    }

    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, ErrorCode::Forbidden, message)
    }

    pub(crate) fn device_revoked() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            ErrorCode::DeviceRevoked,
            "this device has been revoked",
        )
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, message)
    }

    pub(crate) fn rate_limited() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RateLimited,
            "too many requests, retry later",
        )
    }

    pub(crate) fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            "internal error",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        // Queries only ever bind parameters, so the error carries no data.
        tracing::error!(error = %e, "database error");
        Self::internal()
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        tracing::error!(error = %e, "stored record could not be decoded");
        Self::internal()
    }
}

pub(crate) type ApiResult<T> = Result<T, ApiError>;
