//! # lk-protocol
//!
//! Request and response types of the Last Keys HTTP API, version 1, shared by
//! the server and every client. All binary values (OPAQUE messages,
//! envelopes, keys, signatures) are [`Bytes`] (unpadded Base64url in JSON).
//! Field names are part of the protocol: renaming one is a breaking change
//! that requires `/v2`.
//!
//! Authentication follows ADR-0005 (OPAQUE); synchronization follows ADR-0008.

#![forbid(unsafe_code)]

use lk_core::{
    AccountId, AccountKeyBundle, Bytes, ChangeId, DeviceCertificate, DeviceId, DeviceRevocation,
    EncryptedItem, ItemId, KdfConfig, VaultId, WrappedVaultKey,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Path prefix of this API version.
pub const API_PREFIX: &str = "/v1";

// -------------------------------------------------------------------- errors

/// Stable machine-readable error codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The request is malformed or fails validation.
    BadRequest,
    /// Missing, invalid or expired session.
    Unauthorized,
    /// Authentication failed (wrong credentials or unknown account).
    InvalidCredentials,
    /// The session is not allowed to perform this operation.
    Forbidden,
    /// The device has been revoked.
    DeviceRevoked,
    /// The resource does not exist.
    NotFound,
    /// The e-mail address is already registered.
    EmailTaken,
    /// The server does not accept new registrations.
    RegistrationClosed,
    /// Too many requests; retry later.
    RateLimited,
    /// The request body is too large.
    PayloadTooLarge,
    /// A login attempt or other short-lived object expired.
    Expired,
    /// Unexpected server error (details are only in server logs).
    Internal,
}

/// Body of every error response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Machine-readable code.
    pub error: ErrorCode,
    /// Human-readable description (never contains secrets).
    pub message: String,
}

// ------------------------------------------------------------------- health

/// `GET /v1/health`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// `"ok"` when the server and its database are reachable.
    pub status: String,
    /// Server version.
    pub version: String,
}

// ------------------------------------------------------------ registration

/// `POST /v1/accounts/prelogin`: public KDF configuration of an account.
/// Unknown e-mails receive a deterministic fake configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreloginRequest {
    /// Account e-mail.
    pub email: String,
}

/// Response to [`PreloginRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreloginResponse {
    /// KDF configuration to derive the password keys.
    pub kdf: KdfConfig,
}

/// `POST /v1/accounts/register/start`: first OPAQUE registration message for
/// the password and recovery credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterStartRequest {
    /// Account e-mail.
    pub email: String,
    /// OPAQUE registration request (password credential).
    pub password_request: Bytes,
    /// OPAQUE registration request (recovery credential).
    pub recovery_request: Bytes,
}

/// Response to [`RegisterStartRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    /// OPAQUE registration response (password credential).
    pub password_response: Bytes,
    /// OPAQUE registration response (recovery credential).
    pub recovery_response: Bytes,
}

/// `POST /v1/accounts/register/finish`: creates the account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterFinishRequest {
    /// Account e-mail.
    pub email: String,
    /// OPAQUE registration upload (password credential).
    pub password_upload: Bytes,
    /// OPAQUE registration upload (recovery credential).
    pub recovery_upload: Bytes,
    /// Encrypted account key bundle.
    pub bundle: AccountKeyBundle,
    /// Certificate of the registering device, signed by the account key.
    pub device_certificate: DeviceCertificate,
}

/// Response to [`RegisterFinishRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterFinishResponse {
    /// Identifier of the new account.
    pub account_id: AccountId,
}

// -------------------------------------------------------------------- login

/// Which OPAQUE credential is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// Master-password credential.
    Password,
    /// Recovery-key credential.
    Recovery,
}

/// `POST /v1/auth/login/start`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStartRequest {
    /// Account e-mail.
    pub email: String,
    /// Credential used.
    pub credential: CredentialKind,
    /// Device the session will be bound to.
    pub device_id: DeviceId,
    /// OPAQUE credential request.
    pub request: Bytes,
}

/// Response to [`LoginStartRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// Identifier of this login attempt (single use, short-lived).
    pub login_id: Uuid,
    /// OPAQUE credential response.
    pub response: Bytes,
}

/// `POST /v1/auth/login/finish`. On success the client already holds the
/// session token (derived from OPAQUE, ADR-0005); it is never sent here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginFinishRequest {
    /// Login attempt identifier.
    pub login_id: Uuid,
    /// OPAQUE credential finalization.
    pub finalization: Bytes,
}

/// What a session may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    /// Registered, non-revoked device: full access.
    Full,
    /// Device not yet certified: may only fetch the bundle and register its
    /// own certificate.
    Enrollment,
    /// Logged in with the recovery key: may fetch the bundle and replace the
    /// password credential.
    Recovery,
}

/// Response to [`LoginFinishRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginFinishResponse {
    /// Account identifier.
    pub account_id: AccountId,
    /// Session scope.
    pub session: SessionKind,
    /// Session expiry (Unix seconds).
    pub expires_at_unix: u64,
}

// ------------------------------------------------------- account management

/// `POST /v1/account/credentials/start` (two-step credential replacement,
/// e.g. after a password change or a recovery-key rotation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialStartRequest {
    /// Credential being replaced.
    pub credential: CredentialKind,
    /// OPAQUE registration request.
    pub request: Bytes,
}

/// Response to [`CredentialStartRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialStartResponse {
    /// OPAQUE registration response.
    pub response: Bytes,
}

/// `POST /v1/account/credentials/finish`: replaces the credential and the
/// account bundle atomically. The bundle must keep the account identity
/// (same account id and public keys).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialFinishRequest {
    /// Credential being replaced.
    pub credential: CredentialKind,
    /// OPAQUE registration upload.
    pub upload: Bytes,
    /// Re-wrapped account key bundle.
    pub bundle: AccountKeyBundle,
}

// ------------------------------------------------------------------ devices

/// `POST /v1/devices`: registers (or activates) a certified device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    /// Certificate signed by the account key.
    pub certificate: DeviceCertificate,
}

/// One device as listed by `GET /v1/devices`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntry {
    /// Account-signed certificate.
    pub certificate: DeviceCertificate,
    /// Account-signed revocation, if revoked.
    pub revocation: Option<DeviceRevocation>,
    /// Last authenticated request (Unix seconds).
    pub last_seen_unix: Option<u64>,
}

/// `GET /v1/devices`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceList {
    /// Every device ever registered on the account.
    pub devices: Vec<DeviceEntry>,
}

/// `POST /v1/devices/{device_id}/revoke`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeDeviceRequest {
    /// Revocation signed by the account key.
    pub revocation: DeviceRevocation,
}

// ------------------------------------------------------------------- vaults

/// `GET /v1/vaults`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyList {
    /// Wrapped vault keys of the account.
    pub vaults: Vec<WrappedVaultKey>,
}

/// One change pushed by a client (ADR-0008).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushChange {
    /// Idempotency key.
    pub change_id: ChangeId,
    /// Item concerned.
    pub item_id: ItemId,
    /// Server revision the client last saw (0 for a new item).
    pub base_revision: u64,
    /// New content; `None` deletes the item.
    pub item: Option<EncryptedItem>,
}

/// `POST /v1/vaults/{vault_id}/changes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
    /// Changes, applied in order.
    pub changes: Vec<PushChange>,
}

/// Current server state of an item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemState {
    /// Item identifier.
    pub item_id: ItemId,
    /// Server revision.
    pub revision: u64,
    /// Account sequence number of the change that produced this state.
    pub seq: u64,
    /// Content; `None` for a tombstone.
    pub item: Option<EncryptedItem>,
}

/// Outcome of one pushed change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PushOutcome {
    /// Applied; the item now has this state.
    Accepted {
        /// New state.
        state: ItemState,
    },
    /// Not applied: the server revision differs from `base_revision`.
    Conflict {
        /// Current server state, to merge with.
        current: ItemState,
    },
}

/// Response to [`PushRequest`]: one outcome per change, in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
    /// Outcomes.
    pub results: Vec<PushOutcome>,
}

/// Response to `GET /v1/vaults/{vault_id}/changes?since=…&limit=…`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullResponse {
    /// States with `seq > since`, in `seq` order.
    pub items: Vec<ItemState>,
    /// Cursor for the next pull.
    pub next_since: u64,
    /// Whether more states remain.
    pub more: bool,
    /// Latest `seq` of the account when the pull was served (never lower
    /// than the `seq` of a returned state). A client whose cursor is ahead of
    /// it is talking to a server whose data went back in time.
    pub head: u64,
    /// Identifier of the server's history. It changes when the operator
    /// restores a backup; clients then refuse to synchronize until the user
    /// asks for a full resynchronization (ADR-0008, "Restore").
    pub history: Uuid,
}

/// Identifier type re-exported for convenience.
pub type VaultIdentifier = VaultId;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_snake_case() {
        let body = ErrorBody {
            error: ErrorCode::DeviceRevoked,
            message: "x".into(),
        };
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"error":"device_revoked","message":"x"}"#
        );
    }

    #[test]
    fn push_outcome_is_tagged() {
        let state = ItemState {
            item_id: ItemId::generate().unwrap(),
            revision: 2,
            seq: 7,
            item: None,
        };
        let json = serde_json::to_string(&PushOutcome::Conflict {
            current: state.clone(),
        })
        .unwrap();
        assert!(json.starts_with(r#"{"outcome":"conflict""#));
        let back: PushOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, PushOutcome::Conflict { current: state });
    }
}
