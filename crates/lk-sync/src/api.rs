//! Typed client of the Last Keys API v1 (`lk-protocol`).

use core::fmt;

use lk_auth::{start_login, start_registration};
use lk_core::{
    AccountId, AccountKeyBundle, DeviceCertificate, DeviceId, DeviceRevocation, KdfConfig, VaultId,
    WrappedVaultKey,
};
use lk_crypto::{AuthKey, Zeroizing};
use lk_protocol::{
    CredentialFinishRequest, CredentialKind, CredentialStartRequest, CredentialStartResponse,
    DeviceList, ErrorBody, ErrorCode, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse, PreloginRequest, PreloginResponse, PullResponse, PushChange, PushRequest,
    PushResponse, RegisterDeviceRequest, RegisterFinishRequest, RegisterFinishResponse,
    RegisterStartRequest, RegisterStartResponse, RevokeDeviceRequest, SessionKind, VaultKeyList,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Result, SyncError};
use crate::transport::{Method, Transport};

/// An authenticated session (the token is zeroized on drop, never logged).
pub struct Session {
    token: Zeroizing<String>,
    /// Account of the session.
    pub account_id: AccountId,
    /// Scope of the session.
    pub kind: SessionKind,
}

impl Session {
    fn token(&self) -> &str {
        &self.token
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("account_id", &self.account_id)
            .field("kind", &self.kind)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// API client over a [`Transport`].
pub struct Api<T> {
    transport: T,
}

fn decode<R: DeserializeOwned>(body: &[u8]) -> Result<R> {
    serde_json::from_slice(body).map_err(|_| SyncError::Integrity("malformed server response"))
}

impl<T: Transport> Api<T> {
    /// Wraps a transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    fn raw<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&B>,
    ) -> Result<Vec<u8>> {
        let bytes = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| SyncError::Integrity("request serialization failed"))?;
        let response = self.transport.send(method, path, token, bytes.as_deref())?;
        if (200..300).contains(&response.status) {
            return Ok(response.body);
        }
        let error: Option<ErrorBody> = serde_json::from_slice(&response.body).ok();
        Err(match error.as_ref().map(|e| e.error) {
            Some(ErrorCode::InvalidCredentials) => SyncError::InvalidCredentials,
            Some(ErrorCode::DeviceRevoked) => SyncError::DeviceRevoked,
            code => SyncError::Server {
                status: response.status,
                code,
                message: error.map_or_else(|| "unexpected response".to_owned(), |e| e.message),
            },
        })
    }

    fn call<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&B>,
    ) -> Result<R> {
        decode(&self.raw(method, path, token, body)?)
    }

    /// Public KDF configuration of an account.
    ///
    /// # Errors
    /// Transport or server errors.
    pub fn prelogin(&self, email: &str) -> Result<KdfConfig> {
        let r: PreloginResponse = self.call(
            Method::Post,
            "/v1/accounts/prelogin",
            None,
            Some(&PreloginRequest {
                email: email.to_owned(),
            }),
        )?;
        Ok(r.kdf)
    }

    /// Registers an account (both OPAQUE credentials) with its first device.
    ///
    /// # Errors
    /// Transport, server (e.g. e-mail taken) or protocol errors.
    pub fn register(
        &self,
        email: &str,
        password_auth: &AuthKey,
        recovery_auth: &AuthKey,
        bundle: &AccountKeyBundle,
        certificate: &DeviceCertificate,
    ) -> Result<AccountId> {
        let (pflow, preq) = start_registration(password_auth)?;
        let (rflow, rreq) = start_registration(recovery_auth)?;
        let start: RegisterStartResponse = self.call(
            Method::Post,
            "/v1/accounts/register/start",
            None,
            Some(&RegisterStartRequest {
                email: email.to_owned(),
                password_request: preq.into(),
                recovery_request: rreq.into(),
            }),
        )?;
        let password_upload = pflow.finish(password_auth, start.password_response.as_slice())?;
        let recovery_upload = rflow.finish(recovery_auth, start.recovery_response.as_slice())?;
        let finish: RegisterFinishResponse = self.call(
            Method::Post,
            "/v1/accounts/register/finish",
            None,
            Some(&RegisterFinishRequest {
                email: email.to_owned(),
                password_upload: password_upload.into(),
                recovery_upload: recovery_upload.into(),
                bundle: bundle.clone(),
                device_certificate: certificate.clone(),
            }),
        )?;
        if finish.account_id != bundle.account_id {
            return Err(SyncError::Integrity("server returned another account id"));
        }
        Ok(finish.account_id)
    }

    /// Logs in with OPAQUE. The session token is derived locally and never
    /// received from the server.
    ///
    /// # Errors
    /// [`SyncError::InvalidCredentials`], [`SyncError::DeviceRevoked`],
    /// transport or server errors.
    pub fn login(
        &self,
        email: &str,
        auth: &AuthKey,
        credential: CredentialKind,
        device_id: DeviceId,
    ) -> Result<Session> {
        let (flow, request) = start_login(auth)?;
        let start: LoginStartResponse = self.call(
            Method::Post,
            "/v1/auth/login/start",
            None,
            Some(&LoginStartRequest {
                email: email.to_owned(),
                credential,
                device_id,
                request: request.into(),
            }),
        )?;
        let (finalization, token) = flow
            .finish(auth, start.response.as_slice())
            .map_err(|_| SyncError::InvalidCredentials)?;
        let finish: LoginFinishResponse = self.call(
            Method::Post,
            "/v1/auth/login/finish",
            None,
            Some(&LoginFinishRequest {
                login_id: start.login_id,
                finalization: finalization.into(),
            }),
        )?;
        Ok(Session {
            token: token.to_text(),
            account_id: finish.account_id,
            kind: finish.session,
        })
    }

    /// Ends a session.
    ///
    /// # Errors
    /// Transport or server errors.
    pub fn logout(&self, session: &Session) -> Result<()> {
        self.raw::<()>(Method::Post, "/v1/auth/logout", Some(session.token()), None)?;
        Ok(())
    }

    /// Downloads the account bundle.
    ///
    /// # Errors
    /// Transport or server errors.
    pub fn bundle(&self, session: &Session) -> Result<AccountKeyBundle> {
        let bundle: AccountKeyBundle = self.call::<(), _>(
            Method::Get,
            "/v1/account/bundle",
            Some(session.token()),
            None,
        )?;
        if bundle.account_id != session.account_id {
            return Err(SyncError::Integrity("bundle of another account"));
        }
        Ok(bundle)
    }

    /// Replaces a credential and the bundle (password change, password reset
    /// with the recovery key, recovery-key rotation).
    ///
    /// # Errors
    /// Transport, server or protocol errors.
    pub fn replace_credential(
        &self,
        session: &Session,
        credential: CredentialKind,
        auth: &AuthKey,
        bundle: &AccountKeyBundle,
    ) -> Result<()> {
        let (flow, request) = start_registration(auth)?;
        let start: CredentialStartResponse = self.call(
            Method::Post,
            "/v1/account/credentials/start",
            Some(session.token()),
            Some(&CredentialStartRequest {
                credential,
                request: request.into(),
            }),
        )?;
        let upload = flow.finish(auth, start.response.as_slice())?;
        self.raw(
            Method::Post,
            "/v1/account/credentials/finish",
            Some(session.token()),
            Some(&CredentialFinishRequest {
                credential,
                upload: upload.into(),
                bundle: bundle.clone(),
            }),
        )?;
        Ok(())
    }

    /// Registers a device certificate.
    ///
    /// # Errors
    /// Transport or server errors.
    pub fn register_device(
        &self,
        session: &Session,
        certificate: &DeviceCertificate,
    ) -> Result<()> {
        self.raw(
            Method::Post,
            "/v1/devices",
            Some(session.token()),
            Some(&RegisterDeviceRequest {
                certificate: certificate.clone(),
            }),
        )?;
        Ok(())
    }

    /// Lists the account's devices (to be verified with
    /// [`lk_core::trusted_devices`]).
    ///
    /// # Errors
    /// Transport or server errors.
    pub fn devices(&self, session: &Session) -> Result<DeviceList> {
        self.call::<(), _>(Method::Get, "/v1/devices", Some(session.token()), None)
    }

    /// Revokes a device.
    ///
    /// # Errors
    /// Transport or server errors.
    pub fn revoke(&self, session: &Session, revocation: &DeviceRevocation) -> Result<()> {
        self.raw(
            Method::Post,
            &format!("/v1/devices/{}/revoke", revocation.device_id),
            Some(session.token()),
            Some(&RevokeDeviceRequest {
                revocation: revocation.clone(),
            }),
        )?;
        Ok(())
    }

    /// Lists the wrapped vault keys.
    ///
    /// # Errors
    /// Transport or server errors.
    pub fn vault_keys(&self, session: &Session) -> Result<Vec<WrappedVaultKey>> {
        let list: VaultKeyList =
            self.call::<(), _>(Method::Get, "/v1/vaults", Some(session.token()), None)?;
        if list
            .vaults
            .iter()
            .any(|v| v.account_id != session.account_id)
        {
            return Err(SyncError::Integrity("vault key of another account"));
        }
        Ok(list.vaults)
    }

    /// Stores a wrapped vault key.
    ///
    /// # Errors
    /// Transport or server errors.
    pub fn put_vault_key(&self, session: &Session, wrapped: &WrappedVaultKey) -> Result<()> {
        self.raw(
            Method::Put,
            &format!("/v1/vaults/{}/key", wrapped.vault_id),
            Some(session.token()),
            Some(wrapped),
        )?;
        Ok(())
    }

    /// Pushes changes.
    ///
    /// # Errors
    /// Transport or server errors; [`SyncError::Integrity`] if the response
    /// does not have one outcome per change.
    pub fn push(
        &self,
        session: &Session,
        vault: &VaultId,
        changes: Vec<PushChange>,
    ) -> Result<PushResponse> {
        let count = changes.len();
        let response: PushResponse = self.call(
            Method::Post,
            &format!("/v1/vaults/{vault}/changes"),
            Some(session.token()),
            Some(&PushRequest { changes }),
        )?;
        if response.results.len() != count {
            return Err(SyncError::Integrity("push response size mismatch"));
        }
        Ok(response)
    }

    /// Pulls states after `since`.
    ///
    /// # Errors
    /// Transport or server errors.
    pub fn pull(&self, session: &Session, vault: &VaultId, since: u64) -> Result<PullResponse> {
        self.call::<(), _>(
            Method::Get,
            &format!("/v1/vaults/{vault}/changes?since={since}"),
            Some(session.token()),
            None,
        )
    }
}
