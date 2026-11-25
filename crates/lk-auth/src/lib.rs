//! # lk-auth
//!
//! Server authentication for Last Keys with OPAQUE (RFC 9807), as decided in
//! ADR-0005:
//!
//! * the password input is the HKDF-derived [`AuthKey`] (already stretched by
//!   Argon2id on the client), so OPAQUE uses the identity stretching function;
//! * the server stores a [`PasswordFile`] per credential, from which no
//!   password or login secret can be derived without one Argon2id per guess;
//! * after a successful login, client and server both derive the same
//!   [`SessionToken`] from the OPAQUE session key; the token is never sent in
//!   the login exchange and the server stores only its [`SessionToken::verifier`].
//!
//! Cipher suite: OPRF over Ristretto255, 3DH over Ristretto255 with SHA-512.
//!
//! Randomness comes from the operating system. If the OS generator fails,
//! the underlying library aborts (fail-closed); it cannot return an error.

#![forbid(unsafe_code)]

use core::fmt;

use hkdf::Hkdf;
use lk_crypto::{AuthKey, Zeroizing};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand_core_legacy::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The OPAQUE cipher suite of Last Keys (ADR-0005).
#[derive(Debug, Clone, Copy)]
pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_legacy::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

/// Errors returned by `lk-auth`. They never contain secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// A protocol message or stored record could not be decoded.
    #[error("malformed authentication message")]
    Malformed,
    /// The credentials are wrong (or the account does not exist — the two
    /// cases are indistinguishable by design).
    #[error("authentication failed")]
    InvalidCredentials,
    /// The e-mail address is not acceptable as an identifier.
    #[error("invalid e-mail address")]
    InvalidEmail,
    /// Internal derivation failure (not expected).
    #[error("authentication protocol error")]
    Protocol,
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, AuthError>;

// ------------------------------------------------------------------ identity

/// Maximum length of an e-mail address (RFC 5321 path limit).
pub const MAX_EMAIL_LEN: usize = 254;

/// Normalizes an e-mail address for use as an account identifier: trimmed and
/// lower-cased, with a minimal shape check (one `@`, non-empty local and
/// domain parts, no whitespace or control characters). Deliverability is
/// verified by the server's confirmation flow, not here.
///
/// # Errors
/// [`AuthError::InvalidEmail`].
pub fn normalize_email(email: &str) -> Result<String> {
    let normalized = email.trim().to_lowercase();
    let valid = normalized.len() <= MAX_EMAIL_LEN
        && !normalized
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        && matches!(
            normalized.split_once('@'),
            Some((local, domain)) if !local.is_empty() && !domain.is_empty() && !domain.contains('@')
        );
    if valid {
        Ok(normalized)
    } else {
        Err(AuthError::InvalidEmail)
    }
}

/// OPAQUE credential identifier of the master-password credential.
///
/// # Errors
/// [`AuthError::InvalidEmail`].
pub fn password_credential_id(email: &str) -> Result<Vec<u8>> {
    Ok(normalize_email(email)?.into_bytes())
}

/// OPAQUE credential identifier of the recovery-key credential.
///
/// # Errors
/// [`AuthError::InvalidEmail`].
pub fn recovery_credential_id(email: &str) -> Result<Vec<u8>> {
    Ok(format!("recovery:{}", normalize_email(email)?).into_bytes())
}

// ------------------------------------------------------------------- secrets

/// The server's long-term OPAQUE secret (OPRF seed and key pair). Kept outside
/// the database (ADR-0005). Zeroized when serialized; redacted from `Debug`.
pub struct ServerSecret(ServerSetup<Suite>);

impl ServerSecret {
    /// Generates a new server secret.
    #[must_use]
    pub fn generate() -> Self {
        Self(ServerSetup::<Suite>::new(&mut OsRng))
    }

    /// Serializes the secret for storage in a protected file.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.serialize().to_vec())
    }

    /// Restores a serialized secret.
    ///
    /// # Errors
    /// [`AuthError::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ServerSetup::<Suite>::deserialize(bytes)
            .map(Self)
            .map_err(|_| AuthError::Malformed)
    }
}

impl fmt::Debug for ServerSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerSecret(<redacted>)")
    }
}

/// What the server stores for one credential (OPAQUE registration record).
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordFile(Vec<u8>);

impl PasswordFile {
    /// Serialized form for the database.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Restores a stored record, validating its structure.
    ///
    /// # Errors
    /// [`AuthError::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ServerRegistration::<Suite>::deserialize(bytes).map_err(|_| AuthError::Malformed)?;
        Ok(Self(bytes.to_vec()))
    }

    fn decode(&self) -> Result<ServerRegistration<Suite>> {
        ServerRegistration::<Suite>::deserialize(&self.0).map_err(|_| AuthError::Malformed)
    }
}

impl fmt::Debug for PasswordFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PasswordFile(len={})", self.0.len())
    }
}

/// Server-side state between the two login messages. Contains secrets: it
/// must be kept on the server (never sent to the client) and expire quickly.
pub struct ServerLoginState(Zeroizing<Vec<u8>>);

impl ServerLoginState {
    /// Serialized form, for short-lived server-side storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Restores a stored state.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }
}

impl fmt::Debug for ServerLoginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerLoginState(<redacted>)")
    }
}

// ------------------------------------------------------------- session token

const TOKEN_LABEL: &[u8] = b"lastkeys/v1/session-token";
const TOKEN_LEN: usize = 32;

/// A session token derived by both parties from the OPAQUE session key.
pub struct SessionToken(Zeroizing<[u8; TOKEN_LEN]>);

impl SessionToken {
    fn derive(session_key: &[u8]) -> Result<Self> {
        let mut out = Zeroizing::new([0u8; TOKEN_LEN]);
        Hkdf::<Sha256>::new(None, session_key)
            .expand(TOKEN_LABEL, out.as_mut())
            .map_err(|_| AuthError::Protocol)?;
        Ok(Self(out))
    }

    /// Text form sent by the client as a bearer token (unpadded Base64url).
    #[must_use]
    pub fn to_text(&self) -> Zeroizing<String> {
        Zeroizing::new(data_encoding::BASE64URL_NOPAD.encode(self.0.as_slice()))
    }

    /// Parses the text form.
    ///
    /// # Errors
    /// [`AuthError::Malformed`].
    pub fn from_text(text: &str) -> Result<Self> {
        let bytes = Zeroizing::new(
            data_encoding::BASE64URL_NOPAD
                .decode(text.as_bytes())
                .map_err(|_| AuthError::Malformed)?,
        );
        let array: [u8; TOKEN_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::Malformed)?;
        Ok(Self(Zeroizing::new(array)))
    }

    /// The value the server stores and looks up: `SHA-256(token)`.
    #[must_use]
    pub fn verifier(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_slice()).into()
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

// --------------------------------------------------------------------- client

/// Client side of a registration in progress.
pub struct ClientRegistrationFlow(ClientRegistration<Suite>);

impl fmt::Debug for ClientRegistrationFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientRegistrationFlow(<redacted>)")
    }
}

/// Starts registering `auth_key`; returns the state and the request to send.
///
/// # Errors
/// [`AuthError::Protocol`] (not expected).
pub fn start_registration(auth_key: &AuthKey) -> Result<(ClientRegistrationFlow, Vec<u8>)> {
    let start = ClientRegistration::<Suite>::start(&mut OsRng, auth_key.expose_secret())
        .map_err(|_| AuthError::Protocol)?;
    Ok((
        ClientRegistrationFlow(start.state),
        start.message.serialize().to_vec(),
    ))
}

impl ClientRegistrationFlow {
    /// Completes the registration with the server's response; returns the
    /// upload to send.
    ///
    /// # Errors
    /// [`AuthError::Malformed`] or [`AuthError::Protocol`].
    pub fn finish(self, auth_key: &AuthKey, response: &[u8]) -> Result<Vec<u8>> {
        let response = RegistrationResponse::<Suite>::deserialize(response)
            .map_err(|_| AuthError::Malformed)?;
        let finish = self
            .0
            .finish(
                &mut OsRng,
                auth_key.expose_secret(),
                response,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(|_| AuthError::Protocol)?;
        Ok(finish.message.serialize().to_vec())
    }
}

/// Client side of a login in progress.
pub struct ClientLoginFlow(ClientLogin<Suite>);

impl fmt::Debug for ClientLoginFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientLoginFlow(<redacted>)")
    }
}

/// Starts a login with `auth_key`; returns the state and the request to send.
///
/// # Errors
/// [`AuthError::Protocol`] (not expected).
pub fn start_login(auth_key: &AuthKey) -> Result<(ClientLoginFlow, Vec<u8>)> {
    let start = ClientLogin::<Suite>::start(&mut OsRng, auth_key.expose_secret())
        .map_err(|_| AuthError::Protocol)?;
    Ok((
        ClientLoginFlow(start.state),
        start.message.serialize().to_vec(),
    ))
}

impl ClientLoginFlow {
    /// Completes the login with the server's response. Returns the
    /// finalization message to send and the session token.
    ///
    /// # Errors
    /// [`AuthError::InvalidCredentials`] for a wrong key or an unknown
    /// account; [`AuthError::Malformed`] for a malformed response.
    pub fn finish(self, auth_key: &AuthKey, response: &[u8]) -> Result<(Vec<u8>, SessionToken)> {
        let response =
            CredentialResponse::<Suite>::deserialize(response).map_err(|_| AuthError::Malformed)?;
        let finish = self
            .0
            .finish(
                &mut OsRng,
                auth_key.expose_secret(),
                response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|_| AuthError::InvalidCredentials)?;
        let token = SessionToken::derive(finish.session_key.as_slice())?;
        Ok((finish.message.serialize().to_vec(), token))
    }
}

// --------------------------------------------------------------------- server

/// Answers a registration request for `credential_id`.
///
/// # Errors
/// [`AuthError::Malformed`] or [`AuthError::Protocol`].
pub fn registration_response(
    secret: &ServerSecret,
    request: &[u8],
    credential_id: &[u8],
) -> Result<Vec<u8>> {
    let request =
        RegistrationRequest::<Suite>::deserialize(request).map_err(|_| AuthError::Malformed)?;
    let start = ServerRegistration::<Suite>::start(&secret.0, request, credential_id)
        .map_err(|_| AuthError::Protocol)?;
    Ok(start.message.serialize().to_vec())
}

/// Turns the client's registration upload into the record to store.
///
/// # Errors
/// [`AuthError::Malformed`].
pub fn registration_finish(upload: &[u8]) -> Result<PasswordFile> {
    let upload =
        RegistrationUpload::<Suite>::deserialize(upload).map_err(|_| AuthError::Malformed)?;
    Ok(PasswordFile(
        ServerRegistration::<Suite>::finish(upload)
            .serialize()
            .to_vec(),
    ))
}

/// Answers a login request. Pass `None` as `password_file` for an unknown
/// account: the response is then a fake, indistinguishable from a real one,
/// and the login fails at the client.
///
/// # Errors
/// [`AuthError::Malformed`] or [`AuthError::Protocol`].
pub fn login_start(
    secret: &ServerSecret,
    password_file: Option<&PasswordFile>,
    request: &[u8],
    credential_id: &[u8],
) -> Result<(ServerLoginState, Vec<u8>)> {
    let request =
        CredentialRequest::<Suite>::deserialize(request).map_err(|_| AuthError::Malformed)?;
    let record = password_file.map(PasswordFile::decode).transpose()?;
    let start = ServerLogin::start(
        &mut OsRng,
        &secret.0,
        record,
        request,
        credential_id,
        ServerLoginParameters::default(),
    )
    .map_err(|_| AuthError::Protocol)?;
    Ok((
        ServerLoginState(Zeroizing::new(start.state.serialize().to_vec())),
        start.message.serialize().to_vec(),
    ))
}

/// Verifies the client's finalization and derives the session token.
///
/// # Errors
/// [`AuthError::InvalidCredentials`] if the client did not prove knowledge of
/// the key; [`AuthError::Malformed`] for malformed input.
pub fn login_finish(state: &ServerLoginState, finalization: &[u8]) -> Result<SessionToken> {
    let state = ServerLogin::<Suite>::deserialize(&state.0).map_err(|_| AuthError::Malformed)?;
    let finalization = CredentialFinalization::<Suite>::deserialize(finalization)
        .map_err(|_| AuthError::Malformed)?;
    let finish = state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|_| AuthError::InvalidCredentials)?;
    SessionToken::derive(finish.session_key.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalization() {
        assert_eq!(
            normalize_email("  Alice@Example.COM ").unwrap(),
            "alice@example.com"
        );
        for bad in [
            "",
            "alice",
            "@example.com",
            "alice@",
            "a b@example.com",
            "a@b@c",
            "a@ex\u{0}.com",
        ] {
            assert_eq!(
                normalize_email(bad),
                Err(AuthError::InvalidEmail),
                "{bad:?}"
            );
        }
        let long = format!("{}@example.com", "a".repeat(250));
        assert_eq!(normalize_email(&long), Err(AuthError::InvalidEmail));
        assert_eq!(recovery_credential_id("A@B.c").unwrap(), b"recovery:a@b.c");
        assert_ne!(
            password_credential_id("a@b.c").unwrap(),
            recovery_credential_id("a@b.c").unwrap()
        );
    }

    #[test]
    fn token_text_round_trip_and_redaction() {
        let token = SessionToken::derive(&[7u8; 64]).unwrap();
        let text = token.to_text();
        let back = SessionToken::from_text(&text).unwrap();
        assert_eq!(back.verifier(), token.verifier());
        assert_ne!(token.verifier().as_slice(), token.0.as_slice());
        assert_eq!(format!("{token:?}"), "SessionToken(<redacted>)");
        assert!(SessionToken::from_text("short").is_err());
        assert!(SessionToken::from_text("!!!!").is_err());
    }
}
