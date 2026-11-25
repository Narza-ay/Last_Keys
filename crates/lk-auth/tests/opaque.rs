//! OPAQUE flows end to end (client and server halves exchanging bytes).

// Test helpers outside `#[test]` functions: panicking is the intended outcome.
#![allow(clippy::unwrap_used)]

use lk_auth::{
    AuthError, PasswordFile, ServerLoginState, ServerSecret, login_finish, login_start,
    password_credential_id, registration_finish, registration_response, start_login,
    start_registration,
};
use lk_crypto::{AuthKey, RecoveryKey};

/// A random 256-bit auth key (the recovery-key derivation is used here only
/// because it avoids running Argon2id in tests).
fn random_auth_key() -> AuthKey {
    RecoveryKey::generate().unwrap().server_auth_key().unwrap()
}

fn register(secret: &ServerSecret, key: &AuthKey, cid: &[u8]) -> PasswordFile {
    let (flow, request) = start_registration(key).unwrap();
    let response = registration_response(secret, &request, cid).unwrap();
    let upload = flow.finish(key, &response).unwrap();
    registration_finish(&upload).unwrap()
}

#[test]
fn register_then_login_derives_the_same_token() {
    let secret = ServerSecret::generate();
    let key = random_auth_key();
    let cid = password_credential_id("alice@example.com").unwrap();
    let file = register(&secret, &key, &cid);

    let (flow, request) = start_login(&key).unwrap();
    let (state, response) = login_start(&secret, Some(&file), &request, &cid).unwrap();
    let (finalization, client_token) = flow.finish(&key, &response).unwrap();
    let server_token = login_finish(&state, &finalization).unwrap();
    assert_eq!(client_token.verifier(), server_token.verifier());

    // A second login yields a different token.
    let (flow, request) = start_login(&key).unwrap();
    let (state, response) = login_start(&secret, Some(&file), &request, &cid).unwrap();
    let (finalization, second) = flow.finish(&key, &response).unwrap();
    login_finish(&state, &finalization).unwrap();
    assert_ne!(second.verifier(), client_token.verifier());
}

#[test]
fn wrong_key_fails_at_the_client() {
    let secret = ServerSecret::generate();
    let cid = password_credential_id("bob@example.com").unwrap();
    let file = register(&secret, &random_auth_key(), &cid);
    let wrong = random_auth_key();
    let (flow, request) = start_login(&wrong).unwrap();
    let (_, response) = login_start(&secret, Some(&file), &request, &cid).unwrap();
    assert_eq!(
        flow.finish(&wrong, &response).unwrap_err(),
        AuthError::InvalidCredentials
    );
}

#[test]
fn unknown_account_is_indistinguishable_and_fails() {
    let secret = ServerSecret::generate();
    let key = random_auth_key();
    let known_cid = password_credential_id("known@example.com").unwrap();
    let file = register(&secret, &key, &known_cid);

    let (_, request) = start_login(&key).unwrap();
    let (_, real) = login_start(&secret, Some(&file), &request, &known_cid).unwrap();
    let unknown_cid = password_credential_id("nobody@example.com").unwrap();
    let (flow, request) = start_login(&key).unwrap();
    let (_, fake) = login_start(&secret, None, &request, &unknown_cid).unwrap();
    assert_eq!(
        real.len(),
        fake.len(),
        "fake responses must have the real length"
    );
    assert_eq!(
        flow.finish(&key, &fake).unwrap_err(),
        AuthError::InvalidCredentials
    );
}

#[test]
fn credential_identifier_is_bound() {
    // A record registered for one identifier does not log in under another.
    let secret = ServerSecret::generate();
    let key = random_auth_key();
    let file = register(
        &secret,
        &key,
        &password_credential_id("a@example.com").unwrap(),
    );
    let other = password_credential_id("b@example.com").unwrap();
    let (flow, request) = start_login(&key).unwrap();
    let (_, response) = login_start(&secret, Some(&file), &request, &other).unwrap();
    assert_eq!(
        flow.finish(&key, &response).unwrap_err(),
        AuthError::InvalidCredentials
    );
}

#[test]
fn tampered_messages_are_rejected() {
    let secret = ServerSecret::generate();
    let key = random_auth_key();
    let cid = password_credential_id("carol@example.com").unwrap();
    let file = register(&secret, &key, &cid);

    // Tampered server response.
    let (flow, request) = start_login(&key).unwrap();
    let (_, mut response) = login_start(&secret, Some(&file), &request, &cid).unwrap();
    let last = response.len() - 1;
    response[last] ^= 1;
    assert!(flow.finish(&key, &response).is_err());

    // Tampered client finalization.
    let (flow, request) = start_login(&key).unwrap();
    let (state, response) = login_start(&secret, Some(&file), &request, &cid).unwrap();
    let (mut finalization, _) = flow.finish(&key, &response).unwrap();
    finalization[0] ^= 1;
    assert!(login_finish(&state, &finalization).is_err());
}

#[test]
fn state_and_secret_survive_serialization() {
    let secret = ServerSecret::generate();
    let restored_secret = ServerSecret::from_bytes(&secret.to_bytes()).unwrap();
    let key = random_auth_key();
    let cid = password_credential_id("dave@example.com").unwrap();
    let file = register(&secret, &key, &cid);
    let file = PasswordFile::from_bytes(file.as_bytes()).unwrap();

    let (flow, request) = start_login(&key).unwrap();
    let (state, response) = login_start(&restored_secret, Some(&file), &request, &cid).unwrap();
    let state = ServerLoginState::from_bytes(state.as_bytes());
    let (finalization, client) = flow.finish(&key, &response).unwrap();
    assert_eq!(
        login_finish(&state, &finalization).unwrap().verifier(),
        client.verifier()
    );
}

#[test]
fn another_server_secret_cannot_authenticate_the_record() {
    let secret = ServerSecret::generate();
    let impostor = ServerSecret::generate();
    let key = random_auth_key();
    let cid = password_credential_id("erin@example.com").unwrap();
    let file = register(&secret, &key, &cid);
    let (flow, request) = start_login(&key).unwrap();
    let (_, response) = login_start(&impostor, Some(&file), &request, &cid).unwrap();
    assert_eq!(
        flow.finish(&key, &response).unwrap_err(),
        AuthError::InvalidCredentials
    );
}

#[test]
fn malformed_inputs_are_errors() {
    let secret = ServerSecret::generate();
    assert_eq!(
        registration_response(&secret, b"junk", b"x").unwrap_err(),
        AuthError::Malformed
    );
    assert_eq!(
        registration_finish(b"junk").unwrap_err(),
        AuthError::Malformed
    );
    assert_eq!(
        login_start(&secret, None, b"junk", b"x").unwrap_err(),
        AuthError::Malformed
    );
    assert_eq!(
        PasswordFile::from_bytes(b"junk").unwrap_err(),
        AuthError::Malformed
    );
    assert_eq!(
        ServerSecret::from_bytes(b"junk").unwrap_err(),
        AuthError::Malformed
    );
    assert!(login_finish(&ServerLoginState::from_bytes(b"junk"), b"junk").is_err());
    assert_eq!(format!("{secret:?}"), "ServerSecret(<redacted>)");
}
