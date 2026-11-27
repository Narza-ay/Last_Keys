//! Pairing material and mutual challenge-response authentication.
//!
//! After pairing, the desktop and the extension share a client ID and a
//! random 256-bit key. Each connection runs:
//!
//! 1. extension → desktop: `hello` with the client ID and a fresh nonce `nc`;
//! 2. desktop → extension: a fresh nonce `ns` and
//!    `HMAC-SHA-256(key, SERVER_LABEL ‖ client_id ‖ nc ‖ ns)`;
//! 3. the extension verifies it, then sends
//!    `HMAC-SHA-256(key, CLIENT_LABEL ‖ client_id ‖ ns ‖ nc)`.
//!
//! Every input has a fixed length, so the concatenation is unambiguous; the
//! labels separate the two directions so that one proof can never be
//! replayed as the other. Encodings: standard Base64 with padding (what
//! `btoa`/`atob` produce in the extension).

use data_encoding::{BASE64, HEXLOWER};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// Length of a pairing key (bytes).
pub const KEY_LEN: usize = 32;
/// Length of a nonce (bytes).
pub const NONCE_LEN: usize = 32;
/// Length of a client ID (bytes, before hex encoding).
pub const CLIENT_ID_LEN: usize = 16;

/// Label of the desktop's proof.
pub const SERVER_LABEL: &[u8] = b"lk-bridge v1 server proof\0";
/// Label of the extension's proof.
pub const CLIENT_LABEL: &[u8] = b"lk-bridge v1 client proof\0";

/// Alphabet of pairing codes: no 0/O, 1/I/L, 2/Z, 5/S, 8/B, U/V.
const CODE_ALPHABET: &[u8] = b"34679ACDEFGHJKMNPQRTWXY";

/// Errors of this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The operating system's random generator failed.
    #[error("random generator unavailable")]
    RandomUnavailable,
    /// A value has the wrong encoding or length.
    #[error("invalid {0}")]
    Invalid(&'static str),
}

fn random<const N: usize>() -> Result<[u8; N], AuthError> {
    let mut out = [0_u8; N];
    getrandom::fill(&mut out).map_err(|_| AuthError::RandomUnavailable)?;
    Ok(out)
}

fn decode_fixed<const N: usize>(
    text: &str,
    what: &'static str,
) -> Result<Zeroizing<[u8; N]>, AuthError> {
    let bytes = Zeroizing::new(
        BASE64
            .decode(text.as_bytes())
            .map_err(|_| AuthError::Invalid(what))?,
    );
    let mut out = Zeroizing::new([0_u8; N]);
    if bytes.len() != N {
        return Err(AuthError::Invalid(what));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// A pairing key (wiped when dropped).
#[derive(Clone)]
pub struct PairingKey(Zeroizing<[u8; KEY_LEN]>);

impl PairingKey {
    /// A new random key.
    ///
    /// # Errors
    /// [`AuthError::RandomUnavailable`].
    pub fn generate() -> Result<Self, AuthError> {
        Ok(Self(Zeroizing::new(random()?)))
    }

    /// Decodes a stored key.
    ///
    /// # Errors
    /// [`AuthError::Invalid`].
    pub fn from_base64(text: &str) -> Result<Self, AuthError> {
        Ok(Self(decode_fixed(text, "pairing key")?))
    }

    /// Encodes the key for storage or for the pairing answer.
    #[must_use]
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE64.encode(self.0.as_slice()))
    }

    fn mac(&self, label: &[u8], parts: [&[u8]; 3]) -> Result<Hmac<Sha256>, AuthError> {
        // HMAC accepts keys of any length; the error case cannot happen.
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.0.as_slice())
            .map_err(|_| AuthError::Invalid("pairing key"))?;
        mac.update(label);
        for part in parts {
            mac.update(part);
        }
        Ok(mac)
    }
}

impl core::fmt::Debug for PairingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairingKey(..)")
    }
}

/// A nonce of one authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// A new random nonce.
    ///
    /// # Errors
    /// [`AuthError::RandomUnavailable`].
    pub fn generate() -> Result<Self, AuthError> {
        Ok(Self(random()?))
    }

    /// Decodes a received nonce.
    ///
    /// # Errors
    /// [`AuthError::Invalid`].
    pub fn from_base64(text: &str) -> Result<Self, AuthError> {
        Ok(Self(*decode_fixed::<NONCE_LEN>(text, "nonce")?))
    }

    /// Encodes the nonce.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.0)
    }
}

/// Identifier of a paired extension: 32 lower-case hexadecimal characters.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientId(String);

impl ClientId {
    /// A new random identifier.
    ///
    /// # Errors
    /// [`AuthError::RandomUnavailable`].
    pub fn generate() -> Result<Self, AuthError> {
        Ok(Self(HEXLOWER.encode(&random::<CLIENT_ID_LEN>()?)))
    }

    /// Checks a received identifier.
    ///
    /// # Errors
    /// [`AuthError::Invalid`].
    pub fn parse(text: &str) -> Result<Self, AuthError> {
        match HEXLOWER.decode(text.as_bytes()) {
            Ok(bytes) if bytes.len() == CLIENT_ID_LEN => Ok(Self(text.to_owned())),
            _ => Err(AuthError::Invalid("client ID")),
        }
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The desktop's proof for a connection.
///
/// # Errors
/// None in practice (HMAC accepts any key length).
pub fn server_proof(
    key: &PairingKey,
    client: &ClientId,
    client_nonce: &Nonce,
    server_nonce: &Nonce,
) -> Result<String, AuthError> {
    let mac = key.mac(
        SERVER_LABEL,
        [client.0.as_bytes(), &client_nonce.0, &server_nonce.0],
    )?;
    Ok(BASE64.encode(&mac.finalize().into_bytes()))
}

/// The extension's proof for a connection.
///
/// # Errors
/// None in practice (HMAC accepts any key length).
pub fn client_proof(
    key: &PairingKey,
    client: &ClientId,
    client_nonce: &Nonce,
    server_nonce: &Nonce,
) -> Result<String, AuthError> {
    let mac = key.mac(
        CLIENT_LABEL,
        [client.0.as_bytes(), &server_nonce.0, &client_nonce.0],
    )?;
    Ok(BASE64.encode(&mac.finalize().into_bytes()))
}

fn verify(mac: Result<Hmac<Sha256>, AuthError>, proof: &str) -> bool {
    let Ok(mac) = mac else { return false };
    BASE64
        .decode(proof.as_bytes())
        .is_ok_and(|bytes| mac.verify_slice(&bytes).is_ok())
}

/// Checks the desktop's proof (constant time).
#[must_use]
pub fn verify_server_proof(
    key: &PairingKey,
    client: &ClientId,
    client_nonce: &Nonce,
    server_nonce: &Nonce,
    proof: &str,
) -> bool {
    verify(
        key.mac(
            SERVER_LABEL,
            [client.0.as_bytes(), &client_nonce.0, &server_nonce.0],
        ),
        proof,
    )
}

/// Checks the extension's proof (constant time).
#[must_use]
pub fn verify_client_proof(
    key: &PairingKey,
    client: &ClientId,
    client_nonce: &Nonce,
    server_nonce: &Nonce,
    proof: &str,
) -> bool {
    verify(
        key.mac(
            CLIENT_LABEL,
            [client.0.as_bytes(), &server_nonce.0, &client_nonce.0],
        ),
        proof,
    )
}

/// A code shown both in the desktop's pairing dialog and in the popup, so
/// that the user approves the request they started: six characters from an
/// unambiguous alphabet, as `XXX-XXX`.
///
/// # Errors
/// [`AuthError::RandomUnavailable`].
pub fn pairing_code() -> Result<String, AuthError> {
    let mut code = String::with_capacity(7);
    let len = CODE_ALPHABET.len();
    // Rejection sampling: no modulo bias.
    let limit = 256_usize.saturating_sub(256_usize.checked_rem(len).unwrap_or(0));
    while code.len() < 7 {
        if code.len() == 3 {
            code.push('-');
        }
        let [byte] = random::<1>()?;
        if usize::from(byte) < limit
            && let Some(c) = usize::from(byte)
                .checked_rem(len)
                .and_then(|i| CODE_ALPHABET.get(i))
        {
            code.push(char::from(*c));
        }
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn proofs_verify_and_are_bound_to_every_input() {
        let key = PairingKey::generate().unwrap();
        let client = ClientId::generate().unwrap();
        let (nc, ns) = (Nonce::generate().unwrap(), Nonce::generate().unwrap());
        let sp = server_proof(&key, &client, &nc, &ns).unwrap();
        let cp = client_proof(&key, &client, &nc, &ns).unwrap();
        assert!(verify_server_proof(&key, &client, &nc, &ns, &sp));
        assert!(verify_client_proof(&key, &client, &nc, &ns, &cp));
        // Directions are not interchangeable.
        assert_ne!(sp, cp);
        assert!(!verify_client_proof(&key, &client, &nc, &ns, &sp));
        assert!(!verify_server_proof(&key, &client, &nc, &ns, &cp));
        // Swapped nonces, another client, another key: refused.
        assert!(!verify_server_proof(&key, &client, &ns, &nc, &sp));
        let other = ClientId::generate().unwrap();
        assert!(!verify_server_proof(&key, &other, &nc, &ns, &sp));
        let key2 = PairingKey::generate().unwrap();
        assert!(!verify_server_proof(&key2, &client, &nc, &ns, &sp));
        // Malformed proofs.
        for bad in ["", "not base64!", &BASE64.encode(&[0_u8; 31])] {
            assert!(!verify_client_proof(&key, &client, &nc, &ns, bad));
        }
    }

    #[test]
    fn known_answer() {
        // Fixed inputs; the same vector is checked by the extension's tests
        // (apps/extension/src/background/auth.test.ts).
        let key = PairingKey::from_base64(&BASE64.encode(&[7_u8; 32])).unwrap();
        let client = ClientId::parse("00112233445566778899aabbccddeeff").unwrap();
        let nc = Nonce::from_base64(&BASE64.encode(&[1_u8; 32])).unwrap();
        let ns = Nonce::from_base64(&BASE64.encode(&[2_u8; 32])).unwrap();
        let sp = server_proof(&key, &client, &nc, &ns).unwrap();
        let cp = client_proof(&key, &client, &nc, &ns).unwrap();
        // Independently computed with Python's hmac module.
        assert_eq!(sp, SERVER_VECTOR);
        assert_eq!(cp, CLIENT_VECTOR);
    }

    const SERVER_VECTOR: &str = "ALZwLEYrQEG4xn8nmvNO+Kz+2BYCF1ysL57WaG1mJ+s=";
    const CLIENT_VECTOR: &str = "9Nc+NplOA858ruq6QWjCWWCIdZXiMPpgn96XtMVbcyk=";

    #[test]
    fn encodings() {
        let key = PairingKey::generate().unwrap();
        let text = key.to_base64();
        assert_eq!(text.len(), 44);
        assert_eq!(PairingKey::from_base64(&text).unwrap().to_base64(), text);
        assert!(PairingKey::from_base64(&BASE64.encode(&[0_u8; 31])).is_err());
        assert!(PairingKey::from_base64("@@@").is_err());
        assert_eq!(format!("{key:?}"), "PairingKey(..)");
        let n = Nonce::generate().unwrap();
        assert_eq!(Nonce::from_base64(&n.to_base64()).unwrap(), n);
        assert_ne!(Nonce::generate().unwrap(), n);

        let id = ClientId::generate().unwrap();
        assert_eq!(id.as_str().len(), 32);
        assert_eq!(ClientId::parse(id.as_str()).unwrap(), id);
        for bad in [
            "",
            "00112233445566778899AABBCCDDEEFF",
            "0011",
            "zz112233445566778899aabbccddeeff",
        ] {
            assert!(ClientId::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn pairing_codes() {
        for _ in 0..200 {
            let code = pairing_code().unwrap();
            assert_eq!(code.len(), 7);
            assert_eq!(code.as_bytes().get(3), Some(&b'-'));
            assert!(
                code.bytes()
                    .enumerate()
                    .all(|(i, c)| i == 3 || CODE_ALPHABET.contains(&c)),
                "{code}"
            );
        }
        assert_ne!(pairing_code().unwrap(), pairing_code().unwrap());
    }
}
