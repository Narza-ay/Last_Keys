//! Ed25519 signatures with mandatory domain separation.
//!
//! Signatures identify devices and authorize security-relevant statements
//! (device certificates, key transfers). Every signature is computed over
//!
//! ```text
//! "LastKeys signature v1" || 0x00 || len(label) (1 byte) || label || message
//! ```
//!
//! so a signature produced for one statement type can never be replayed as
//! another. Verification uses `verify_strict` (rejects small-order keys and
//! non-canonical signatures).

use core::fmt;

use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use crate::envelope::{Envelope, Purpose};
use crate::error::{CryptoError, Result};
use crate::secret::SymmetricKey;

/// Length of an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

const DOMAIN_PREFIX: &[u8] = b"LastKeys signature v1\0";
/// Type tag of an Ed25519 seed inside a wrapped private key.
const KEY_TYPE_ED25519: u8 = 1;
const SEED_LEN: usize = 32;

fn domain_separated(label: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let label_len = u8::try_from(label.len()).map_err(|_| CryptoError::Malformed)?;
    let capacity = DOMAIN_PREFIX
        .len()
        .saturating_add(1)
        .saturating_add(label.len())
        .saturating_add(message.len());
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(DOMAIN_PREFIX);
    out.push(label_len);
    out.extend_from_slice(label);
    out.extend_from_slice(message);
    Ok(out)
}

/// An Ed25519 signing key pair. The secret half is zeroized on drop.
pub struct SigningKeyPair(SigningKey);

impl SigningKeyPair {
    /// Generates a new key pair from the OS CSPRNG.
    ///
    /// # Errors
    /// Returns [`CryptoError::RandomUnavailable`] if the OS RNG fails.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        crate::rng::fill_random(seed.as_mut())?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    /// Returns the public verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Signs `message` under the domain-separation `label`.
    ///
    /// # Errors
    /// Returns [`CryptoError::Malformed`] if `label` exceeds 255 bytes.
    pub fn sign(&self, label: &'static [u8], message: &[u8]) -> Result<Signature> {
        let msg = domain_separated(label, message)?;
        Ok(Signature(self.0.sign(&msg).to_bytes()))
    }

    /// Encrypts the private key under `wrapping_key` for storage.
    ///
    /// # Errors
    /// See [`Envelope::seal`].
    pub fn seal(&self, wrapping_key: &SymmetricKey, context: &[u8]) -> Result<Envelope> {
        let mut plaintext = Zeroizing::new([0u8; 1 + SEED_LEN]);
        let (tag, seed) = plaintext.split_at_mut(1);
        tag.copy_from_slice(&[KEY_TYPE_ED25519]);
        seed.copy_from_slice(self.0.as_bytes());
        Envelope::seal(
            wrapping_key,
            Purpose::PrivateKey,
            context,
            plaintext.as_slice(),
        )
    }

    /// Decrypts a private key produced by [`SigningKeyPair::seal`].
    ///
    /// # Errors
    /// See [`Envelope::open`]; [`CryptoError::Malformed`] if the payload is
    /// not an Ed25519 key.
    pub fn open(envelope: &Envelope, wrapping_key: &SymmetricKey, context: &[u8]) -> Result<Self> {
        let plaintext = envelope.open(wrapping_key, Purpose::PrivateKey, context)?;
        let Some((&KEY_TYPE_ED25519, seed)) = plaintext.split_first() else {
            return Err(CryptoError::Malformed);
        };
        let seed: Zeroizing<[u8; SEED_LEN]> =
            Zeroizing::new(seed.try_into().map_err(|_| CryptoError::Malformed)?);
        Ok(Self(SigningKey::from_bytes(&seed)))
    }
}

impl fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeyPair")
            .field("public", &self.verifying_key())
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Decodes a public key, rejecting invalid curve points.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidPublicKey`] if decoding fails.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// Encodes the public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Verifies `signature` over `message` under the domain-separation `label`.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidSignature`] if verification fails.
    pub fn verify(
        &self,
        label: &'static [u8],
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        let msg = domain_separated(label, message)?;
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        self.0
            .verify_strict(&msg, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VerifyingKey({})",
            data_encoding::HEXLOWER.encode(self.0.as_bytes())
        )
    }
}

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Wraps raw signature bytes (validity is checked on verification).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw signature bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", data_encoding::HEXLOWER.encode(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &[u8] = b"test-statement";

    #[test]
    fn sign_and_verify() {
        let kp = SigningKeyPair::generate().unwrap();
        let sig = kp.sign(LABEL, b"message").unwrap();
        kp.verifying_key().verify(LABEL, b"message", &sig).unwrap();
    }

    #[test]
    fn wrong_message_label_or_key_fails() {
        let kp = SigningKeyPair::generate().unwrap();
        let other = SigningKeyPair::generate().unwrap();
        let sig = kp.sign(LABEL, b"message").unwrap();
        let vk = kp.verifying_key();
        assert_eq!(
            vk.verify(LABEL, b"messagf", &sig),
            Err(CryptoError::InvalidSignature)
        );
        assert_eq!(
            vk.verify(b"other-statement", b"message", &sig),
            Err(CryptoError::InvalidSignature)
        );
        assert_eq!(
            other.verifying_key().verify(LABEL, b"message", &sig),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn label_and_message_boundary_is_unambiguous() {
        // ("ab", "c") and ("a", "bc") must not produce interchangeable signatures.
        let kp = SigningKeyPair::generate().unwrap();
        let sig = kp.sign(b"ab", b"c").unwrap();
        assert!(kp.verifying_key().verify(b"a", b"bc", &sig).is_err());
    }

    #[test]
    fn rfc8032_test_vector_1_underlying_primitive() {
        // RFC 8032 §7.1 TEST 1: confirms the underlying Ed25519 implementation
        // (our wrapper adds domain separation on top of it).
        let hex = |s: &str| data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap();
        let sk: [u8; 32] = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .try_into()
            .unwrap();
        let key = SigningKey::from_bytes(&sk);
        assert_eq!(
            key.verifying_key().to_bytes().to_vec(),
            hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        );
        let sig = key.sign(b"").to_bytes();
        assert_eq!(
            sig.to_vec(),
            hex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                 5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )
        );
    }

    #[test]
    fn sealed_private_key_roundtrip() {
        let kek = SymmetricKey::generate().unwrap();
        let kp = SigningKeyPair::generate().unwrap();
        let env = kp.seal(&kek, b"ctx").unwrap();
        let back = SigningKeyPair::open(&env, &kek, b"ctx").unwrap();
        assert_eq!(back.verifying_key(), kp.verifying_key());
        assert!(SigningKeyPair::open(&env, &kek, b"other").is_err());
    }

    #[test]
    fn invalid_public_key_rejected() {
        // y = 2 is not on the curve (no valid x), decoding must fail.
        let mut bytes = [0u8; 32];
        bytes[0] = 2;
        assert_eq!(
            VerifyingKey::from_bytes(&bytes),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let kp = SigningKeyPair::generate().unwrap();
        let printed = format!("{kp:?}");
        assert!(printed.contains("<redacted>"));
        let seed_hex = data_encoding::HEXLOWER.encode(kp.0.as_bytes());
        assert!(!printed.contains(&seed_hex));
    }
}
