//! Public-key encryption with HPKE (RFC 9180).
//!
//! Used to transfer a symmetric key to another device or another user
//! (trusted-device enrollment, device recovery, sharing). Suite 1 is
//! `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20-Poly1305`, in base
//! mode. Sender authenticity is provided separately by an Ed25519 signature
//! from the sending device over the sealed message (see `lk-core`).
//!
//! Sealed message layout (version 1):
//!
//! ```text
//! offset  size  field
//! 0       1     format version (1)
//! 1       1     suite (1, see above)
//! 2       32    HPKE encapsulated key
//! 34      n+16  ciphertext followed by the 16-byte tag
//! ```
//!
//! The HPKE `info` is `"lastkeys/v1/hpke/" || label`; the HPKE `aad` is the
//! two header bytes followed by the caller-supplied context.
//!
//! Note: ephemeral key generation inside the HPKE library draws from the OS
//! RNG and aborts the process if the OS RNG fails (fail-closed); it can not
//! return an error.

use core::fmt;

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::envelope::{Envelope, Purpose};
use crate::error::{CryptoError, Result};
use crate::secret::{KEY_ID_LEN, KEY_LEN, KeyId, SymmetricKey};

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// Current sealed-message format version.
pub const SEALED_FORMAT_VERSION: u8 = 1;
/// Suite 1: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305.
/// Suite 2 is reserved for the X-Wing hybrid post-quantum KEM.
pub const SUITE_X25519_SHA256_CHACHA20: u8 = 1;
/// Length of an X25519 public key and of the encapsulated key.
pub const PUBLIC_KEY_LEN: usize = 32;
const SEALED_HEADER_LEN: usize = 2 + PUBLIC_KEY_LEN;
const TAG_LEN: usize = 16;
/// Maximum plaintext of a sealed message (64 KiB): sealed messages carry
/// keys and small key bundles, never bulk data.
pub const MAX_SEALED_PLAINTEXT_LEN: usize = 64 * 1024;
const INFO_PREFIX: &[u8] = b"lastkeys/v1/hpke/";
/// Type tag of an X25519 secret inside a wrapped private key.
const KEY_TYPE_X25519: u8 = 2;
const WRAPPED_KEY_LEN: usize = KEY_ID_LEN + KEY_LEN;

fn info(label: &[u8]) -> Vec<u8> {
    [INFO_PREFIX, label].concat()
}

fn aad(context: &[u8]) -> Vec<u8> {
    [
        &[SEALED_FORMAT_VERSION, SUITE_X25519_SHA256_CHACHA20][..],
        context,
    ]
    .concat()
}

/// An X25519 key pair used to receive sealed messages.
pub struct EncryptionKeyPair {
    secret: <Kem as KemTrait>::PrivateKey,
    public: PublicEncryptionKey,
}

impl EncryptionKeyPair {
    /// Generates a new key pair (RFC 9180 `DeriveKeyPair` over 32 bytes from
    /// the OS CSPRNG).
    ///
    /// # Errors
    /// Returns [`CryptoError::RandomUnavailable`] if the OS RNG fails.
    pub fn generate() -> Result<Self> {
        let mut ikm = Zeroizing::new([0u8; 32]);
        crate::rng::fill_random(ikm.as_mut())?;
        let (secret, public) = Kem::derive_keypair(ikm.as_slice());
        Ok(Self {
            secret,
            public: PublicEncryptionKey(public),
        })
    }

    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> PublicEncryptionKey {
        self.public.clone()
    }

    /// Decrypts a message sealed to this key pair.
    ///
    /// # Errors
    /// Returns [`CryptoError::DecryptionFailed`] if the message was not sealed
    /// to this key, or if the label, context or data differ.
    pub fn open(
        &self,
        sealed: &SealedMessage,
        label: &'static [u8],
        context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&sealed.encapped_key)
            .map_err(|_| CryptoError::Malformed)?;
        hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &self.secret,
            &encapped,
            &info(label),
            &sealed.ciphertext,
            &aad(context),
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Decrypts a symmetric key sealed with [`seal_key_to`].
    ///
    /// # Errors
    /// See [`EncryptionKeyPair::open`]; [`CryptoError::Malformed`] if the
    /// payload is not a wrapped key.
    pub fn open_key(
        &self,
        sealed: &SealedMessage,
        label: &'static [u8],
        context: &[u8],
    ) -> Result<SymmetricKey> {
        let plaintext = self.open(sealed, label, context)?;
        if plaintext.len() != WRAPPED_KEY_LEN {
            return Err(CryptoError::Malformed);
        }
        let (id_part, key_part) = plaintext.split_at(KEY_ID_LEN);
        let id: [u8; KEY_ID_LEN] = id_part.try_into().map_err(|_| CryptoError::Malformed)?;
        SymmetricKey::from_slice(KeyId::from_bytes(id), key_part)
    }

    /// Encrypts the private key under `wrapping_key` for storage.
    ///
    /// # Errors
    /// See [`Envelope::seal`].
    pub fn seal(&self, wrapping_key: &SymmetricKey, context: &[u8]) -> Result<Envelope> {
        let mut plaintext = Zeroizing::new([0u8; 1 + PUBLIC_KEY_LEN]);
        let (tag, secret) = plaintext.split_at_mut(1);
        tag.copy_from_slice(&[KEY_TYPE_X25519]);
        self.secret.write_exact(secret);
        Envelope::seal(
            wrapping_key,
            Purpose::PrivateKey,
            context,
            plaintext.as_slice(),
        )
    }

    /// Decrypts a private key produced by [`EncryptionKeyPair::seal`].
    ///
    /// # Errors
    /// See [`Envelope::open`]; [`CryptoError::Malformed`] if the payload is
    /// not an X25519 key.
    pub fn open_sealed(
        envelope: &Envelope,
        wrapping_key: &SymmetricKey,
        context: &[u8],
    ) -> Result<Self> {
        let plaintext = envelope.open(wrapping_key, Purpose::PrivateKey, context)?;
        let Some((&KEY_TYPE_X25519, secret)) = plaintext.split_first() else {
            return Err(CryptoError::Malformed);
        };
        let secret = <Kem as KemTrait>::PrivateKey::from_bytes(secret)
            .map_err(|_| CryptoError::Malformed)?;
        let public = PublicEncryptionKey(Kem::sk_to_pk(&secret));
        Ok(Self { secret, public })
    }
}

impl fmt::Debug for EncryptionKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionKeyPair")
            .field("public", &self.public)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// An X25519 public key to which messages can be sealed.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicEncryptionKey(<Kem as KemTrait>::PublicKey);

impl PublicEncryptionKey {
    /// Decodes a public key.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidPublicKey`] on malformed input.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self> {
        <Kem as KemTrait>::PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// Encodes the public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        let mut out = [0u8; PUBLIC_KEY_LEN];
        self.0.write_exact(&mut out);
        out
    }
}

impl fmt::Debug for PublicEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicEncryptionKey({})",
            data_encoding::HEXLOWER.encode(&self.to_bytes())
        )
    }
}

/// A message sealed to a [`PublicEncryptionKey`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedMessage {
    encapped_key: [u8; PUBLIC_KEY_LEN],
    ciphertext: Vec<u8>,
}

impl SealedMessage {
    /// Serializes to the canonical binary form.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SEALED_HEADER_LEN.saturating_add(self.ciphertext.len()));
        out.push(SEALED_FORMAT_VERSION);
        out.push(SUITE_X25519_SHA256_CHACHA20);
        out.extend_from_slice(&self.encapped_key);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses the canonical binary form (strict; never panics).
    ///
    /// # Errors
    /// [`CryptoError::Malformed`], [`CryptoError::UnsupportedVersion`] or
    /// [`CryptoError::UnsupportedSuite`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let min_len = SEALED_HEADER_LEN.saturating_add(TAG_LEN);
        let max_len = min_len.saturating_add(MAX_SEALED_PLAINTEXT_LEN);
        if bytes.len() < min_len || bytes.len() > max_len {
            return Err(CryptoError::Malformed);
        }
        let [version, suite, rest @ ..] = bytes else {
            return Err(CryptoError::Malformed);
        };
        if *version != SEALED_FORMAT_VERSION {
            return Err(CryptoError::UnsupportedVersion);
        }
        if *suite != SUITE_X25519_SHA256_CHACHA20 {
            return Err(CryptoError::UnsupportedSuite);
        }
        let (enc, ciphertext) = rest.split_at(PUBLIC_KEY_LEN);
        Ok(Self {
            encapped_key: enc.try_into().map_err(|_| CryptoError::Malformed)?,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// Seals `plaintext` to `recipient` under the domain-separation `label`,
/// bound to `context`.
///
/// # Errors
/// * [`CryptoError::PlaintextTooLarge`] above [`MAX_SEALED_PLAINTEXT_LEN`].
/// * [`CryptoError::InvalidPublicKey`] if encapsulation fails.
pub fn seal_to(
    recipient: &PublicEncryptionKey,
    label: &'static [u8],
    context: &[u8],
    plaintext: &[u8],
) -> Result<SealedMessage> {
    if plaintext.len() > MAX_SEALED_PLAINTEXT_LEN {
        return Err(CryptoError::PlaintextTooLarge);
    }
    let (encapped, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &recipient.0,
        &info(label),
        plaintext,
        &aad(context),
    )
    .map_err(|_| CryptoError::InvalidPublicKey)?;
    let mut encapped_key = [0u8; PUBLIC_KEY_LEN];
    encapped.write_exact(&mut encapped_key);
    Ok(SealedMessage {
        encapped_key,
        ciphertext,
    })
}

/// Seals a symmetric key (with its identifier) to `recipient`.
///
/// # Errors
/// See [`seal_to`].
pub fn seal_key_to(
    recipient: &PublicEncryptionKey,
    label: &'static [u8],
    context: &[u8],
    key: &SymmetricKey,
) -> Result<SealedMessage> {
    let mut plaintext = Zeroizing::new([0u8; WRAPPED_KEY_LEN]);
    let (id_part, key_part) = plaintext.split_at_mut(KEY_ID_LEN);
    id_part.copy_from_slice(key.id().as_bytes());
    key_part.copy_from_slice(key.expose());
    seal_to(recipient, label, context, plaintext.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &[u8] = b"test-transfer";

    #[test]
    fn seal_open_roundtrip_through_bytes() {
        let kp = EncryptionKeyPair::generate().unwrap();
        let sealed = seal_to(&kp.public_key(), LABEL, b"ctx", b"secret").unwrap();
        let parsed = SealedMessage::from_bytes(&sealed.to_bytes()).unwrap();
        assert_eq!(parsed, sealed);
        assert_eq!(
            kp.open(&parsed, LABEL, b"ctx").unwrap().as_slice(),
            b"secret"
        );
    }

    #[test]
    fn wrong_recipient_label_or_context_fails() {
        let kp = EncryptionKeyPair::generate().unwrap();
        let other = EncryptionKeyPair::generate().unwrap();
        let sealed = seal_to(&kp.public_key(), LABEL, b"ctx", b"secret").unwrap();
        assert_eq!(
            other.open(&sealed, LABEL, b"ctx").unwrap_err(),
            CryptoError::DecryptionFailed
        );
        assert_eq!(
            kp.open(&sealed, b"other", b"ctx").unwrap_err(),
            CryptoError::DecryptionFailed
        );
        assert_eq!(
            kp.open(&sealed, LABEL, b"ctx2").unwrap_err(),
            CryptoError::DecryptionFailed
        );
    }

    #[test]
    fn tampering_is_detected() {
        let kp = EncryptionKeyPair::generate().unwrap();
        let bytes = seal_to(&kp.public_key(), LABEL, b"ctx", b"secret")
            .unwrap()
            .to_bytes();
        for i in 0..bytes.len() {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            let ok = SealedMessage::from_bytes(&t)
                .and_then(|m| kp.open(&m, LABEL, b"ctx"))
                .is_ok();
            assert!(!ok, "tampering at byte {i} undetected");
        }
    }

    #[test]
    fn key_transfer_roundtrip() {
        let kp = EncryptionKeyPair::generate().unwrap();
        let key = SymmetricKey::generate().unwrap();
        let sealed = seal_key_to(&kp.public_key(), LABEL, b"ctx", &key).unwrap();
        let back = kp.open_key(&sealed, LABEL, b"ctx").unwrap();
        assert_eq!(back.id(), key.id());
        assert_eq!(back.expose(), key.expose());
    }

    #[test]
    fn private_key_storage_roundtrip() {
        let kek = SymmetricKey::generate().unwrap();
        let kp = EncryptionKeyPair::generate().unwrap();
        let env = kp.seal(&kek, b"ctx").unwrap();
        let back = EncryptionKeyPair::open_sealed(&env, &kek, b"ctx").unwrap();
        assert_eq!(back.public_key(), kp.public_key());
        let sealed = seal_to(&kp.public_key(), LABEL, b"c", b"m").unwrap();
        assert_eq!(back.open(&sealed, LABEL, b"c").unwrap().as_slice(), b"m");
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let kp = EncryptionKeyPair::generate().unwrap();
        let pk = kp.public_key();
        assert_eq!(PublicEncryptionKey::from_bytes(&pk.to_bytes()).unwrap(), pk);
    }

    #[test]
    fn strict_parsing() {
        let kp = EncryptionKeyPair::generate().unwrap();
        let good = seal_to(&kp.public_key(), LABEL, b"", b"x")
            .unwrap()
            .to_bytes();
        let mut v = good.clone();
        v[0] = 2;
        assert_eq!(
            SealedMessage::from_bytes(&v),
            Err(CryptoError::UnsupportedVersion)
        );
        let mut s = good.clone();
        s[1] = 2;
        assert_eq!(
            SealedMessage::from_bytes(&s),
            Err(CryptoError::UnsupportedSuite)
        );
        assert_eq!(
            SealedMessage::from_bytes(&good[..40]),
            Err(CryptoError::Malformed)
        );
    }

    /// Cross-implementation vector (criterion V-C3): the sealed message was
    /// produced by pyhpke 0.6.5 (backed by pyca/cryptography, i.e. OpenSSL),
    /// independent from rust-hpke, using our suite, `info` and `aad`
    /// conventions, to the key pair RFC 9180 `DeriveKeyPair` gives for the IKM
    /// 00 01 .. 1f. Both implementations must also agree on that public key.
    #[test]
    fn opens_message_sealed_by_independent_implementation() {
        let hex = |s: &str| data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap();
        let ikm: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let (secret, public) = Kem::derive_keypair(&ikm);
        let kp = EncryptionKeyPair {
            secret,
            public: PublicEncryptionKey(public),
        };
        assert_eq!(
            data_encoding::HEXLOWER.encode(&kp.public_key().to_bytes()),
            "b1f1b840de7a3241b02748cf9b05b74dc8c5e8451298738817bd76aa8ebe8c2b"
        );
        let sealed = SealedMessage::from_bytes(&hex(
            "01019f93f2544684523191cda46edd935bb351b307221575d14eaeed41aaa559\
             894c5591864f0f5eae8311725c5fe1410b03e4b895cdff3a90fbb9be8b195b53\
             05a24d46bc6fc1efdb677771c9f95b9ed2447e1b65f2a837af28d0e5605ad3d6\
             5a9e",
        ))
        .unwrap();
        let key = kp
            .open_key(
                &sealed,
                b"account-key-transfer",
                b"lastkeys/v1/test/cross-implementation",
            )
            .unwrap();
        assert_eq!(key.id().as_bytes(), &[0x11; 16]);
        assert_eq!(key.expose(), &[0x22; 32]);
    }

    #[test]
    fn oversized_plaintext_rejected() {
        let kp = EncryptionKeyPair::generate().unwrap();
        let big = vec![0u8; MAX_SEALED_PLAINTEXT_LEN + 1];
        assert_eq!(
            seal_to(&kp.public_key(), LABEL, b"", &big).unwrap_err(),
            CryptoError::PlaintextTooLarge
        );
    }
}
