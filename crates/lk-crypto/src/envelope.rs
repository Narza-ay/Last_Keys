//! Versioned authenticated-encryption envelope.
//!
//! Every symmetric ciphertext produced by Last Keys is an [`Envelope`]. Its
//! binary layout (all integers are single bytes, version 1) is:
//!
//! ```text
//! offset  size  field
//! 0       2     magic "LK"
//! 2       1     format version (1)
//! 3       1     cipher suite (1 = XChaCha20-Poly1305)
//! 4       1     purpose (see [`Purpose`])
//! 5       1     flags (reserved, must be 0 in version 1)
//! 6       16    key identifier of the encryption key
//! 22      24    random nonce
//! 46      n+16  ciphertext followed by the 16-byte Poly1305 tag
//! ```
//!
//! The associated data authenticated by the AEAD is the complete 46-byte
//! header followed by a caller-supplied *context*. The context binds the
//! ciphertext to its location (for example the identifier of the item it
//! belongs to), so that a malicious server or a corrupted store cannot swap
//! two valid ciphertexts without decryption failing. Because the header has a
//! fixed length, `header || context` is unambiguous.
//!
//! Nonces are 192-bit values drawn from the OS CSPRNG for every encryption,
//! which makes accidental nonce reuse under the same key negligible
//! (probability ≈ 2⁻⁹⁶ after 2⁴⁸ messages).

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::rng::random_array;
use crate::secret::{KEY_ID_LEN, KEY_LEN, KeyId, SymmetricKey};

/// Magic bytes at the start of every envelope.
pub const MAGIC: [u8; 2] = *b"LK";
/// Current envelope format version.
pub const FORMAT_VERSION: u8 = 1;
/// Length of the XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;
/// Length of the Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;
/// Length of the fixed envelope header.
pub const HEADER_LEN: usize = 2 + 1 + 1 + 1 + 1 + KEY_ID_LEN + NONCE_LEN;
/// Maximum plaintext size of a single envelope (16 MiB). Larger payloads
/// (attachments) will use a chunked streaming format with its own suite
/// identifier (planned for Phase 4).
pub const MAX_PLAINTEXT_LEN: usize = 16 * 1024 * 1024;

/// Length of a wrapped-key plaintext: key identifier followed by key bytes.
const WRAPPED_KEY_LEN: usize = KEY_ID_LEN + KEY_LEN;

/// Cipher suite identifier. Values are part of the storage format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum Suite {
    /// XChaCha20-Poly1305 with a 24-byte random nonce and a 16-byte tag.
    XChaCha20Poly1305 = 1,
}

impl Suite {
    const fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::XChaCha20Poly1305),
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }
}

/// What an envelope protects. The purpose is authenticated (it is part of
/// the header) and checked on decryption, so a ciphertext produced for one
/// purpose can never be accepted as another.
///
/// Values are part of the storage format and must never be reassigned.
/// Values 9–255 are reserved for future purposes (attachment chunks, share
/// links, sync log entries, ...).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum Purpose {
    /// Account key wrapped by the key derived from the master password.
    AccountKeyByPassword = 1,
    /// Account key wrapped by the key derived from the recovery key.
    AccountKeyByRecovery = 2,
    /// Account key wrapped by a device-local key (OS keystore / biometrics).
    AccountKeyByLocalDevice = 3,
    /// Vault key wrapped by the account key.
    VaultKey = 4,
    /// Item key wrapped by a vault key.
    ItemKey = 5,
    /// Item content encrypted by its item key.
    ItemContent = 6,
    /// Asymmetric private key wrapped by the account key.
    PrivateKey = 7,
    /// Encrypted export file payload.
    Export = 8,
}

impl Purpose {
    /// Stable numeric identifier.
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Parses a stable numeric identifier.
    ///
    /// # Errors
    /// Returns [`CryptoError::Malformed`] for unknown identifiers.
    pub const fn from_id(id: u8) -> Result<Self> {
        Ok(match id {
            1 => Self::AccountKeyByPassword,
            2 => Self::AccountKeyByRecovery,
            3 => Self::AccountKeyByLocalDevice,
            4 => Self::VaultKey,
            5 => Self::ItemKey,
            6 => Self::ItemContent,
            7 => Self::PrivateKey,
            8 => Self::Export,
            _ => return Err(CryptoError::Malformed),
        })
    }
}

/// An authenticated, versioned ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    suite: Suite,
    purpose: Purpose,
    key_id: KeyId,
    nonce: [u8; NONCE_LEN],
    /// Ciphertext followed by the authentication tag.
    ciphertext: Vec<u8>,
}

impl Envelope {
    /// Encrypts `plaintext` under `key` for `purpose`, bound to `context`.
    ///
    /// # Errors
    /// * [`CryptoError::PlaintextTooLarge`] above [`MAX_PLAINTEXT_LEN`].
    /// * [`CryptoError::RandomUnavailable`] if no nonce can be generated.
    pub fn seal(
        key: &SymmetricKey,
        purpose: Purpose,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<Self> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(CryptoError::PlaintextTooLarge);
        }
        let mut envelope = Self {
            suite: Suite::XChaCha20Poly1305,
            purpose,
            key_id: key.id(),
            nonce: random_array()?,
            ciphertext: Vec::new(),
        };
        let aad = envelope.associated_data(context);
        let cipher = cipher_for(key)?;
        // Capacity covers the tag, so the buffer is never reallocated while it
        // still holds plaintext.
        let mut buffer = Vec::with_capacity(plaintext.len().saturating_add(TAG_LEN));
        buffer.extend_from_slice(plaintext);
        cipher
            .encrypt_in_place(&XNonce::from(envelope.nonce), &aad, &mut buffer)
            .map_err(|_| CryptoError::PlaintextTooLarge)?;
        envelope.ciphertext = buffer;
        Ok(envelope)
    }

    /// Authenticates and decrypts the envelope.
    ///
    /// # Errors
    /// * [`CryptoError::PurposeMismatch`] if the envelope purpose differs.
    /// * [`CryptoError::KeyMismatch`] if it was sealed under another key id.
    /// * [`CryptoError::DecryptionFailed`] on authentication failure (wrong
    ///   key, wrong context or modified data).
    pub fn open(
        &self,
        key: &SymmetricKey,
        expected_purpose: Purpose,
        context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if self.purpose != expected_purpose {
            return Err(CryptoError::PurposeMismatch);
        }
        if self.key_id != key.id() {
            return Err(CryptoError::KeyMismatch);
        }
        let aad = self.associated_data(context);
        let cipher = cipher_for(key)?;
        let mut buffer = Zeroizing::new(self.ciphertext.clone());
        cipher
            .decrypt_in_place(&XNonce::from(self.nonce), &aad, &mut *buffer)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(buffer)
    }

    /// Wraps (encrypts) `key_to_wrap`, including its identifier, under
    /// `wrapping_key`.
    ///
    /// # Errors
    /// See [`Envelope::seal`].
    pub fn seal_key(
        wrapping_key: &SymmetricKey,
        purpose: Purpose,
        context: &[u8],
        key_to_wrap: &SymmetricKey,
    ) -> Result<Self> {
        let mut plaintext = Zeroizing::new([0u8; WRAPPED_KEY_LEN]);
        let (id_part, key_part) = plaintext.split_at_mut(KEY_ID_LEN);
        id_part.copy_from_slice(key_to_wrap.id().as_bytes());
        key_part.copy_from_slice(key_to_wrap.expose());
        Self::seal(wrapping_key, purpose, context, plaintext.as_slice())
    }

    /// Unwraps a key sealed with [`Envelope::seal_key`].
    ///
    /// # Errors
    /// See [`Envelope::open`]; additionally [`CryptoError::Malformed`] if the
    /// decrypted payload is not a wrapped key.
    pub fn open_key(
        &self,
        wrapping_key: &SymmetricKey,
        expected_purpose: Purpose,
        context: &[u8],
    ) -> Result<SymmetricKey> {
        let plaintext = self.open(wrapping_key, expected_purpose, context)?;
        if plaintext.len() != WRAPPED_KEY_LEN {
            return Err(CryptoError::Malformed);
        }
        let (id_part, key_part) = plaintext.split_at(KEY_ID_LEN);
        let id: [u8; KEY_ID_LEN] = id_part.try_into().map_err(|_| CryptoError::Malformed)?;
        SymmetricKey::from_slice(KeyId::from_bytes(id), key_part)
    }

    /// Cipher suite of this envelope.
    #[must_use]
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// Purpose of this envelope.
    #[must_use]
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// Identifier of the key this envelope was sealed under.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Serializes the envelope to its canonical binary form.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(self.ciphertext.len()));
        out.extend_from_slice(&self.header());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses an envelope from its binary form.
    ///
    /// Parsing is strict: unknown versions, suites, purposes, non-zero
    /// reserved flags and out-of-range lengths are rejected. Parsing never
    /// panics on arbitrary input (covered by property tests).
    ///
    /// # Errors
    /// [`CryptoError::Malformed`], [`CryptoError::UnsupportedVersion`] or
    /// [`CryptoError::UnsupportedSuite`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let min_len = HEADER_LEN.saturating_add(TAG_LEN);
        let max_len = min_len.saturating_add(MAX_PLAINTEXT_LEN);
        if bytes.len() < min_len || bytes.len() > max_len {
            return Err(CryptoError::Malformed);
        }
        let (header, ciphertext) = bytes.split_at(HEADER_LEN);
        let (magic, rest) = header.split_at(2);
        if magic != MAGIC {
            return Err(CryptoError::Malformed);
        }
        let [version, suite, purpose, flags, rest @ ..] = rest else {
            return Err(CryptoError::Malformed);
        };
        if *version != FORMAT_VERSION {
            return Err(CryptoError::UnsupportedVersion);
        }
        let suite = Suite::from_id(*suite)?;
        let purpose = Purpose::from_id(*purpose)?;
        if *flags != 0 {
            return Err(CryptoError::Malformed);
        }
        let (key_id, nonce) = rest.split_at(KEY_ID_LEN);
        let key_id: [u8; KEY_ID_LEN] = key_id.try_into().map_err(|_| CryptoError::Malformed)?;
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::Malformed)?;
        Ok(Self {
            suite,
            purpose,
            key_id: KeyId::from_bytes(key_id),
            nonce,
            ciphertext: ciphertext.to_vec(),
        })
    }

    fn header(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        let (magic, rest) = h.split_at_mut(2);
        magic.copy_from_slice(&MAGIC);
        let (fixed, rest) = rest.split_at_mut(4);
        fixed.copy_from_slice(&[FORMAT_VERSION, self.suite as u8, self.purpose.id(), 0]);
        let (key_id, nonce) = rest.split_at_mut(KEY_ID_LEN);
        key_id.copy_from_slice(self.key_id.as_bytes());
        nonce.copy_from_slice(&self.nonce);
        h
    }

    fn associated_data(&self, context: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HEADER_LEN.saturating_add(context.len()));
        aad.extend_from_slice(&self.header());
        aad.extend_from_slice(context);
        aad
    }
}

fn cipher_for(key: &SymmetricKey) -> Result<XChaCha20Poly1305> {
    // `new_from_slice` builds the cipher directly from the key bytes without
    // an intermediate stack copy; the cipher zeroizes its key on drop.
    XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"lastkeys/v1/test/context";

    fn key() -> SymmetricKey {
        SymmetricKey::generate().unwrap()
    }

    #[test]
    fn roundtrip() {
        let k = key();
        let env = Envelope::seal(&k, Purpose::ItemContent, CTX, b"hello").unwrap();
        assert_eq!(env.key_id(), k.id());
        assert_eq!(env.purpose(), Purpose::ItemContent);
        assert_eq!(env.suite(), Suite::XChaCha20Poly1305);
        let parsed = Envelope::from_bytes(&env.to_bytes()).unwrap();
        assert_eq!(parsed, env);
        let pt = parsed.open(&k, Purpose::ItemContent, CTX).unwrap();
        assert_eq!(pt.as_slice(), b"hello");
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let k = key();
        let env = Envelope::seal(&k, Purpose::ItemContent, CTX, b"").unwrap();
        assert_eq!(env.to_bytes().len(), HEADER_LEN + TAG_LEN);
        assert!(env.open(&k, Purpose::ItemContent, CTX).unwrap().is_empty());
    }

    #[test]
    fn layout_is_as_documented() {
        let k = key();
        let env = Envelope::seal(&k, Purpose::VaultKey, CTX, b"abc").unwrap();
        let bytes = env.to_bytes();
        assert_eq!(HEADER_LEN, 46);
        assert_eq!(&bytes[0..2], b"LK");
        assert_eq!(bytes[2], 1);
        assert_eq!(bytes[3], 1);
        assert_eq!(bytes[4], Purpose::VaultKey.id());
        assert_eq!(bytes[5], 0);
        assert_eq!(&bytes[6..22], k.id().as_bytes());
        assert_eq!(bytes.len(), HEADER_LEN + 3 + TAG_LEN);
    }

    #[test]
    fn nonces_are_fresh_for_every_encryption() {
        let k = key();
        let a = Envelope::seal(&k, Purpose::ItemContent, CTX, b"same").unwrap();
        let b = Envelope::seal(&k, Purpose::ItemContent, CTX, b"same").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let k = key();
        let env = Envelope::seal(&k, Purpose::ItemContent, CTX, b"secret").unwrap();
        assert_eq!(
            env.open(&key(), Purpose::ItemContent, CTX).unwrap_err(),
            CryptoError::KeyMismatch
        );
        // Same key id but different key bytes (forged id): AEAD must fail.
        let impostor = SymmetricKey::from_slice(k.id(), &[0u8; 32]).unwrap();
        assert_eq!(
            env.open(&impostor, Purpose::ItemContent, CTX).unwrap_err(),
            CryptoError::DecryptionFailed
        );
    }

    #[test]
    fn wrong_context_is_rejected() {
        let k = key();
        let env = Envelope::seal(&k, Purpose::ItemContent, b"item:A", b"secret").unwrap();
        assert_eq!(
            env.open(&k, Purpose::ItemContent, b"item:B").unwrap_err(),
            CryptoError::DecryptionFailed
        );
    }

    #[test]
    fn wrong_purpose_is_rejected_even_if_header_is_rewritten() {
        let k = key();
        let env = Envelope::seal(&k, Purpose::ItemContent, CTX, b"secret").unwrap();
        assert_eq!(
            env.open(&k, Purpose::VaultKey, CTX).unwrap_err(),
            CryptoError::PurposeMismatch
        );
        let mut bytes = env.to_bytes();
        bytes[4] = Purpose::VaultKey.id();
        let forged = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(
            forged.open(&k, Purpose::VaultKey, CTX).unwrap_err(),
            CryptoError::DecryptionFailed
        );
    }

    #[test]
    fn every_single_bit_flip_is_detected() {
        let k = key();
        let bytes = Envelope::seal(&k, Purpose::ItemContent, CTX, b"0123456789")
            .unwrap()
            .to_bytes();
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut tampered = bytes.clone();
                tampered[i] ^= 1 << bit;
                let ok = Envelope::from_bytes(&tampered)
                    .and_then(|e| e.open(&k, Purpose::ItemContent, CTX))
                    .is_ok();
                assert!(!ok, "bit {bit} of byte {i} flipped without detection");
            }
        }
    }

    #[test]
    fn truncation_is_detected() {
        let k = key();
        let bytes = Envelope::seal(&k, Purpose::ItemContent, CTX, b"0123456789")
            .unwrap()
            .to_bytes();
        for len in 0..bytes.len() {
            let ok = Envelope::from_bytes(&bytes[..len])
                .and_then(|e| e.open(&k, Purpose::ItemContent, CTX))
                .is_ok();
            assert!(!ok, "truncation to {len} bytes not detected");
        }
    }

    #[test]
    fn strict_header_parsing() {
        let k = key();
        let good = Envelope::seal(&k, Purpose::ItemContent, CTX, b"x")
            .unwrap()
            .to_bytes();
        let mut bad_version = good.clone();
        bad_version[2] = 2;
        assert_eq!(
            Envelope::from_bytes(&bad_version),
            Err(CryptoError::UnsupportedVersion)
        );
        let mut bad_suite = good.clone();
        bad_suite[3] = 9;
        assert_eq!(
            Envelope::from_bytes(&bad_suite),
            Err(CryptoError::UnsupportedSuite)
        );
        let mut bad_purpose = good.clone();
        bad_purpose[4] = 200;
        assert_eq!(
            Envelope::from_bytes(&bad_purpose),
            Err(CryptoError::Malformed)
        );
        let mut bad_flags = good.clone();
        bad_flags[5] = 1;
        assert_eq!(
            Envelope::from_bytes(&bad_flags),
            Err(CryptoError::Malformed)
        );
        let mut bad_magic = good;
        bad_magic[0] = b'X';
        assert_eq!(
            Envelope::from_bytes(&bad_magic),
            Err(CryptoError::Malformed)
        );
    }

    #[test]
    fn oversized_plaintext_is_rejected() {
        let k = key();
        let big = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        assert_eq!(
            Envelope::seal(&k, Purpose::Export, CTX, &big).unwrap_err(),
            CryptoError::PlaintextTooLarge
        );
    }

    #[test]
    fn key_wrapping_roundtrip_preserves_id_and_bytes() {
        let kek = key();
        let inner = key();
        let env = Envelope::seal_key(&kek, Purpose::VaultKey, CTX, &inner).unwrap();
        let back = env.open_key(&kek, Purpose::VaultKey, CTX).unwrap();
        assert_eq!(back.id(), inner.id());
        assert_eq!(back.expose(), inner.expose());
    }

    #[test]
    fn open_key_rejects_non_key_payload() {
        let kek = key();
        let env = Envelope::seal(&kek, Purpose::VaultKey, CTX, b"not a key").unwrap();
        assert_eq!(
            env.open_key(&kek, Purpose::VaultKey, CTX).unwrap_err(),
            CryptoError::Malformed
        );
    }

    #[test]
    fn purpose_ids_are_stable() {
        let all = [
            (Purpose::AccountKeyByPassword, 1),
            (Purpose::AccountKeyByRecovery, 2),
            (Purpose::AccountKeyByLocalDevice, 3),
            (Purpose::VaultKey, 4),
            (Purpose::ItemKey, 5),
            (Purpose::ItemContent, 6),
            (Purpose::PrivateKey, 7),
            (Purpose::Export, 8),
        ];
        for (p, id) in all {
            assert_eq!(p.id(), id);
            assert_eq!(Purpose::from_id(id), Ok(p));
        }
        assert!(Purpose::from_id(0).is_err());
        assert!(Purpose::from_id(9).is_err());
    }
}
