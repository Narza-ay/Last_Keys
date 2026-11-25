//! Secret-holding key types.
//!
//! * Secret bytes are zeroized when dropped.
//! * `Debug` implementations never print secret bytes.
//! * Secret types deliberately do not implement `Clone`, `Copy`, `PartialEq`
//!   or serialization: copying or persisting a key must go through an
//!   explicit, reviewed API (for example [`crate::envelope::Envelope::seal_key`]).

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CryptoError, Result};
use crate::rng::random_array;

/// Length in bytes of every symmetric key used by Last Keys (256 bits).
pub const KEY_LEN: usize = 32;

/// Length in bytes of a [`KeyId`].
pub const KEY_ID_LEN: usize = 16;

/// Public, non-secret identifier of a symmetric key.
///
/// Key identifiers are written into every envelope header so that a client
/// can tell which key (and which key version, after a rotation) protects an
/// object, and can reject an object encrypted under an unexpected key before
/// attempting decryption.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId([u8; KEY_ID_LEN]);

impl KeyId {
    /// Generates a fresh random key identifier.
    ///
    /// # Errors
    /// Returns [`CryptoError::RandomUnavailable`] if the OS RNG fails.
    pub fn random() -> Result<Self> {
        Ok(Self(random_array()?))
    }

    /// Wraps raw identifier bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_ID_LEN] {
        &self.0
    }

    /// Lower-case hexadecimal representation (32 characters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.0)
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.to_hex())
    }
}

/// A 256-bit symmetric key together with its public [`KeyId`].
///
/// The key bytes never leave this crate: encryption, decryption and key
/// wrapping are performed through [`crate::envelope::Envelope`].
pub struct SymmetricKey {
    id: KeyId,
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

impl SymmetricKey {
    /// Generates a new random key with a new random identifier.
    ///
    /// # Errors
    /// Returns [`CryptoError::RandomUnavailable`] if the OS RNG fails.
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        crate::rng::fill_random(bytes.as_mut())?;
        Ok(Self {
            id: KeyId::random()?,
            bytes,
        })
    }

    /// Builds a key from a slice, used when unwrapping a decrypted key.
    pub(crate) fn from_slice(id: KeyId, slice: &[u8]) -> Result<Self> {
        let array: [u8; KEY_LEN] = slice.try_into().map_err(|_| CryptoError::Malformed)?;
        Ok(Self {
            id,
            bytes: Zeroizing::new(array),
        })
    }

    /// Builds a key from owned bytes produced inside this crate (e.g. HKDF).
    pub(crate) fn from_zeroizing(id: KeyId, bytes: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self { id, bytes }
    }

    /// Returns the public identifier of this key.
    #[must_use]
    pub const fn id(&self) -> KeyId {
        self.id
    }

    /// Exposes the raw key bytes to the rest of this crate only.
    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("id", &self.id)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// A 256-bit secret used to authenticate to a Last Keys server.
///
/// It is derived from the master key (or from the recovery key) with a label
/// that is distinct from every encryption key, so that what the server
/// authentication protocol consumes can never decrypt vault data
/// (see `docs/adr/0002-key-hierarchy.md`). The planned server protocol
/// (OPAQUE, Phase 3) consumes it as its password input.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthKey([u8; KEY_LEN]);

impl AuthKey {
    pub(crate) fn from_zeroizing(bytes: &Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self(**bytes)
    }

    /// Exposes the secret bytes to the server-authentication protocol.
    ///
    /// The caller must not log, persist or transmit these bytes directly.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_distinct() {
        let a = SymmetricKey::generate().unwrap();
        let b = SymmetricKey::generate().unwrap();
        assert_ne!(a.id(), b.id());
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn debug_output_redacts_secret_bytes() {
        let key = SymmetricKey::from_slice(KeyId::from_bytes([7; 16]), &[0xAB; 32]).unwrap();
        let printed = format!("{key:?}");
        assert!(printed.contains("<redacted>"));
        assert!(!printed.to_lowercase().contains("abab"));
        let auth = AuthKey([0xCD; 32]);
        assert_eq!(format!("{auth:?}"), "AuthKey(<redacted>)");
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        let id = KeyId::from_bytes([0; 16]);
        assert!(SymmetricKey::from_slice(id, &[0; 31]).is_err());
        assert!(SymmetricKey::from_slice(id, &[0; 33]).is_err());
    }
}
