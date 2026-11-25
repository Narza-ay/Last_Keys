//! Master password handling and Argon2id key derivation.
//!
//! The master password is normalized to Unicode NFC (as in the RFC 8265
//! `OpaqueString` profile) so that the same password typed on different
//! platforms or keyboards derives the same key. It is then stretched with
//! Argon2id (RFC 9106) into a [`MasterKey`], from which independent sub-keys
//! are derived with HKDF (see [`MasterKey::password_wrapping_key`] and
//! [`MasterKey::server_auth_key`]).

use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::derive::{derive_symmetric_key, hkdf_expand, labels};
use crate::error::{CryptoError, Result};
use crate::rng::random_array;
use crate::secret::{AuthKey, KEY_LEN, SymmetricKey};

/// Length in bytes of a KDF salt (128 bits, as recommended by RFC 9106).
pub const SALT_LEN: usize = 16;

/// Password-based key derivation algorithm identifier.
///
/// The numeric value is part of the stored account format and must never be
/// reassigned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum KdfAlgorithm {
    /// Argon2id, version 0x13 (RFC 9106).
    Argon2id13 = 1,
}

impl KdfAlgorithm {
    /// Stable numeric identifier.
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Parses a stable numeric identifier.
    ///
    /// # Errors
    /// Returns [`CryptoError::UnsupportedKdf`] for unknown identifiers.
    pub const fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::Argon2id13),
            _ => Err(CryptoError::UnsupportedKdf),
        }
    }
}

/// Argon2id cost parameters.
///
/// Parameters are stored with the account and may be fetched from a server by
/// a new device. A malicious server could try to send weak parameters to make
/// offline guessing cheaper, so [`KdfParams::validate`] enforces a floor that
/// every client applies before deriving anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KdfParams {
    /// Algorithm identifier.
    pub algorithm: KdfAlgorithm,
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes over memory.
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
}

impl KdfParams {
    /// Minimum accepted memory cost: 64 MiB.
    pub const MIN_MEMORY_KIB: u32 = 64 * 1024;
    /// Maximum accepted memory cost: 2 GiB (prevents memory-exhaustion
    /// attacks through hostile parameters).
    pub const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024;
    /// Minimum accepted number of passes.
    pub const MIN_ITERATIONS: u32 = 2;
    /// Maximum accepted number of passes.
    pub const MAX_ITERATIONS: u32 = 20;
    /// Minimum accepted parallelism.
    pub const MIN_PARALLELISM: u32 = 1;
    /// Maximum accepted parallelism.
    pub const MAX_PARALLELISM: u32 = 16;

    /// Default parameters for new accounts: RFC 9106 §4 second recommended
    /// option (Argon2id, m = 64 MiB, t = 3, p = 4).
    ///
    /// This default is provisional until the Phase 2 benchmark campaign on
    /// the minimum supported devices is complete (see `docs/TESTING.md`).
    #[must_use]
    pub const fn recommended() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id13,
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }

    /// Checks that the parameters are within the accepted bounds.
    ///
    /// # Errors
    /// Returns [`CryptoError::KdfParamsOutOfBounds`] if any value is outside
    /// the accepted range.
    pub const fn validate(&self) -> Result<()> {
        let ok = self.memory_kib >= Self::MIN_MEMORY_KIB
            && self.memory_kib <= Self::MAX_MEMORY_KIB
            && self.iterations >= Self::MIN_ITERATIONS
            && self.iterations <= Self::MAX_ITERATIONS
            && self.parallelism >= Self::MIN_PARALLELISM
            && self.parallelism <= Self::MAX_PARALLELISM;
        if ok {
            Ok(())
        } else {
            Err(CryptoError::KdfParamsOutOfBounds)
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::recommended()
    }
}

/// Random, non-secret per-account KDF salt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KdfSalt([u8; SALT_LEN]);

impl KdfSalt {
    /// Generates a new random salt.
    ///
    /// # Errors
    /// Returns [`CryptoError::RandomUnavailable`] if the OS RNG fails.
    pub fn random() -> Result<Self> {
        Ok(Self(random_array()?))
    }

    /// Wraps stored salt bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the salt bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

/// A user's master password, NFC-normalized and zeroized on drop.
pub struct MasterPassword(Zeroizing<String>);

impl MasterPassword {
    /// Maximum accepted length of the normalized password, in bytes.
    pub const MAX_LEN_BYTES: usize = 4096;

    /// Normalizes and wraps a master password.
    ///
    /// Leading and trailing whitespace is preserved (it is part of the
    /// password). Strength requirements are enforced by the caller (UI layer),
    /// not here.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidPassword`] if the password is empty or
    /// longer than [`MasterPassword::MAX_LEN_BYTES`] after normalization.
    pub fn new(input: &str) -> Result<Self> {
        if input.is_empty() || input.len() > Self::MAX_LEN_BYTES {
            return Err(CryptoError::InvalidPassword);
        }
        // NFC can expand UTF-8 text by at most 3x (UAX #15, §9). Reserving
        // that capacity up front guarantees the buffer is never reallocated,
        // so no partial copy of the password is left behind in freed memory.
        let capacity = input
            .len()
            .checked_mul(3)
            .ok_or(CryptoError::InvalidPassword)?;
        let mut normalized = Zeroizing::new(String::with_capacity(capacity));
        for c in input.nfc() {
            normalized.push(c);
        }
        if normalized.len() > Self::MAX_LEN_BYTES {
            return Err(CryptoError::InvalidPassword);
        }
        Ok(Self(normalized))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for MasterPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterPassword(<redacted>)")
    }
}

/// Output of Argon2id over the master password. Never stored, never sent.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    /// Derives the key that wraps (encrypts) the account key.
    ///
    /// # Errors
    /// Returns [`CryptoError::KdfFailure`] if HKDF fails (not expected).
    pub fn password_wrapping_key(&self) -> Result<SymmetricKey> {
        derive_symmetric_key(&self.0, labels::MASTER_PASSWORD_WRAP)
    }

    /// Derives the secret used to authenticate to the server.
    ///
    /// # Errors
    /// Returns [`CryptoError::KdfFailure`] if HKDF fails (not expected).
    pub fn server_auth_key(&self) -> Result<AuthKey> {
        let bytes = hkdf_expand::<KEY_LEN>(&self.0, &[labels::MASTER_SERVER_AUTH])?;
        Ok(AuthKey::from_zeroizing(&bytes))
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// Derives the [`MasterKey`] from a master password with Argon2id.
///
/// This is deliberately slow (hundreds of milliseconds with the recommended
/// parameters). Run it off the UI thread.
///
/// # Errors
/// * [`CryptoError::KdfParamsOutOfBounds`] if `params` fail validation.
/// * [`CryptoError::KdfFailure`] if Argon2 reports an error (e.g. allocation).
pub fn derive_master_key(
    password: &MasterPassword,
    salt: &KdfSalt,
    params: &KdfParams,
) -> Result<MasterKey> {
    params.validate()?;
    match params.algorithm {
        KdfAlgorithm::Argon2id13 => {}
    }
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::KdfParamsOutOfBounds)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = MasterKey([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut out.0)
        .map_err(|_| CryptoError::KdfFailure)?;
    Ok(out)
}

/// Test-only helpers shared by the unit tests of this crate.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Derives a master key while bypassing the production parameter floor,
    /// so that tests do not spend seconds in Argon2. Never available outside
    /// `cfg(test)`.
    pub(crate) fn fast_master_key(password: &str, salt: &KdfSalt) -> MasterKey {
        let pw = MasterPassword::new(password).unwrap();
        let params = Params::new(256, 1, 1, Some(KEY_LEN)).unwrap();
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = MasterKey([0u8; KEY_LEN]);
        argon
            .hash_password_into(pw.as_bytes(), salt.as_bytes(), &mut out.0)
            .unwrap();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfc_normalization_makes_equivalent_inputs_equal() {
        // "é" precomposed (U+00E9) vs "e" + combining acute (U+0065 U+0301).
        let a = MasterPassword::new("caf\u{00E9}-p\u{00E2}ssword").unwrap();
        let b = MasterPassword::new("cafe\u{0301}-pa\u{0302}ssword").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn whitespace_is_preserved() {
        let a = MasterPassword::new(" secret ").unwrap();
        assert_eq!(a.as_bytes(), b" secret ");
    }

    #[test]
    fn empty_and_oversized_passwords_are_rejected() {
        assert_eq!(
            MasterPassword::new("").unwrap_err(),
            CryptoError::InvalidPassword
        );
        let long = "a".repeat(MasterPassword::MAX_LEN_BYTES + 1);
        assert_eq!(
            MasterPassword::new(&long).unwrap_err(),
            CryptoError::InvalidPassword
        );
        let max = "a".repeat(MasterPassword::MAX_LEN_BYTES);
        assert!(MasterPassword::new(&max).is_ok());
    }

    #[test]
    fn nfc_expansion_beyond_limit_is_rejected() {
        // U+0958 (DEVANAGARI LETTER QA) is a composition exclusion: NFC turns
        // its 3 UTF-8 bytes into 6 (U+0915 U+093C). 1000 copies are within
        // the limit before normalization (3000 bytes) but not after (6000).
        let input = "\u{0958}".repeat(1000);
        assert_eq!(input.len(), 3000);
        assert_eq!(
            MasterPassword::new(&input).unwrap_err(),
            CryptoError::InvalidPassword
        );
    }

    #[test]
    fn debug_is_redacted() {
        let pw = MasterPassword::new("hunter2").unwrap();
        assert_eq!(format!("{pw:?}"), "MasterPassword(<redacted>)");
        let mk = testing::fast_master_key("hunter2", &KdfSalt::from_bytes([1; 16]));
        assert_eq!(format!("{mk:?}"), "MasterKey(<redacted>)");
    }

    #[test]
    fn recommended_params_are_valid_and_bounds_enforced() {
        assert!(KdfParams::recommended().validate().is_ok());
        let weak = KdfParams {
            memory_kib: 8 * 1024,
            ..KdfParams::recommended()
        };
        assert_eq!(weak.validate(), Err(CryptoError::KdfParamsOutOfBounds));
        let one_pass = KdfParams {
            iterations: 1,
            ..KdfParams::recommended()
        };
        assert_eq!(one_pass.validate(), Err(CryptoError::KdfParamsOutOfBounds));
        let huge = KdfParams {
            memory_kib: KdfParams::MAX_MEMORY_KIB + 1,
            ..KdfParams::recommended()
        };
        assert_eq!(huge.validate(), Err(CryptoError::KdfParamsOutOfBounds));
        let zero_lanes = KdfParams {
            parallelism: 0,
            ..KdfParams::recommended()
        };
        assert_eq!(
            zero_lanes.validate(),
            Err(CryptoError::KdfParamsOutOfBounds)
        );
    }

    #[test]
    fn derive_master_key_refuses_weak_params_before_hashing() {
        let pw = MasterPassword::new("pw").unwrap();
        let weak = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            algorithm: KdfAlgorithm::Argon2id13,
        };
        assert_eq!(
            derive_master_key(&pw, &KdfSalt::from_bytes([0; 16]), &weak).unwrap_err(),
            CryptoError::KdfParamsOutOfBounds
        );
    }

    /// Cross-implementation check: the expected value was computed with the
    /// reference C implementation (libargon2 via `argon2-cffi`
    /// `hash_secret_raw`, type ID, version 0x13) using the production default
    /// parameters. Any platform binding of `lk-crypto` (WASM, mobile) must
    /// reproduce it.
    #[test]
    fn matches_reference_implementation_with_recommended_params() {
        let params = KdfParams::recommended();
        assert_eq!(
            (params.memory_kib, params.iterations, params.parallelism),
            (65536, 3, 4)
        );
        let salt: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let pw = MasterPassword::new("correct horse battery staple").unwrap();
        let mk = derive_master_key(&pw, &KdfSalt::from_bytes(salt), &params).unwrap();
        assert_eq!(
            data_encoding::HEXLOWER.encode(&mk.0),
            "853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e"
        );
    }

    #[test]
    fn kdf_algorithm_ids_are_stable() {
        assert_eq!(KdfAlgorithm::Argon2id13.id(), 1);
        assert_eq!(KdfAlgorithm::from_id(1), Ok(KdfAlgorithm::Argon2id13));
        assert_eq!(KdfAlgorithm::from_id(0), Err(CryptoError::UnsupportedKdf));
        assert_eq!(KdfAlgorithm::from_id(2), Err(CryptoError::UnsupportedKdf));
    }

    #[test]
    fn subkeys_are_independent_and_password_dependent() {
        let salt = KdfSalt::from_bytes([3; 16]);
        let a = testing::fast_master_key("correct horse", &salt);
        let b = testing::fast_master_key("correct horsf", &salt);
        let wrap_a = a.password_wrapping_key().unwrap();
        let wrap_b = b.password_wrapping_key().unwrap();
        assert_ne!(wrap_a.expose(), wrap_b.expose());
        let auth_a = a.server_auth_key().unwrap();
        assert_ne!(auth_a.expose_secret(), wrap_a.expose());
    }
}
