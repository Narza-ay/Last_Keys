//! Personal recovery key.
//!
//! A recovery key is 256 bits from the OS CSPRNG. Because it has full
//! entropy it is used directly as HKDF input (no password stretching). It is
//! shown to the user exactly once, as a printable string:
//!
//! ```text
//! LK1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
//! ```
//!
//! The 56 symbols encode, in Crockford Base32, the 32 key bytes followed by
//! a 3-byte checksum `SHA-256("lastkeys/v1/recovery/checksum" || key)[..3]`.
//! The checksum only detects typing mistakes; it is not a security control.
//! Parsing is case-insensitive, ignores spaces and hyphens, accepts the
//! prefix as optional, and maps the easily confused `I`/`L` to `1` and `O`
//! to `0`.

use core::fmt;

use data_encoding::{Encoding, Specification};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::derive::{derive_symmetric_key, hkdf_expand, labels};
use crate::error::{CryptoError, Result};
use crate::secret::{AuthKey, KEY_LEN, SymmetricKey};

/// Length of the recovery key secret in bytes.
pub const RECOVERY_KEY_LEN: usize = 32;
const CHECKSUM_LEN: usize = 3;
const PAYLOAD_LEN: usize = RECOVERY_KEY_LEN + CHECKSUM_LEN;
/// Number of Base32 symbols (35 bytes × 8 bits / 5 bits per symbol).
const SYMBOLS: usize = 56;
const GROUP: usize = 4;
const PREFIX: &str = "LK1";
const PREFIX_LEN: usize = PREFIX.len();
/// Symbols plus prefix, separators removed.
const PREFIXED_LEN: usize = PREFIX_LEN + SYMBOLS;
/// "LK1" followed by 14 groups of "-XXXX".
const DISPLAY_LEN: usize = PREFIX_LEN + (SYMBOLS / GROUP) * (GROUP + 1);
const CHECKSUM_LABEL: &[u8] = b"lastkeys/v1/recovery/checksum";

fn crockford() -> Result<Encoding> {
    let mut spec = Specification::new();
    spec.symbols.push_str("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    spec.translate.from.push_str("ILO");
    spec.translate.to.push_str("110");
    spec.encoding()
        .map_err(|_| CryptoError::InvalidRecoveryKeyFormat)
}

fn checksum(key: &[u8; RECOVERY_KEY_LEN]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::new()
        .chain_update(CHECKSUM_LABEL)
        .chain_update(key)
        .finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(digest.get(..CHECKSUM_LEN).unwrap_or(&[0; CHECKSUM_LEN]));
    out
}

/// A personal recovery key. Zeroized on drop; never printed by `Debug`.
pub struct RecoveryKey(Zeroizing<[u8; RECOVERY_KEY_LEN]>);

impl RecoveryKey {
    /// Generates a new recovery key from the OS CSPRNG.
    ///
    /// # Errors
    /// Returns [`CryptoError::RandomUnavailable`] if the OS RNG fails.
    pub fn generate() -> Result<Self> {
        let mut key = Zeroizing::new([0u8; RECOVERY_KEY_LEN]);
        crate::rng::fill_random(key.as_mut())?;
        Ok(Self(key))
    }

    /// Formats the key for display to the user (exactly once, in a secure
    /// screen or printed emergency kit). The returned string is zeroized on
    /// drop.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidRecoveryKeyFormat`] if the encoder can
    /// not be built (not expected).
    pub fn to_display_string(&self) -> Result<Zeroizing<String>> {
        let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
        let (key_part, sum_part) = payload.split_at_mut(RECOVERY_KEY_LEN);
        key_part.copy_from_slice(self.0.as_slice());
        sum_part.copy_from_slice(&checksum(&self.0));
        let symbols = Zeroizing::new(crockford()?.encode(payload.as_slice()));
        let mut out = Zeroizing::new(String::with_capacity(DISPLAY_LEN));
        out.push_str(PREFIX);
        for (i, c) in symbols.chars().enumerate() {
            if i % GROUP == 0 {
                out.push('-');
            }
            out.push(c);
        }
        Ok(out)
    }

    /// Parses a recovery key typed or pasted by the user.
    ///
    /// # Errors
    /// * [`CryptoError::InvalidRecoveryKeyFormat`] for wrong length or symbols.
    /// * [`CryptoError::RecoveryKeyChecksum`] if the checksum does not match.
    pub fn parse(input: &str) -> Result<Self> {
        let mut cleaned = Zeroizing::new(String::with_capacity(input.len()));
        for c in input.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            cleaned.push(c.to_ascii_uppercase());
        }
        let body: &str = if cleaned.len() == PREFIXED_LEN {
            let (prefix, rest) = cleaned
                .split_at_checked(PREFIX_LEN)
                .ok_or(CryptoError::InvalidRecoveryKeyFormat)?;
            // The prefix's "1" is subject to the same I/L confusion as the body.
            if !matches!(prefix, "LK1" | "LKI" | "LKL") {
                return Err(CryptoError::InvalidRecoveryKeyFormat);
            }
            rest
        } else if cleaned.len() == SYMBOLS {
            cleaned.as_str()
        } else {
            return Err(CryptoError::InvalidRecoveryKeyFormat);
        };
        let decoded = Zeroizing::new(
            crockford()?
                .decode(body.as_bytes())
                .map_err(|_| CryptoError::InvalidRecoveryKeyFormat)?,
        );
        if decoded.len() != PAYLOAD_LEN {
            return Err(CryptoError::InvalidRecoveryKeyFormat);
        }
        let (key_part, sum_part) = decoded.split_at(RECOVERY_KEY_LEN);
        let key: Zeroizing<[u8; RECOVERY_KEY_LEN]> = Zeroizing::new(
            key_part
                .try_into()
                .map_err(|_| CryptoError::InvalidRecoveryKeyFormat)?,
        );
        if !bool::from(checksum(&key).ct_eq(sum_part)) {
            return Err(CryptoError::RecoveryKeyChecksum);
        }
        Ok(Self(key))
    }

    /// Derives the key that wraps the account key for recovery.
    ///
    /// # Errors
    /// Returns [`CryptoError::KdfFailure`] if HKDF fails (not expected).
    pub fn wrapping_key(&self) -> Result<SymmetricKey> {
        derive_symmetric_key(self.0.as_slice(), labels::RECOVERY_WRAP)
    }

    /// Derives the secret used to authenticate a recovery request to the
    /// server (Phase 3 protocol).
    ///
    /// # Errors
    /// Returns [`CryptoError::KdfFailure`] if HKDF fails (not expected).
    pub fn server_auth_key(&self) -> Result<AuthKey> {
        let bytes = hkdf_expand::<KEY_LEN>(self.0.as_slice(), &[labels::RECOVERY_SERVER_AUTH])?;
        Ok(AuthKey::from_zeroizing(&bytes))
    }

    #[cfg(test)]
    fn from_bytes(bytes: [u8; RECOVERY_KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vectors computed independently (Python: `hashlib` +
    /// a straightforward Crockford Base32 encoder). They freeze the format.
    #[test]
    fn known_answer_vectors() {
        let zero = RecoveryKey::from_bytes([0; 32]);
        assert_eq!(
            zero.to_display_string().unwrap().as_str(),
            "LK1-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0005-B7J7"
        );
        let counting = RecoveryKey::from_bytes(core::array::from_fn(|i| u8::try_from(i).unwrap()));
        assert_eq!(
            counting.to_display_string().unwrap().as_str(),
            "LK1-000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFS-0FKV"
        );
    }

    #[test]
    fn display_parse_roundtrip() {
        let rk = RecoveryKey::generate().unwrap();
        let shown = rk.to_display_string().unwrap();
        assert_eq!(shown.len(), DISPLAY_LEN);
        assert_eq!(DISPLAY_LEN, 3 + 14 * 5);
        assert!(shown.starts_with("LK1-"));
        let back = RecoveryKey::parse(&shown).unwrap();
        assert_eq!(back.0.as_slice(), rk.0.as_slice());
    }

    #[test]
    fn lenient_input_forms_are_accepted() {
        let rk = RecoveryKey::from_bytes(core::array::from_fn(|i| u8::try_from(i).unwrap()));
        let canonical = "LK1-000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFS-0FKV";
        let lower_spaced = canonical.to_lowercase().replace('-', " ");
        let no_prefix = canonical.trim_start_matches("LK1-");
        // Includes the prefix: "LK1-" becomes "lkl-".
        let confusable = canonical.replace('0', "o").replace('1', "l");
        for form in [lower_spaced.as_str(), no_prefix, confusable.as_str()] {
            let parsed = RecoveryKey::parse(form).unwrap();
            assert_eq!(parsed.0.as_slice(), rk.0.as_slice(), "form {form:?}");
        }
    }

    #[test]
    fn typos_are_detected() {
        let canonical = "LK1-000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFS-0FKV";
        // Change one symbol inside the key part.
        let typo = canonical.replacen("40R4", "40R5", 1);
        assert_eq!(
            RecoveryKey::parse(&typo).unwrap_err(),
            CryptoError::RecoveryKeyChecksum
        );
        // Missing symbol / extra symbol / invalid symbol.
        assert_eq!(
            RecoveryKey::parse(&canonical[..canonical.len() - 1]).unwrap_err(),
            CryptoError::InvalidRecoveryKeyFormat
        );
        assert_eq!(
            RecoveryKey::parse(&format!("{canonical}0")).unwrap_err(),
            CryptoError::InvalidRecoveryKeyFormat
        );
        let invalid_symbol = canonical.replacen('G', "U", 1);
        assert_eq!(
            RecoveryKey::parse(&invalid_symbol).unwrap_err(),
            CryptoError::InvalidRecoveryKeyFormat
        );
        assert!(RecoveryKey::parse("").is_err());
        // A wrong prefix of the right length is rejected, not silently skipped.
        let wrong_prefix = canonical.replacen("LK1", "XY1", 1);
        assert_eq!(
            RecoveryKey::parse(&wrong_prefix).unwrap_err(),
            CryptoError::InvalidRecoveryKeyFormat
        );
    }

    #[test]
    fn derived_keys_are_distinct_and_deterministic() {
        let rk = RecoveryKey::from_bytes([5; 32]);
        let w1 = rk.wrapping_key().unwrap();
        let w2 = rk.wrapping_key().unwrap();
        assert_eq!(w1.expose(), w2.expose());
        assert_ne!(rk.server_auth_key().unwrap().expose_secret(), w1.expose());
    }

    #[test]
    fn debug_is_redacted() {
        let rk = RecoveryKey::generate().unwrap();
        assert_eq!(format!("{rk:?}"), "RecoveryKey(<redacted>)");
    }
}
