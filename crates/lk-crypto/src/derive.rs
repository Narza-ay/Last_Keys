//! HKDF-SHA256 sub-key derivation with explicit domain-separation labels.
//!
//! Every derived key in Last Keys is produced by HKDF-SHA256 (RFC 5869) from
//! a uniformly random input key and a unique, versioned ASCII label. Labels are
//! constants: a label must never be reused for a different purpose, and a
//! changed derivation must use a new label (e.g. `.../v2/...`).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::secret::{KEY_ID_LEN, KEY_LEN, KeyId, SymmetricKey};

/// Registry of every HKDF label used by this crate.
pub(crate) mod labels {
    /// Master key → key that wraps the account key.
    pub(crate) const MASTER_PASSWORD_WRAP: &[u8] = b"lastkeys/v1/master/password-wrap-key";
    /// Master key → secret consumed by the server authentication protocol.
    pub(crate) const MASTER_SERVER_AUTH: &[u8] = b"lastkeys/v1/master/server-auth-key";
    /// Recovery key → key that wraps the account key.
    pub(crate) const RECOVERY_WRAP: &[u8] = b"lastkeys/v1/recovery/wrap-key";
    /// Recovery key → secret consumed by the recovery authentication protocol.
    pub(crate) const RECOVERY_SERVER_AUTH: &[u8] = b"lastkeys/v1/recovery/server-auth-key";
    /// Suffix appended to a key label to derive that key's public identifier.
    pub(crate) const KEY_ID_SUFFIX: &[u8] = b"#key-id";
}

/// HKDF-SHA256 (extract with an all-zero salt, then expand) to `N` bytes.
pub(crate) fn hkdf_expand<const N: usize>(
    ikm: &[u8],
    info: &[&[u8]],
) -> Result<Zeroizing<[u8; N]>> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let joined: Zeroizing<Vec<u8>> = Zeroizing::new(info.concat());
    let mut out = Zeroizing::new([0u8; N]);
    hk.expand(&joined, out.as_mut())
        .map_err(|_| CryptoError::KdfFailure)?;
    Ok(out)
}

/// Derives a [`SymmetricKey`] and its deterministic public [`KeyId`] from a
/// uniformly random input key and a label.
pub(crate) fn derive_symmetric_key(ikm: &[u8], label: &[u8]) -> Result<SymmetricKey> {
    let bytes = hkdf_expand::<KEY_LEN>(ikm, &[label])?;
    let id_bytes = hkdf_expand::<KEY_ID_LEN>(ikm, &[label, labels::KEY_ID_SUFFIX])?;
    Ok(SymmetricKey::from_zeroizing(
        KeyId::from_bytes(*id_bytes),
        bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869, Appendix A.3 (SHA-256, zero-length salt and info): checks
    /// that our wrapper calls HKDF exactly as specified.
    #[test]
    fn rfc5869_test_case_3() {
        let ikm = [0x0b_u8; 22];
        let okm = hkdf_expand::<42>(&ikm, &[]).unwrap();
        let expected = data_encoding::HEXLOWER
            .decode(
                b"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                  9d201395faa4b61a96c8",
            )
            .unwrap();
        assert_eq!(okm.as_slice(), expected.as_slice());
    }

    #[test]
    fn labels_are_unique() {
        let all = [
            labels::MASTER_PASSWORD_WRAP,
            labels::MASTER_SERVER_AUTH,
            labels::RECOVERY_WRAP,
            labels::RECOVERY_SERVER_AUTH,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
            assert!(
                !a.windows(labels::KEY_ID_SUFFIX.len())
                    .any(|w| w == labels::KEY_ID_SUFFIX)
            );
        }
    }

    #[test]
    fn different_labels_give_independent_keys() {
        let ikm = [42u8; 32];
        let a = derive_symmetric_key(&ikm, labels::MASTER_PASSWORD_WRAP).unwrap();
        let b = derive_symmetric_key(&ikm, labels::RECOVERY_WRAP).unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.id(), b.id());
        assert_ne!(a.id().as_bytes().as_slice(), &a.expose()[..16]);
    }

    #[test]
    fn derivation_is_deterministic() {
        let ikm = [9u8; 32];
        let a = derive_symmetric_key(&ikm, labels::MASTER_PASSWORD_WRAP).unwrap();
        let b = derive_symmetric_key(&ikm, labels::MASTER_PASSWORD_WRAP).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_eq!(a.id(), b.id());
    }
}
