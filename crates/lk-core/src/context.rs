//! Associated-data contexts and signature/HPKE labels.
//!
//! Every ciphertext is bound to *where* it belongs through its envelope
//! context. Changing any of these strings is a breaking format change and
//! requires a new format version.

use crate::ids::{AccountId, DeviceId, ItemId, VaultId};

/// Signature label: account key certifying a device.
pub(crate) const SIG_DEVICE_CERTIFICATE: &[u8] = b"device-certificate";
/// Signature label: account key revoking a device.
pub(crate) const SIG_DEVICE_REVOCATION: &[u8] = b"device-revocation";
/// Signature label: device signing an account-key transfer.
pub(crate) const SIG_ACCOUNT_KEY_TRANSFER: &[u8] = b"account-key-transfer";
/// HPKE label: account-key transfer to a new or recovering device.
pub(crate) const HPKE_ACCOUNT_KEY_TRANSFER: &[u8] = b"account-key-transfer";

pub(crate) fn account_key_by_password(a: &AccountId) -> Vec<u8> {
    format!("lastkeys/v1/account/{a}/account-key/by-password").into_bytes()
}

pub(crate) fn account_key_by_recovery(a: &AccountId) -> Vec<u8> {
    format!("lastkeys/v1/account/{a}/account-key/by-recovery").into_bytes()
}

pub(crate) fn account_signing_private_key(a: &AccountId) -> Vec<u8> {
    format!("lastkeys/v1/account/{a}/signing-private-key").into_bytes()
}

pub(crate) fn account_encryption_private_key(a: &AccountId) -> Vec<u8> {
    format!("lastkeys/v1/account/{a}/encryption-private-key").into_bytes()
}

pub(crate) fn vault_key(a: &AccountId, v: &VaultId) -> Vec<u8> {
    format!("lastkeys/v1/account/{a}/vault/{v}/vault-key").into_bytes()
}

pub(crate) fn item_key(v: &VaultId, i: &ItemId) -> Vec<u8> {
    format!("lastkeys/v1/vault/{v}/item/{i}/item-key").into_bytes()
}

pub(crate) fn item_content(v: &VaultId, i: &ItemId) -> Vec<u8> {
    format!("lastkeys/v1/vault/{v}/item/{i}/content").into_bytes()
}

pub(crate) fn device_signing_private_key(d: &DeviceId) -> Vec<u8> {
    format!("lastkeys/v1/device/{d}/signing-private-key").into_bytes()
}

pub(crate) fn device_encryption_private_key(d: &DeviceId) -> Vec<u8> {
    format!("lastkeys/v1/device/{d}/encryption-private-key").into_bytes()
}

pub(crate) fn account_key_transfer(a: &AccountId, from: &DeviceId, to: &DeviceId) -> Vec<u8> {
    format!("lastkeys/v1/account/{a}/account-key-transfer/{from}/{to}").into_bytes()
}

/// Deterministic, length-prefixed binary encoding of signed statements.
///
/// Signed data must be byte-for-byte reproducible on every platform, which a
/// general-purpose serializer (e.g. JSON) does not guarantee. Fixed-size
/// fields are written as-is; variable-size fields are prefixed with their
/// length as a big-endian `u32`.
pub(crate) struct Canonical(Vec<u8>);

impl Canonical {
    pub(crate) fn new(statement: &[u8], version: u8) -> Self {
        let mut c = Self(Vec::with_capacity(256));
        c.var(statement);
        c.0.push(version);
        c
    }

    pub(crate) fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Callers bound every variable field well below `u32::MAX`; the length
    /// is saturated defensively rather than truncated.
    pub(crate) fn var(&mut self, bytes: &[u8]) -> &mut Self {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_encoding_is_unambiguous() {
        let a = Canonical::new(b"s", 1).var(b"ab").var(b"c").finish();
        let b = Canonical::new(b"s", 1).var(b"a").var(b"bc").finish();
        assert_ne!(a, b);
        assert_eq!(
            Canonical::new(b"s", 1).u64(258).u8(7).finish(),
            [0, 0, 0, 1, b's', 1, 0, 0, 0, 0, 0, 0, 1, 2, 7]
        );
    }

    #[test]
    fn contexts_embed_identifiers() {
        let a = AccountId::generate().unwrap();
        let v = VaultId::generate().unwrap();
        let ctx = String::from_utf8(vault_key(&a, &v)).unwrap();
        assert!(ctx.contains(&a.to_string()) && ctx.contains(&v.to_string()));
        assert_ne!(account_key_by_password(&a), account_key_by_recovery(&a));
    }
}
