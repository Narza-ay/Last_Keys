//! Strongly typed random identifiers.
//!
//! Identifiers are random (UUID version 4 layout) so they reveal nothing
//! about creation order or device; they are generated from the OS CSPRNG
//! through `lk-crypto`.

use core::fmt;

use lk_crypto::rng::random_array;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new random identifier.
            ///
            /// # Errors
            /// Fails only if the OS random number generator is unavailable.
            pub fn generate() -> Result<Self> {
                let bytes = random_array::<16>()?;
                Ok(Self(uuid::Builder::from_random_bytes(bytes).into_uuid()))
            }

            /// Wraps an existing UUID.
            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Returns the 16 raw bytes (used in canonical encodings).
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0.hyphenated(), f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0.hyphenated())
            }
        }
    };
}

id_type!(
    /// Identifier of a Last Keys account.
    AccountId
);
id_type!(
    /// Identifier of a physical device (one per installation).
    DeviceId
);
id_type!(
    /// Identifier of a vault.
    VaultId
);
id_type!(
    /// Identifier of a vault item.
    ItemId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_random_v4_and_distinct() {
        let a = ItemId::generate().unwrap();
        let b = ItemId::generate().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.as_uuid().get_version_num(), 4);
        assert_eq!(a.to_string().len(), 36);
    }

    #[test]
    fn serde_is_a_plain_uuid_string() {
        let id = VaultId::generate().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        let back: VaultId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
}
