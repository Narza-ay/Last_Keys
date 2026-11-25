//! Binary blob wrapper for serialized structures.
//!
//! Serialized as unpadded Base64url text in human-readable formats (JSON for
//! the REST API and local metadata) and as raw bytes in binary formats.

use core::fmt;

use data_encoding::BASE64URL_NOPAD;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An opaque byte string (ciphertext, public key, signature).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Wraps a byte vector.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the bytes as a fixed-size array, if the length matches.
    #[must_use]
    pub fn to_array<const N: usize>(&self) -> Option<[u8; N]> {
        self.0.as_slice().try_into().ok()
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl<const N: usize> From<[u8; N]> for Bytes {
    fn from(v: [u8; N]) -> Self {
        Self(v.to_vec())
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only ever holds public data or ciphertext, but keep logs short.
        write!(f, "Bytes(len={})", self.0.len())
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&BASE64URL_NOPAD.encode(&self.0))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BytesVisitor;

        impl Visitor<'_> for BytesVisitor {
            type Value = Bytes;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unpadded base64url text or a byte string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Bytes, E> {
                BASE64URL_NOPAD
                    .decode(v.as_bytes())
                    .map(Bytes)
                    .map_err(|_| E::custom("invalid unpadded base64url"))
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Bytes, E> {
                Ok(Bytes(v.to_vec()))
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Bytes, E> {
                Ok(Bytes(v))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(BytesVisitor)
        } else {
            deserializer.deserialize_byte_buf(BytesVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_uses_base64url() {
        let b = Bytes::new(vec![0xfb, 0xff, 0x00, 0x01]);
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, "\"-_8AAQ\"");
        assert_eq!(serde_json::from_str::<Bytes>(&json).unwrap(), b);
    }

    #[test]
    fn rejects_padded_or_standard_base64() {
        assert!(serde_json::from_str::<Bytes>("\"+/8AAQ\"").is_err());
        assert!(serde_json::from_str::<Bytes>("\"-_8AAQ==\"").is_err());
    }

    #[test]
    fn to_array_checks_length() {
        let b = Bytes::from([1u8, 2, 3]);
        assert_eq!(b.to_array::<3>(), Some([1, 2, 3]));
        assert_eq!(b.to_array::<4>(), None);
    }
}
