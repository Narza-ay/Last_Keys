//! Serialization and encryption of items.
//!
//! The plaintext of an item is the JSON encoding of [`ItemData`] (UTF-8,
//! at most [`MAX_ITEM_BYTES`]). It is encrypted with the item key by
//! `lk-core` (per-item key wrapped by the vault key, ciphertext bound to the
//! vault and item identifiers).
//!
//! Decoding first reads only the schema version, so that an item written by a
//! newer Last Keys produces [`VaultError::UnsupportedSchema`] (prompting an
//! update) rather than a parse error.

use lk_core::{EncryptedItem, VaultKey};
use lk_crypto::Zeroizing;
use serde::Deserialize;

use crate::error::{Result, VaultError};
use crate::item::{ITEM_SCHEMA_VERSION, ItemData};

/// Maximum size of an item's serialized plaintext (1 MiB).
pub const MAX_ITEM_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
struct SchemaProbe {
    schema: u16,
}

/// Validates and serializes an item. The buffer is zeroized on drop.
///
/// # Errors
/// Validation errors, or [`VaultError::TooLarge`].
pub fn encode(item: &ItemData) -> Result<Zeroizing<Vec<u8>>> {
    item.validate()?;
    let bytes = Zeroizing::new(serde_json::to_vec(item).map_err(|_| VaultError::Corrupted)?);
    if bytes.len() > MAX_ITEM_BYTES {
        return Err(VaultError::TooLarge);
    }
    Ok(bytes)
}

/// Parses and validates a serialized item.
///
/// # Errors
/// [`VaultError::UnsupportedSchema`] for items written by a newer version,
/// [`VaultError::Corrupted`] for malformed payloads, validation errors.
pub fn decode(bytes: &[u8]) -> Result<ItemData> {
    if bytes.len() > MAX_ITEM_BYTES {
        return Err(VaultError::TooLarge);
    }
    let probe: SchemaProbe = serde_json::from_slice(bytes).map_err(|_| VaultError::Corrupted)?;
    if probe.schema != ITEM_SCHEMA_VERSION {
        return Err(VaultError::UnsupportedSchema(probe.schema));
    }
    let item: ItemData = serde_json::from_slice(bytes).map_err(|_| VaultError::Corrupted)?;
    item.validate()?;
    Ok(item)
}

/// Encrypts a new item (fresh item identifier and item key).
///
/// # Errors
/// Validation or encryption errors.
pub fn seal_new(vault: &VaultKey, item: &ItemData) -> Result<EncryptedItem> {
    let plaintext = encode(item)?;
    Ok(vault.create_item(&plaintext)?)
}

/// Re-encrypts an existing item with new content (same identifier and item
/// key, fresh nonce).
///
/// # Errors
/// Validation or encryption errors, or if `existing` does not belong to
/// `vault`.
pub fn seal_update(
    vault: &VaultKey,
    existing: &EncryptedItem,
    item: &ItemData,
) -> Result<EncryptedItem> {
    let plaintext = encode(item)?;
    Ok(vault.update_item(existing, &plaintext)?)
}

/// Decrypts and decodes an item.
///
/// # Errors
/// Decryption, schema or validation errors.
pub fn open(vault: &VaultKey, encrypted: &EncryptedItem) -> Result<ItemData> {
    let plaintext = vault.open_item(encrypted)?;
    decode(&plaintext)
}
