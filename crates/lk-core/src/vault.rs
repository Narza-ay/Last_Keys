//! Vault keys and per-item encryption.
//!
//! Each vault has a random vault key, wrapped by the account key of every
//! member. Each item has its own random item key, wrapped by the vault key;
//! the item content is encrypted by the item key. Per-item keys allow a
//! single item to be shared (by re-wrapping only its item key) and limit the
//! blast radius of any single key.
//!
//! Every ciphertext is bound to its vault and item identifiers, so a server
//! cannot move an encrypted item into another vault or swap the content of
//! two items without decryption failing.

use lk_crypto::{Envelope, Purpose, SymmetricKey, Zeroizing};
use serde::{Deserialize, Serialize};

use crate::account::AccountKeys;
use crate::bytes::Bytes;
use crate::context;
use crate::error::{CoreError, Result};
use crate::ids::{AccountId, ItemId, VaultId};

/// Current format version of vault structures.
pub const VAULT_FORMAT_VERSION: u8 = 1;

/// An unlocked vault key (memory only).
#[derive(Debug)]
pub struct VaultKey {
    vault_id: VaultId,
    key: SymmetricKey,
}

/// A vault key wrapped for one account member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedVaultKey {
    /// Format version ([`VAULT_FORMAT_VERSION`]).
    pub format_version: u8,
    /// Account whose account key wraps this vault key.
    pub account_id: AccountId,
    /// Vault identifier.
    pub vault_id: VaultId,
    /// Envelope (purpose `VaultKey`).
    pub wrapped_key: Bytes,
}

/// An encrypted vault item, as stored locally and synchronized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedItem {
    /// Format version ([`VAULT_FORMAT_VERSION`]).
    pub format_version: u8,
    /// Vault identifier.
    pub vault_id: VaultId,
    /// Item identifier.
    pub item_id: ItemId,
    /// Item key wrapped by the vault key (envelope, purpose `ItemKey`).
    pub wrapped_item_key: Bytes,
    /// Item content encrypted by the item key (envelope, purpose
    /// `ItemContent`). The plaintext schema is defined by the vault model
    /// (Phase 4); this layer treats it as opaque bytes.
    pub content: Bytes,
}

fn check_version(v: u8) -> Result<()> {
    if v == VAULT_FORMAT_VERSION {
        Ok(())
    } else {
        Err(CoreError::UnsupportedFormat(v))
    }
}

impl AccountKeys {
    /// Creates a new vault and its key wrapped for this account.
    ///
    /// # Errors
    /// Fails only if the OS RNG fails.
    pub fn create_vault(&self) -> Result<(VaultKey, WrappedVaultKey)> {
        let vault_id = VaultId::generate()?;
        let key = SymmetricKey::generate()?;
        let wrapped = Envelope::seal_key(
            &self.account_key,
            Purpose::VaultKey,
            &context::vault_key(&self.account_id, &vault_id),
            &key,
        )?;
        Ok((
            VaultKey { vault_id, key },
            WrappedVaultKey {
                format_version: VAULT_FORMAT_VERSION,
                account_id: self.account_id,
                vault_id,
                wrapped_key: wrapped.to_bytes().into(),
            },
        ))
    }

    /// Unwraps a vault key belonging to this account.
    ///
    /// # Errors
    /// Fails if the wrapped key belongs to another account or was tampered
    /// with.
    pub fn open_vault_key(&self, wrapped: &WrappedVaultKey) -> Result<VaultKey> {
        check_version(wrapped.format_version)?;
        if wrapped.account_id != self.account_id {
            return Err(CoreError::Mismatch("account"));
        }
        let envelope = Envelope::from_bytes(wrapped.wrapped_key.as_slice())?;
        let key = envelope.open_key(
            &self.account_key,
            Purpose::VaultKey,
            &context::vault_key(&self.account_id, &wrapped.vault_id),
        )?;
        Ok(VaultKey {
            vault_id: wrapped.vault_id,
            key,
        })
    }
}

impl VaultKey {
    /// Vault identifier.
    #[must_use]
    pub const fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Encrypts a new item with a fresh item key and a fresh identifier.
    ///
    /// # Errors
    /// Fails if the content is too large or the OS RNG fails.
    pub fn create_item(&self, plaintext: &[u8]) -> Result<EncryptedItem> {
        let item_id = ItemId::generate()?;
        let item_key = SymmetricKey::generate()?;
        let wrapped_item_key = Envelope::seal_key(
            &self.key,
            Purpose::ItemKey,
            &context::item_key(&self.vault_id, &item_id),
            &item_key,
        )?;
        self.seal_content(
            item_id,
            &item_key,
            wrapped_item_key.to_bytes().into(),
            plaintext,
        )
    }

    /// Re-encrypts an existing item with new content. The item key is kept
    /// (it may be shared); a fresh nonce is used.
    ///
    /// # Errors
    /// Fails if the item belongs to another vault or was tampered with.
    pub fn update_item(&self, item: &EncryptedItem, plaintext: &[u8]) -> Result<EncryptedItem> {
        let item_key = self.open_item_key(item)?;
        self.seal_content(
            item.item_id,
            &item_key,
            item.wrapped_item_key.clone(),
            plaintext,
        )
    }

    /// Decrypts an item.
    ///
    /// # Errors
    /// Fails if the item belongs to another vault or was tampered with.
    pub fn open_item(&self, item: &EncryptedItem) -> Result<Zeroizing<Vec<u8>>> {
        let item_key = self.open_item_key(item)?;
        let envelope = Envelope::from_bytes(item.content.as_slice())?;
        Ok(envelope.open(
            &item_key,
            Purpose::ItemContent,
            &context::item_content(&self.vault_id, &item.item_id),
        )?)
    }

    fn open_item_key(&self, item: &EncryptedItem) -> Result<SymmetricKey> {
        check_version(item.format_version)?;
        if item.vault_id != self.vault_id {
            return Err(CoreError::Mismatch("vault"));
        }
        let envelope = Envelope::from_bytes(item.wrapped_item_key.as_slice())?;
        Ok(envelope.open_key(
            &self.key,
            Purpose::ItemKey,
            &context::item_key(&self.vault_id, &item.item_id),
        )?)
    }

    fn seal_content(
        &self,
        item_id: ItemId,
        item_key: &SymmetricKey,
        wrapped_item_key: Bytes,
        plaintext: &[u8],
    ) -> Result<EncryptedItem> {
        let content = Envelope::seal(
            item_key,
            Purpose::ItemContent,
            &context::item_content(&self.vault_id, &item_id),
            plaintext,
        )?;
        Ok(EncryptedItem {
            format_version: VAULT_FORMAT_VERSION,
            vault_id: self.vault_id,
            item_id,
            wrapped_item_key,
            content: content.to_bytes().into(),
        })
    }
}
