//! # lk-vault
//!
//! The vault model of Last Keys: a versioned, validated schema for logins,
//! secure notes, payment cards and identities (with TOTP, backup codes,
//! custom fields and password history), and its encryption through
//! `lk-core`.
//!
//! Passkeys, documents/attachments and other item types arrive in later
//! milestones (M9, M12) with a schema version bump.

#![forbid(unsafe_code)]

pub mod codec;
mod error;
pub mod item;
pub mod secret;

pub use error::{Result, VaultError};
pub use item::{
    Address, CustomField, DocumentKind, FieldKind, HistoryEntry, ITEM_SCHEMA_VERSION, Identity,
    IdentityDocument, ItemContent, ItemData, ItemKind, Login, PaymentCard, SecureNote,
    normalize_totp, normalize_url,
};
pub use secret::SecretString;
