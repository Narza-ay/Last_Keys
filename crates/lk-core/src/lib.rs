//! # lk-core
//!
//! Domain core of Last Keys, shared by every client (desktop, mobile, web,
//! browser extension, CLI) through native bindings (UniFFI for Kotlin and
//! Swift, WebAssembly for the web, direct linking for Tauri and the CLI).
//!
//! This crate defines the account key hierarchy, vault and item keys, and
//! device identities. It performs no I/O and reads no clock: storage,
//! networking and time are supplied by the caller, which keeps it portable
//! (including to `wasm32-unknown-unknown`) and deterministic under test.
//!
//! See `docs/ARCHITECTURE.md` and `docs/adr/0002-key-hierarchy.md`.

#![forbid(unsafe_code)]

pub mod account;
pub mod bytes;
mod context;
pub mod device;
pub mod error;
pub mod ids;
pub mod vault;

pub use account::{
    ACCOUNT_BUNDLE_VERSION, AccountKeyBundle, AccountKeys, KdfConfig, NewAccount, PasswordKeys,
    create_account,
};
pub use bytes::Bytes;
pub use device::{
    AccountKeyTransfer, DeviceCertificate, DeviceIdentity, DevicePublicInfo, DeviceRevocation,
    Platform, SealedDeviceIdentity, trusted_devices,
};
pub use error::{CoreError, Result};
pub use ids::{AccountId, DeviceId, ItemId, VaultId};
pub use vault::{EncryptedItem, VaultKey, WrappedVaultKey};
