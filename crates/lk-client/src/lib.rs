//! Last Keys application layer, shared by every client (the `lk` CLI and the
//! desktop application today; the mobile bindings and the browser later).
//!
//! It turns the core crates into the operations a user performs: create or
//! enroll a vault, unlock it, list, read, add, edit and delete items, read
//! TOTP codes, change the master password, rotate the recovery key, register
//! on a server, synchronize, list and revoke devices.
//!
//! For graphical clients it also provides view models ([`view`]) in which
//! secret values are replaced by presence flags, and edit requests
//! ([`draft`]) in which secret fields are sent as changes. A secret value
//! leaves this crate only through [`Vault::field_value`] (explicit reveal or
//! copy), [`Vault::item`] (clients that render secrets themselves) and the
//! origin-checked autofill operations ([`autofill`]).
//!
//! Every function takes the current time as a parameter (Unix seconds), so
//! that behaviour is deterministic and testable.

#![forbid(unsafe_code)]

pub mod autofill;
pub mod draft;
mod error;
pub mod vault;
pub mod view;

pub use autofill::{AutofillCandidate, AutofillCredentials, FillTarget, SaveProposal};
pub use draft::{
    ContentDraft, CustomFieldDraft, DocumentDraft, ItemDraft, ListChange, SecretChange,
};
pub use error::{ClientError, ErrorKind, Result};
pub use vault::{
    Created, Credential, Enrolled, MIN_MASTER_PASSWORD_CHARS, MIN_REFERENCE_CHARS, Vault,
    new_master_password,
};
pub use view::{
    AddressView, ContentView, CustomFieldView, DeviceStatus, DeviceView, DocumentView, Field,
    HistoryView, ItemSummary, ItemView, KdfView, RemoteView, SyncSummary, TotpView, UnlockMethod,
    VaultInfo,
};

/// Re-exported so that clients do not need a direct dependency for these.
pub use lk_autofill::MatchKind;
pub use lk_core::{DeviceId, ItemId, Platform};
pub use lk_crypto::{MasterPassword, RecoveryKey, Zeroizing};
