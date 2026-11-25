//! # lk-sync
//!
//! Client side of Last Keys synchronization: a typed API client
//! ([`Api`]), an HTTP transport using the operating system's trust store
//! ([`UreqTransport`]), account flows (registration, device enrollment) and
//! the synchronization engine ([`sync_vault`]) implementing the merge rules
//! of ADR-0008 (conflicts produce copies; no version is ever discarded).

#![forbid(unsafe_code)]

pub mod account;
pub mod api;
pub mod engine;
mod error;
pub mod transport;

pub use account::{Enrollment, enroll_device, login_registered, register_account};
pub use api::{Api, Session};
pub use engine::{CONFLICT_SUFFIX, SyncReport, resync_vault, sync_vault};
pub use error::{Result, SyncError};
#[cfg(feature = "http")]
pub use transport::UreqTransport;
pub use transport::{HttpResponse, Method, Transport, normalize_server_url};
