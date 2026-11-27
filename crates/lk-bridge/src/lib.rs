//! The bridge between the browser extension and the desktop application
//! (ADR-0011): frames, request types, pairing material and mutual
//! authentication, the local endpoint's name, native messaging manifests
//! and relay arguments. It holds no vault data and performs no I/O beyond
//! the frame helpers; the desktop application serves the endpoint and runs
//! the relay.

#![forbid(unsafe_code)]

pub mod auth;
pub mod endpoint;
pub mod frame;
pub mod native;
pub mod proto;

pub use auth::{AuthError, ClientId, Nonce, PairingKey, pairing_code};
pub use endpoint::{APP_IDENTIFIER, Endpoint, endpoint};
pub use frame::{FrameError, MAX_FRAME};
pub use native::{Browser, BrowserFamily, Caller, HOST_NAME, caller_from_args};
pub use proto::{CopyField, Incoming, ProtoError, Request, SecretText, parse_request};
