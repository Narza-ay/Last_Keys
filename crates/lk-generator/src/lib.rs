//! # lk-generator
//!
//! Password and passphrase generation for Last Keys. Every random draw comes
//! from the operating-system CSPRNG through `lk-crypto` and is uniform
//! (rejection sampling). Results are zeroized on drop and report the exact
//! entropy of their generation process.

#![forbid(unsafe_code)]

mod error;
pub mod passphrase;
pub mod password;
pub mod strength;

pub use error::{GeneratorError, Result};
pub use passphrase::{PassphrasePolicy, generate_passphrase};
pub use password::{PasswordPolicy, generate_password};
pub use strength::{Generated, StrengthLevel};
