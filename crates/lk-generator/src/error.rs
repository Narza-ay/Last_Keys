//! Generator errors.

use lk_crypto::CryptoError;
use thiserror::Error;

/// Errors returned by the generators.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GeneratorError {
    /// Requested length outside the accepted range.
    #[error("password length must be between {min} and {max}")]
    InvalidLength {
        /// Minimum accepted length.
        min: usize,
        /// Maximum accepted length.
        max: usize,
    },
    /// No character class is enabled.
    #[error("at least one character class must be enabled")]
    NoCharacterClass,
    /// A class is enabled but every one of its characters is excluded.
    #[error("all characters of the {0} class are excluded")]
    EmptyCharacterClass(&'static str),
    /// A minimum count is requested for a disabled class.
    #[error("a minimum is set for the disabled {0} class")]
    MinimumForDisabledClass(&'static str),
    /// The sum of the minimum counts exceeds the length.
    #[error("the minimum character counts exceed the password length")]
    MinimumsExceedLength,
    /// Word count outside the accepted range.
    #[error("passphrase word count must be between {min} and {max}")]
    InvalidWordCount {
        /// Minimum accepted word count.
        min: usize,
        /// Maximum accepted word count.
        max: usize,
    },
    /// The separator is too long or contains letters.
    #[error("the separator must have at most 5 characters and no letters")]
    InvalidSeparator,
    /// An empty separator is only allowed with capitalized words.
    #[error("an empty separator requires capitalized words")]
    EmptySeparatorWithoutCapitalization,
    /// The OS random number generator failed.
    #[error(transparent)]
    Random(#[from] CryptoError),
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, GeneratorError>;
