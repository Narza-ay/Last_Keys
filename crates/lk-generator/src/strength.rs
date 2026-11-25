//! Strength of *generated* secrets.
//!
//! For a secret produced by these generators the strength is known exactly:
//! it is the entropy of the generation process, computed from the policy (a
//! conservative lower bound when minimum counts or digit insertion are used).
//! Estimating the strength of passwords chosen by humans requires a pattern
//! model (dictionary, keyboard walks, dates); it is planned with the
//! onboarding screen (M4) and the security center (Phase 7).

use core::fmt;

use lk_crypto::Zeroizing;
use serde::{Deserialize, Serialize};

/// Qualitative strength level, from the entropy in bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrengthLevel {
    /// Fewer than 35 bits.
    VeryWeak,
    /// 35 to 49 bits.
    Weak,
    /// 50 to 63 bits.
    Fair,
    /// 64 to 79 bits.
    Strong,
    /// 80 bits or more.
    VeryStrong,
}

impl StrengthLevel {
    /// Maps an entropy in bits to a level.
    #[must_use]
    pub fn from_entropy_bits(bits: f64) -> Self {
        if bits >= 80.0 {
            Self::VeryStrong
        } else if bits >= 64.0 {
            Self::Strong
        } else if bits >= 50.0 {
            Self::Fair
        } else if bits >= 35.0 {
            Self::Weak
        } else {
            Self::VeryWeak
        }
    }
}

/// A generated secret together with the entropy of its generation process.
pub struct Generated {
    value: Zeroizing<String>,
    entropy_bits: f64,
}

impl Generated {
    pub(crate) fn new(value: Zeroizing<String>, entropy_bits: f64) -> Self {
        Self {
            value,
            entropy_bits,
        }
    }

    /// The generated secret.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.value
    }

    /// Consumes the result and returns the secret.
    #[must_use]
    pub fn into_secret(self) -> Zeroizing<String> {
        self.value
    }

    /// Entropy of the generation process, in bits.
    #[must_use]
    pub const fn entropy_bits(&self) -> f64 {
        self.entropy_bits
    }

    /// Qualitative strength level.
    #[must_use]
    pub fn level(&self) -> StrengthLevel {
        StrengthLevel::from_entropy_bits(self.entropy_bits)
    }
}

impl fmt::Debug for Generated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generated")
            .field("value", &"<redacted>")
            .field("entropy_bits", &self.entropy_bits)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_follow_thresholds() {
        assert_eq!(
            StrengthLevel::from_entropy_bits(0.0),
            StrengthLevel::VeryWeak
        );
        assert_eq!(
            StrengthLevel::from_entropy_bits(34.9),
            StrengthLevel::VeryWeak
        );
        assert_eq!(StrengthLevel::from_entropy_bits(35.0), StrengthLevel::Weak);
        assert_eq!(StrengthLevel::from_entropy_bits(50.0), StrengthLevel::Fair);
        assert_eq!(
            StrengthLevel::from_entropy_bits(64.0),
            StrengthLevel::Strong
        );
        assert_eq!(
            StrengthLevel::from_entropy_bits(80.0),
            StrengthLevel::VeryStrong
        );
    }

    #[test]
    fn debug_is_redacted() {
        let g = Generated::new(Zeroizing::new("hunter2".to_owned()), 10.0);
        let printed = format!("{g:?}");
        assert!(printed.contains("<redacted>") && !printed.contains("hunter2"));
    }
}
