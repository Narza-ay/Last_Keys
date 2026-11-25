//! Random password generator.
//!
//! Algorithm: for each enabled class, draw its minimum number of characters
//! from that class; draw the remaining characters from the union of the
//! enabled classes; shuffle the result (Fisher–Yates). Every draw is uniform
//! (rejection sampling on the OS CSPRNG, no modulo bias).
//!
//! All character sets are ASCII, so the password is built as bytes.

use lk_crypto::rng::uniform_u32;
use lk_crypto::{CryptoError, Zeroizing};
use serde::{Deserialize, Serialize};

use crate::error::{GeneratorError, Result};
use crate::strength::Generated;

/// Lower-case letters.
pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
/// Upper-case letters.
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Decimal digits.
pub const DIGITS: &str = "0123456789";
/// Symbols. Quotes, backslash, backtick and space are left out because many
/// sites and shells mishandle them.
pub const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
/// Characters easily confused with one another.
pub const AMBIGUOUS: &str = "Il1O0o|";
/// Minimum accepted length.
pub const MIN_LENGTH: usize = 4;
/// Maximum accepted length.
pub const MAX_LENGTH: usize = 256;

/// Password generation policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Total length.
    pub length: usize,
    /// Include lower-case letters.
    pub lowercase: bool,
    /// Include upper-case letters.
    pub uppercase: bool,
    /// Include digits.
    pub digits: bool,
    /// Include symbols.
    pub symbols: bool,
    /// Minimum number of lower-case letters.
    pub min_lowercase: usize,
    /// Minimum number of upper-case letters.
    pub min_uppercase: usize,
    /// Minimum number of digits.
    pub min_digits: usize,
    /// Minimum number of symbols.
    pub min_symbols: usize,
    /// Leave out easily confused characters ([`AMBIGUOUS`]).
    pub exclude_ambiguous: bool,
    /// Additional characters to leave out.
    pub exclude: String,
}

impl Default for PasswordPolicy {
    /// 20 characters, all classes, at least one of each (≈ 125 bits).
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            min_lowercase: 1,
            min_uppercase: 1,
            min_digits: 1,
            min_symbols: 1,
            exclude_ambiguous: false,
            exclude: String::new(),
        }
    }
}

struct Class {
    chars: Vec<u8>,
    min: usize,
}

impl PasswordPolicy {
    fn classes(&self) -> Result<Vec<Class>> {
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&self.length) {
            return Err(GeneratorError::InvalidLength {
                min: MIN_LENGTH,
                max: MAX_LENGTH,
            });
        }
        let spec = [
            ("lower-case", LOWERCASE, self.lowercase, self.min_lowercase),
            ("upper-case", UPPERCASE, self.uppercase, self.min_uppercase),
            ("digit", DIGITS, self.digits, self.min_digits),
            ("symbol", SYMBOLS, self.symbols, self.min_symbols),
        ];
        let mut classes = Vec::with_capacity(spec.len());
        let mut total_min: usize = 0;
        for (name, set, enabled, min) in spec {
            if !enabled {
                if min > 0 {
                    return Err(GeneratorError::MinimumForDisabledClass(name));
                }
                continue;
            }
            let chars: Vec<u8> = set
                .bytes()
                .filter(|b| !(self.exclude_ambiguous && AMBIGUOUS.as_bytes().contains(b)))
                .filter(|b| !self.exclude.as_bytes().contains(b))
                .collect();
            if chars.is_empty() {
                return Err(GeneratorError::EmptyCharacterClass(name));
            }
            total_min = total_min
                .checked_add(min)
                .ok_or(GeneratorError::MinimumsExceedLength)?;
            classes.push(Class { chars, min });
        }
        if classes.is_empty() {
            return Err(GeneratorError::NoCharacterClass);
        }
        if total_min > self.length {
            return Err(GeneratorError::MinimumsExceedLength);
        }
        Ok(classes)
    }

    /// Checks the policy without generating anything.
    ///
    /// # Errors
    /// Returns the same errors as [`generate_password`].
    pub fn validate(&self) -> Result<()> {
        self.classes().map(|_| ())
    }
}

fn pick(set: &[u8]) -> Result<u8> {
    let len = u32::try_from(set.len()).map_err(|_| CryptoError::Malformed)?;
    let index = usize::try_from(uniform_u32(len)?).map_err(|_| CryptoError::Malformed)?;
    set.get(index)
        .copied()
        .ok_or(GeneratorError::Random(CryptoError::Malformed))
}

/// Uniform Fisher–Yates shuffle.
pub(crate) fn shuffle<T>(items: &mut [T]) -> Result<()> {
    for i in (1..items.len()).rev() {
        let bound = u32::try_from(i)
            .ok()
            .and_then(|i| i.checked_add(1))
            .ok_or(CryptoError::Malformed)?;
        let j = usize::try_from(uniform_u32(bound)?).map_err(|_| CryptoError::Malformed)?;
        items.swap(i, j);
    }
    Ok(())
}

/// Generates a password according to `policy`.
///
/// The returned entropy is a lower bound: `(length − Σmin) · log2|union| +
/// Σ(min_c · log2|class_c|)` (the final shuffle adds entropy that is not
/// counted).
///
/// # Errors
/// Fails for invalid policies (see [`GeneratorError`]) or if the OS RNG fails.
pub fn generate_password(policy: &PasswordPolicy) -> Result<Generated> {
    let classes = policy.classes()?;
    let union: Vec<u8> = classes
        .iter()
        .flat_map(|c| c.chars.iter().copied())
        .collect();
    let mut bytes = Zeroizing::new(Vec::with_capacity(policy.length));
    let mut entropy = 0.0_f64;
    let mut drawn: usize = 0;
    for class in &classes {
        for _ in 0..class.min {
            bytes.push(pick(&class.chars)?);
        }
        entropy += class.min as f64 * (class.chars.len() as f64).log2();
        drawn = drawn.saturating_add(class.min);
    }
    let remaining = policy.length.saturating_sub(drawn);
    for _ in 0..remaining {
        bytes.push(pick(&union)?);
    }
    entropy += remaining as f64 * (union.len() as f64).log2();
    shuffle(bytes.as_mut_slice())?;
    // Only ASCII bytes were pushed, so this conversion cannot fail; the
    // fallible path is kept to avoid any panic.
    let text = String::from_utf8(core::mem::take(&mut *bytes))
        .map_err(|_| GeneratorError::Random(CryptoError::Malformed))?;
    Ok(Generated::new(Zeroizing::new(text), entropy))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(s: &str, set: &str) -> usize {
        s.chars().filter(|c| set.contains(*c)).count()
    }

    #[test]
    fn default_policy_meets_its_constraints() {
        for _ in 0..500 {
            let g = generate_password(&PasswordPolicy::default()).unwrap();
            let s = g.expose_secret();
            assert_eq!(s.len(), 20);
            assert!(count(s, LOWERCASE) >= 1);
            assert!(count(s, UPPERCASE) >= 1);
            assert!(count(s, DIGITS) >= 1);
            assert!(count(s, SYMBOLS) >= 1);
            assert!(s.chars().all(|c| {
                [LOWERCASE, UPPERCASE, DIGITS, SYMBOLS]
                    .iter()
                    .any(|set| set.contains(c))
            }));
        }
    }

    #[test]
    fn minimums_are_honoured() {
        let policy = PasswordPolicy {
            length: 12,
            min_digits: 5,
            min_symbols: 4,
            ..PasswordPolicy::default()
        };
        for _ in 0..500 {
            let g = generate_password(&policy).unwrap();
            assert!(count(g.expose_secret(), DIGITS) >= 5);
            assert!(count(g.expose_secret(), SYMBOLS) >= 4);
        }
    }

    #[test]
    fn exclusions_are_honoured() {
        let policy = PasswordPolicy {
            length: 64,
            exclude_ambiguous: true,
            exclude: "abc#$".to_owned(),
            ..PasswordPolicy::default()
        };
        for _ in 0..300 {
            let g = generate_password(&policy).unwrap();
            assert!(
                !g.expose_secret()
                    .chars()
                    .any(|c| "Il1O0o|abc#$".contains(c))
            );
        }
    }

    #[test]
    fn invalid_policies_are_rejected() {
        let base = PasswordPolicy::default();
        let too_short = PasswordPolicy {
            length: 3,
            ..base.clone()
        };
        assert!(matches!(
            too_short.validate(),
            Err(GeneratorError::InvalidLength { .. })
        ));
        let too_long = PasswordPolicy {
            length: 257,
            ..base.clone()
        };
        assert!(matches!(
            too_long.validate(),
            Err(GeneratorError::InvalidLength { .. })
        ));
        let none = PasswordPolicy {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            min_lowercase: 0,
            min_uppercase: 0,
            min_digits: 0,
            min_symbols: 0,
            ..base.clone()
        };
        assert_eq!(none.validate(), Err(GeneratorError::NoCharacterClass));
        let disabled_min = PasswordPolicy {
            digits: false,
            ..base.clone()
        };
        assert_eq!(
            disabled_min.validate(),
            Err(GeneratorError::MinimumForDisabledClass("digit"))
        );
        let over = PasswordPolicy {
            length: 4,
            min_digits: 3,
            ..base.clone()
        };
        assert_eq!(over.validate(), Err(GeneratorError::MinimumsExceedLength));
        let emptied = PasswordPolicy {
            exclude: DIGITS.to_owned(),
            ..base
        };
        assert_eq!(
            emptied.validate(),
            Err(GeneratorError::EmptyCharacterClass("digit"))
        );
    }

    #[test]
    fn entropy_is_exact_for_single_class() {
        let policy = PasswordPolicy {
            length: 10,
            lowercase: false,
            uppercase: false,
            symbols: false,
            min_lowercase: 0,
            min_uppercase: 0,
            min_symbols: 0,
            min_digits: 0,
            ..PasswordPolicy::default()
        };
        let g = generate_password(&policy).unwrap();
        assert!((g.entropy_bits() - 10.0 * 10f64.log2()).abs() < 1e-9);
        assert!(g.expose_secret().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn default_entropy_is_strong() {
        let g = generate_password(&PasswordPolicy::default()).unwrap();
        assert!(g.entropy_bits() > 120.0, "{}", g.entropy_bits());
        assert_eq!(g.level(), crate::StrengthLevel::VeryStrong);
    }

    #[test]
    fn shuffle_keeps_elements() {
        let mut v: Vec<u32> = (0..100).collect();
        shuffle(&mut v).unwrap();
        let mut sorted = v.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..100).collect::<Vec<_>>());
    }
}
