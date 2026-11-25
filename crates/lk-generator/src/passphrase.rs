//! Diceware-style passphrase generator.
//!
//! Words are drawn uniformly from the EFF large wordlist (7 776 words,
//! 12.925 bits per word). The list is © Electronic Frontier Foundation,
//! licensed CC BY 3.0 US (see `NOTICE`). A French wordlist is planned.

use std::sync::OnceLock;

use lk_crypto::rng::uniform_u32;
use lk_crypto::{CryptoError, Zeroizing};
use serde::{Deserialize, Serialize};

use crate::error::{GeneratorError, Result};
use crate::strength::Generated;

const WORDLIST_SOURCE: &str = include_str!("../data/eff_large_wordlist.txt");
/// Number of words in the list.
pub const WORDLIST_LEN: usize = 7776;
/// Minimum accepted word count.
pub const MIN_WORDS: usize = 3;
/// Maximum accepted word count.
pub const MAX_WORDS: usize = 20;
/// Maximum separator length, in characters.
pub const MAX_SEPARATOR_CHARS: usize = 5;

/// The embedded word list.
pub fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| WORDLIST_SOURCE.lines().collect())
}

/// Passphrase generation policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphrasePolicy {
    /// Number of words.
    pub words: usize,
    /// Separator between words (at most 5 characters, no letters).
    pub separator: String,
    /// Capitalize the first letter of each word.
    pub capitalize: bool,
    /// Append one random digit to one random word.
    pub include_number: bool,
}

impl Default for PassphrasePolicy {
    /// Six words separated by hyphens (≈ 77.5 bits).
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".to_owned(),
            capitalize: false,
            include_number: false,
        }
    }
}

impl PassphrasePolicy {
    /// Checks the policy.
    ///
    /// # Errors
    /// Fails for word counts outside 3–20 or an invalid separator.
    pub fn validate(&self) -> Result<()> {
        if !(MIN_WORDS..=MAX_WORDS).contains(&self.words) {
            return Err(GeneratorError::InvalidWordCount {
                min: MIN_WORDS,
                max: MAX_WORDS,
            });
        }
        if self.separator.chars().count() > MAX_SEPARATOR_CHARS
            || self.separator.chars().any(char::is_alphabetic)
        {
            return Err(GeneratorError::InvalidSeparator);
        }
        if self.separator.is_empty() && !self.capitalize {
            return Err(GeneratorError::EmptySeparatorWithoutCapitalization);
        }
        Ok(())
    }
}

fn uniform_index(len: usize) -> Result<usize> {
    let bound = u32::try_from(len).map_err(|_| CryptoError::Malformed)?;
    Ok(usize::try_from(uniform_u32(bound)?).map_err(|_| CryptoError::Malformed)?)
}

/// Generates a passphrase.
///
/// Entropy: `words · log2(7776)`, plus `log2(10)` when a digit is inserted
/// (the choice of the word that receives it is not counted).
///
/// # Errors
/// Fails for invalid policies or if the OS RNG fails.
pub fn generate_passphrase(policy: &PassphrasePolicy) -> Result<Generated> {
    policy.validate()?;
    let list = wordlist();
    if list.len() != WORDLIST_LEN {
        return Err(GeneratorError::Random(CryptoError::Malformed));
    }
    let mut words: Vec<Zeroizing<String>> = Vec::with_capacity(policy.words);
    for _ in 0..policy.words {
        let word = list
            .get(uniform_index(list.len())?)
            .ok_or(GeneratorError::Random(CryptoError::Malformed))?;
        let mut owned = Zeroizing::new(String::with_capacity(word.len().saturating_add(1)));
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            if policy.capitalize {
                owned.extend(first.to_uppercase());
            } else {
                owned.push(first);
            }
        }
        owned.extend(chars);
        words.push(owned);
    }
    let mut entropy = policy.words as f64 * (WORDLIST_LEN as f64).log2();
    if policy.include_number {
        let target = uniform_index(words.len())?;
        let digit = uniform_index(10)?;
        let digit_char = char::from_digit(u32::try_from(digit).unwrap_or(0), 10)
            .ok_or(GeneratorError::Random(CryptoError::Malformed))?;
        if let Some(word) = words.get_mut(target) {
            word.push(digit_char);
        }
        entropy += 10f64.log2();
    }
    let total_len = words
        .iter()
        .map(|w| w.len())
        .sum::<usize>()
        .saturating_add(policy.separator.len().saturating_mul(policy.words));
    let mut out = Zeroizing::new(String::with_capacity(total_len));
    for (i, word) in words.iter().enumerate() {
        if i > 0 {
            out.push_str(&policy.separator);
        }
        out.push_str(word);
    }
    Ok(Generated::new(out, entropy))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_passphrase_shape() {
        let g = generate_passphrase(&PassphrasePolicy::default()).unwrap();
        let parts: Vec<&str> = g.expose_secret().split('-').collect();
        // Some EFF words contain a hyphen, so there may be more parts.
        assert!(parts.len() >= 6);
        assert!((g.entropy_bits() - 6.0 * 7776f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn words_come_from_the_list() {
        let policy = PassphrasePolicy {
            separator: " ".to_owned(),
            ..PassphrasePolicy::default()
        };
        for _ in 0..200 {
            let g = generate_passphrase(&policy).unwrap();
            let words: Vec<&str> = g.expose_secret().split(' ').collect();
            assert_eq!(words.len(), 6);
            assert!(words.iter().all(|w| wordlist().contains(w)));
        }
    }

    #[test]
    fn capitalization_and_number() {
        let policy = PassphrasePolicy {
            words: 4,
            separator: ".".to_owned(),
            capitalize: true,
            include_number: true,
        };
        for _ in 0..200 {
            let g = generate_passphrase(&policy).unwrap();
            let s = g.expose_secret();
            assert_eq!(s.chars().filter(char::is_ascii_digit).count(), 1);
            for word in s.split('.') {
                assert!(word.chars().next().unwrap().is_ascii_uppercase());
            }
            assert!((g.entropy_bits() - (4.0 * 7776f64.log2() + 10f64.log2())).abs() < 1e-9);
        }
    }

    #[test]
    fn invalid_policies_are_rejected() {
        let base = PassphrasePolicy::default();
        assert!(matches!(
            PassphrasePolicy {
                words: 2,
                ..base.clone()
            }
            .validate(),
            Err(GeneratorError::InvalidWordCount { .. })
        ));
        assert!(matches!(
            PassphrasePolicy {
                words: 21,
                ..base.clone()
            }
            .validate(),
            Err(GeneratorError::InvalidWordCount { .. })
        ));
        assert_eq!(
            PassphrasePolicy {
                separator: "and".to_owned(),
                ..base.clone()
            }
            .validate(),
            Err(GeneratorError::InvalidSeparator)
        );
        assert_eq!(
            PassphrasePolicy {
                separator: "------".to_owned(),
                ..base.clone()
            }
            .validate(),
            Err(GeneratorError::InvalidSeparator)
        );
        assert_eq!(
            PassphrasePolicy {
                separator: String::new(),
                ..base.clone()
            }
            .validate(),
            Err(GeneratorError::EmptySeparatorWithoutCapitalization)
        );
        assert!(
            PassphrasePolicy {
                separator: String::new(),
                capitalize: true,
                ..base
            }
            .validate()
            .is_ok()
        );
    }
}
