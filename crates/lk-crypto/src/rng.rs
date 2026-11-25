//! Access to the operating system's cryptographically secure random number
//! generator.
//!
//! Every random value in Last Keys (keys, nonces, salts, identifiers,
//! generated passwords) must come from this module. It delegates directly to
//! the OS CSPRNG through `getrandom` (`getrandom(2)` on Linux, `BCryptGenRandom`
//! / `ProcessPrng` on Windows, `getentropy`/`SecRandomCopyBytes` on Apple
//! platforms, `crypto.getRandomValues` on the web).

use crate::error::{CryptoError, Result};

/// Fills `dest` with bytes from the OS CSPRNG.
///
/// # Errors
/// Returns [`CryptoError::RandomUnavailable`] if the OS generator fails.
/// Callers must propagate this error and never fall back to a weaker source.
pub fn fill_random(dest: &mut [u8]) -> Result<()> {
    getrandom::fill(dest).map_err(|_| CryptoError::RandomUnavailable)
}

/// Returns an array of `N` bytes from the OS CSPRNG.
///
/// # Errors
/// Returns [`CryptoError::RandomUnavailable`] if the OS generator fails.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

/// Returns a uniformly distributed integer in `0..upper` using rejection
/// sampling (no modulo bias).
///
/// # Errors
/// Returns [`CryptoError::RandomUnavailable`] if the OS generator fails.
/// Returns [`CryptoError::Malformed`] if `upper` is zero.
pub fn uniform_u32(upper: u32) -> Result<u32> {
    // `checked_rem` fails only for `upper == 0`.
    let remainder = u32::MAX.checked_rem(upper).ok_or(CryptoError::Malformed)?;
    // `zone` is the largest multiple of `upper` not above u32::MAX; values at
    // or above it are rejected so that every residue is equally likely.
    let zone = u32::MAX.saturating_sub(remainder);
    loop {
        let v = u32::from_le_bytes(random_array::<4>()?);
        if v < zone {
            return v.checked_rem(upper).ok_or(CryptoError::Malformed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_arrays_differ() {
        let a = random_array::<32>().unwrap();
        let b = random_array::<32>().unwrap();
        assert_ne!(a, b, "two 256-bit random values must not collide");
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn uniform_rejects_zero_upper_bound() {
        assert_eq!(uniform_u32(0), Err(CryptoError::Malformed));
    }

    #[test]
    fn uniform_stays_in_range_and_covers_it() {
        let mut seen = [false; 7];
        for _ in 0..2_000 {
            let v = uniform_u32(7).unwrap();
            assert!(v < 7);
            seen[v as usize] = true;
        }
        assert!(seen.iter().all(|s| *s), "all residues should appear");
    }
}
