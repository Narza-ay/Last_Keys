//! Statistical and integrity tests (criterion V-S5).

use lk_generator::passphrase::{WORDLIST_LEN, wordlist};
use lk_generator::{PasswordPolicy, generate_password};
use sha2::{Digest, Sha256};

/// χ² goodness-of-fit over 10⁶ characters drawn from a 36-symbol alphabet
/// (35 degrees of freedom). The threshold 90.47 corresponds to p = 10⁻⁶
/// (Wilson–Hilferty approximation): a correct generator fails this test about
/// once in a million runs.
#[test]
fn characters_are_uniformly_distributed() {
    let policy = PasswordPolicy {
        length: 100,
        lowercase: true,
        uppercase: false,
        digits: true,
        symbols: false,
        min_lowercase: 0,
        min_uppercase: 0,
        min_digits: 0,
        min_symbols: 0,
        exclude_ambiguous: false,
        exclude: String::new(),
    };
    let alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    let mut counts = [0u64; 36];
    for _ in 0..10_000 {
        let g = generate_password(&policy).unwrap();
        for c in g.expose_secret().chars() {
            counts[alphabet.find(c).unwrap()] += 1;
        }
    }
    let total: u64 = counts.iter().sum();
    assert_eq!(total, 1_000_000);
    let expected = total as f64 / 36.0;
    let chi2: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();
    assert!(
        chi2 < 90.47,
        "chi-squared {chi2} exceeds the p = 1e-6 threshold"
    );
}

/// The embedded word list is exactly the EFF large wordlist (words column of
/// eff_large_wordlist.txt, published 2016-07-18, SHA-256 of the original file
/// addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e).
#[test]
fn wordlist_integrity() {
    let list = wordlist();
    assert_eq!(list.len(), WORDLIST_LEN);
    let mut sorted = list.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), WORDLIST_LEN, "duplicate words");
    assert!(
        list.iter().all(|w| (3..=9).contains(&w.len())
            && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
    );
    let joined = list.iter().map(|w| format!("{w}\n")).collect::<String>();
    assert_eq!(
        data_encoding::HEXLOWER.encode(&Sha256::digest(joined.as_bytes())),
        "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522"
    );
}
