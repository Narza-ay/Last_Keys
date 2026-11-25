//! Argon2id parameter benchmark.
//!
//! Measures `derive_master_key` for a grid of parameters so that the default
//! KDF cost can be chosen from measurements on the minimum supported devices
//! (see `docs/TESTING.md`, "KDF benchmark campaign").
//!
//! Run (always in release mode):
//! `cargo run --release -p lk-crypto --example kdf_bench`

#![allow(clippy::print_stdout, clippy::unwrap_used)]

use std::time::Instant;

use lk_crypto::{KdfAlgorithm, KdfParams, KdfSalt, MasterPassword, derive_master_key};

fn main() {
    let password = MasterPassword::new("benchmark password, not a secret").unwrap();
    let salt = KdfSalt::from_bytes([7; 16]);
    let grid = [
        (64 * 1024, 2, 1),
        (64 * 1024, 3, 1),
        (64 * 1024, 3, 4),
        (128 * 1024, 3, 4),
        (256 * 1024, 3, 4),
    ];
    println!("memory_mib,iterations,parallelism,median_ms");
    for (memory_kib, iterations, parallelism) in grid {
        let params = KdfParams {
            algorithm: KdfAlgorithm::Argon2id13,
            memory_kib,
            iterations,
            parallelism,
        };
        let mut samples: Vec<u128> = (0..5)
            .map(|_| {
                let start = Instant::now();
                let _key = derive_master_key(&password, &salt, &params).unwrap();
                start.elapsed().as_millis()
            })
            .collect();
        samples.sort_unstable();
        let median = samples.get(samples.len() / 2).copied().unwrap_or_default();
        println!(
            "{},{},{},{}",
            memory_kib / 1024,
            iterations,
            parallelism,
            median
        );
    }
}
