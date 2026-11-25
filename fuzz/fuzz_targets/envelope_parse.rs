//! Envelope parser: must never panic, and any accepted input must be in
//! canonical form (re-serializing yields the exact same bytes).
#![no_main]

use libfuzzer_sys::fuzz_target;
use lk_crypto::Envelope;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = Envelope::from_bytes(data) {
        assert_eq!(envelope.to_bytes(), data, "non-canonical envelope accepted");
    }
});
