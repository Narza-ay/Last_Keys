//! HPKE sealed-message parser: never panics; accepted input is canonical.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lk_crypto::SealedMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = SealedMessage::from_bytes(data) {
        assert_eq!(message.to_bytes(), data, "non-canonical sealed message accepted");
    }
});
