//! Item decoder (decrypted payloads are still untrusted: they may come from a
//! buggy or newer client). Never panics; accepted items re-encode and decode
//! to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lk_vault::codec;

fuzz_target!(|data: &[u8]| {
    if let Ok(item) = codec::decode(data) {
        let bytes = codec::encode(&item).expect("valid item must encode");
        assert_eq!(codec::decode(&bytes).expect("re-decode"), item);
    }
});
