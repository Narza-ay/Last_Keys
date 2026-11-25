//! Account bundle and item deserialization from untrusted JSON (server
//! responses): never panics, including in the accessors that parse keys.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lk_core::{AccountKeyBundle, EncryptedItem};

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = serde_json::from_slice::<AccountKeyBundle>(data) {
        let _ = bundle.signing_public_key();
        let _ = bundle.encryption_public_key();
        let _ = bundle.kdf.params();
        let _ = bundle.kdf.salt();
    }
    let _ = serde_json::from_slice::<EncryptedItem>(data);
});
