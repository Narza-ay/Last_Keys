//! Recovery-key parser: never panics; an accepted key re-displays and
//! re-parses to the same key.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lk_crypto::RecoveryKey;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(key) = RecoveryKey::parse(text) {
        let shown = key.to_display_string().expect("display");
        let again = RecoveryKey::parse(&shown).expect("re-parse");
        assert_eq!(again.to_display_string().expect("display"), shown);
    }
});
