//! The otpauth parser and the Base32 decoder must never panic.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn uri_parser_never_panics(input in "\\PC{0,200}") {
        let _ = lk_totp::Totp::from_uri(&input);
    }

    #[test]
    fn uri_parser_never_panics_on_otpauth_like_input(
        path in "[A-Za-z0-9%:@. +-]{0,40}",
        query in "[A-Za-z0-9%=&+ -]{0,80}",
    ) {
        let _ = lk_totp::Totp::from_uri(&format!("otpauth://totp/{path}?{query}"));
    }

    #[test]
    fn base32_decoder_never_panics(input in "\\PC{0,200}") {
        let _ = lk_totp::decode_base32_secret(&input);
    }
}
