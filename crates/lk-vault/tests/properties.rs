//! The item decoder must never panic on arbitrary (decrypted but hostile)
//! input, and every valid item must round-trip.

use lk_vault::codec;
use lk_vault::{ItemContent, ItemData, Login, SecretString};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = codec::decode(&bytes);
    }

    #[test]
    fn decoder_never_panics_on_json_like_input(s in "\\{\"schema\":1,[ -~]{0,200}\\}") {
        let _ = codec::decode(s.as_bytes());
    }

    #[test]
    fn valid_logins_round_trip(
        title in "[^\\x00-\\x1f]{1,64}",
        username in proptest::option::of("\\PC{0,64}"),
        password in proptest::option::of("\\PC{0,128}"),
        created in 0u64..2_000_000_000,
    ) {
        prop_assume!(!title.trim().is_empty());
        let item = ItemData::new(
            &title,
            ItemContent::Login(Login {
                username,
                password: password.map(SecretString::new),
                ..Login::default()
            }),
            created,
        ).unwrap();
        let bytes = codec::encode(&item).unwrap();
        prop_assert_eq!(codec::decode(&bytes).unwrap(), item);
    }
}
