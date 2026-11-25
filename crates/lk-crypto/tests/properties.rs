//! Property-based tests for the security-critical parsers and the envelope
//! construction. They run against the public API only.

use lk_crypto::{
    CryptoError, EncryptionKeyPair, Envelope, MasterPassword, Purpose, RecoveryKey, SealedMessage,
    SymmetricKey, seal_to,
};
use proptest::prelude::*;

fn purpose_strategy() -> impl Strategy<Value = Purpose> {
    prop_oneof![
        Just(Purpose::AccountKeyByPassword),
        Just(Purpose::AccountKeyByRecovery),
        Just(Purpose::AccountKeyByLocalDevice),
        Just(Purpose::VaultKey),
        Just(Purpose::ItemKey),
        Just(Purpose::ItemContent),
        Just(Purpose::PrivateKey),
        Just(Purpose::Export),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The envelope parser must never panic, whatever the input.
    #[test]
    fn envelope_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = Envelope::from_bytes(&bytes);
    }

    /// Inputs that start with a valid header but carry random bytes must be
    /// parsed or rejected without panicking, and never decrypt.
    #[test]
    fn random_body_after_valid_header_never_decrypts(
        body in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let key = SymmetricKey::generate().unwrap();
        let mut bytes = Envelope::seal(&key, Purpose::ItemContent, b"c", b"x").unwrap().to_bytes();
        bytes.truncate(46);
        bytes.extend_from_slice(&body);
        if let Ok(env) = Envelope::from_bytes(&bytes) {
            prop_assert!(env.open(&key, Purpose::ItemContent, b"c").is_err());
        }
    }

    /// Any plaintext, purpose and context round-trip through the binary form.
    #[test]
    fn envelope_roundtrip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        context in proptest::collection::vec(any::<u8>(), 0..128),
        purpose in purpose_strategy(),
    ) {
        let key = SymmetricKey::generate().unwrap();
        let env = Envelope::seal(&key, purpose, &context, &plaintext).unwrap();
        let parsed = Envelope::from_bytes(&env.to_bytes()).unwrap();
        let opened = parsed.open(&key, purpose, &context).unwrap();
        prop_assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    /// Any single-byte modification of a serialized envelope is rejected.
    #[test]
    fn envelope_any_modification_is_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 0..256),
        index in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let key = SymmetricKey::generate().unwrap();
        let mut bytes = Envelope::seal(&key, Purpose::ItemContent, b"ctx", &plaintext)
            .unwrap()
            .to_bytes();
        let i = index.index(bytes.len());
        bytes[i] = bytes[i].wrapping_add(delta);
        let result = Envelope::from_bytes(&bytes)
            .and_then(|e| e.open(&key, Purpose::ItemContent, b"ctx"));
        prop_assert!(result.is_err());
    }

    /// A different context always fails authentication.
    #[test]
    fn envelope_context_binding(
        a in proptest::collection::vec(any::<u8>(), 0..64),
        b in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        prop_assume!(a != b);
        let key = SymmetricKey::generate().unwrap();
        let env = Envelope::seal(&key, Purpose::ItemContent, &a, b"secret").unwrap();
        prop_assert_eq!(
            env.open(&key, Purpose::ItemContent, &b).unwrap_err(),
            CryptoError::DecryptionFailed
        );
    }

    /// The HPKE sealed-message parser must never panic.
    #[test]
    fn sealed_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = SealedMessage::from_bytes(&bytes);
    }

    /// HPKE round-trips arbitrary plaintexts and contexts.
    #[test]
    fn sealed_roundtrip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..1024),
        context in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let kp = EncryptionKeyPair::generate().unwrap();
        let sealed = seal_to(&kp.public_key(), b"prop", &context, &plaintext).unwrap();
        let parsed = SealedMessage::from_bytes(&sealed.to_bytes()).unwrap();
        let opened = kp.open(&parsed, b"prop", &context).unwrap();
        prop_assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    /// The recovery-key parser must never panic on arbitrary text.
    #[test]
    fn recovery_parser_never_panics(input in "\\PC{0,120}") {
        let _ = RecoveryKey::parse(&input);
    }

    /// Master password construction never panics on arbitrary text.
    #[test]
    fn master_password_never_panics(input in "\\PC{0,64}") {
        let _ = MasterPassword::new(&input);
    }
}

#[test]
fn recovery_keys_roundtrip_many_times() {
    for _ in 0..256 {
        let rk = RecoveryKey::generate().unwrap();
        let shown = rk.to_display_string().unwrap();
        let parsed = RecoveryKey::parse(&shown).unwrap();
        // Same key ⇒ same derived wrapping key.
        assert_eq!(
            parsed.wrapping_key().unwrap().id(),
            rk.wrapping_key().unwrap().id()
        );
    }
}
