//! Server-side decoders of client-supplied bytes must never panic.

use lk_auth::{
    PasswordFile, ServerLoginState, ServerSecret, login_finish, login_start, registration_finish,
    registration_response,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn server_decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let secret = ServerSecret::generate();
        let _ = registration_response(&secret, &bytes, b"id");
        let _ = registration_finish(&bytes);
        let _ = login_start(&secret, None, &bytes, b"id");
        let _ = PasswordFile::from_bytes(&bytes);
        let _ = ServerSecret::from_bytes(&bytes);
        let _ = login_finish(&ServerLoginState::from_bytes(&bytes), &bytes);
    }
}
