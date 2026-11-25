//! Known-answer tests. Expected values are those published in RFC 4226
//! Appendix D and RFC 6238 Appendix B, and were independently recomputed with
//! Python's `hmac` module.

use lk_totp::{Algorithm, ClockStatus, Totp, TotpError, assess_clock, decode_base32_secret, hotp};

const SEED_SHA1: &[u8] = b"12345678901234567890";
const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

#[test]
fn rfc4226_hotp_vectors() {
    let expected = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    for (counter, want) in expected.iter().enumerate() {
        let got = hotp(SEED_SHA1, counter as u64, 6, Algorithm::Sha1).unwrap();
        assert_eq!(got.as_str(), *want, "counter {counter}");
    }
}

#[test]
fn rfc6238_totp_vectors() {
    let table: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];
    let sha1 = Totp::new(SEED_SHA1, Algorithm::Sha1, 8, 30).unwrap();
    let sha256 = Totp::new(SEED_SHA256, Algorithm::Sha256, 8, 30).unwrap();
    let sha512 = Totp::new(SEED_SHA512, Algorithm::Sha512, 8, 30).unwrap();
    for (t, w1, w256, w512) in table {
        assert_eq!(sha1.code_at(t).unwrap().as_str(), w1, "SHA1 at {t}");
        assert_eq!(sha256.code_at(t).unwrap().as_str(), w256, "SHA256 at {t}");
        assert_eq!(sha512.code_at(t).unwrap().as_str(), w512, "SHA512 at {t}");
    }
}

#[test]
fn six_digit_codes_keep_leading_zeros() {
    // 1111111109 gives 07081804 with 8 digits; with 6 digits: 081804.
    let t = Totp::new(SEED_SHA1, Algorithm::Sha1, 6, 30).unwrap();
    assert_eq!(t.code_at(1_111_111_109).unwrap().as_str(), "081804");
}

#[test]
fn otpauth_uri_parsing() {
    // Base32 of SEED_SHA1 = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    let uri = "otpauth://totp/ACME%20Co:john.doe@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&algorithm=SHA1&digits=8&period=30&image=https%3A%2F%2Fexample.com%2Flogo.png";
    let t = Totp::from_uri(uri).unwrap();
    assert_eq!(t.issuer(), Some("ACME Co"));
    assert_eq!(t.account(), Some("john.doe@example.com"));
    assert_eq!(t.digits(), 8);
    assert_eq!(t.period(), 30);
    assert_eq!(t.algorithm(), Algorithm::Sha1);
    assert_eq!(t.code_at(59).unwrap().as_str(), "94287082");
}

#[test]
fn otpauth_label_with_reserved_characters() {
    let t =
        Totp::from_uri("otpauth://totp/AT&T:john+1@example.com?secret=GEZDGNBVGY3TQOJQ").unwrap();
    assert_eq!(t.issuer(), Some("AT&T"));
    assert_eq!(t.account(), Some("john+1@example.com"));
    // Invalid UTF-8 after decoding is rejected.
    assert_eq!(
        Totp::from_uri("otpauth://totp/%FF?secret=GEZDGNBVGY3TQOJQ").unwrap_err(),
        TotpError::InvalidUri
    );
}

#[test]
fn otpauth_defaults_and_lenient_secret() {
    let t = Totp::from_uri("otpauth://totp/alice?secret=gezd gnbv gy3t qojq gezd gnbv gy3t qojq")
        .unwrap();
    assert_eq!(
        (t.digits(), t.period(), t.algorithm()),
        (6, 30, Algorithm::Sha1)
    );
    assert_eq!(t.issuer(), None);
    assert_eq!(t.account(), Some("alice"));
}

#[test]
fn otpauth_round_trip() {
    let original = Totp::from_uri(
        "otpauth://totp/Example:bob%2Bwork@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA256&digits=7&period=60",
    )
    .unwrap();
    let uri = original.to_uri().unwrap();
    let back = Totp::from_uri(&uri).unwrap();
    assert_eq!(back.issuer(), Some("Example"));
    assert_eq!(back.account(), Some("bob+work@example.com"));
    assert_eq!(
        (back.digits(), back.period(), back.algorithm()),
        (7, 60, Algorithm::Sha256)
    );
    for t in [0u64, 59, 1_234_567_890] {
        assert_eq!(back.code_at(t).unwrap(), original.code_at(t).unwrap());
    }
}

#[test]
fn otpauth_rejections() {
    assert_eq!(
        Totp::from_uri("https://example.com").unwrap_err(),
        TotpError::InvalidUri
    );
    assert_eq!(
        Totp::from_uri("otpauth://hotp/x?secret=GEZDGNBV&counter=1").unwrap_err(),
        TotpError::UnsupportedType
    );
    assert_eq!(
        Totp::from_uri("otpauth://totp/x").unwrap_err(),
        TotpError::InvalidSecret
    );
    assert_eq!(
        Totp::from_uri("otpauth://totp/x?secret=GEZDGNBV&secret=GEZDGNBV").unwrap_err(),
        TotpError::DuplicateParameter("secret")
    );
    assert_eq!(
        Totp::from_uri("otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5").unwrap_err(),
        TotpError::UnsupportedAlgorithm
    );
    assert_eq!(
        Totp::from_uri("otpauth://totp/x?secret=GEZDGNBV&digits=4").unwrap_err(),
        TotpError::InvalidDigits
    );
    assert_eq!(
        Totp::from_uri("otpauth://totp/x?secret=GEZDGNBV&period=0").unwrap_err(),
        TotpError::InvalidPeriod
    );
    assert_eq!(
        Totp::from_uri("otpauth://totp/x?secret=not-base32!").unwrap_err(),
        TotpError::InvalidSecret
    );
}

#[test]
fn base32_decoding() {
    assert_eq!(
        decode_base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .unwrap()
            .as_slice(),
        SEED_SHA1
    );
    assert_eq!(
        decode_base32_secret("gezd-gnbv gy3t qojq gezd gnbv gy3t qojq====")
            .unwrap()
            .as_slice(),
        SEED_SHA1
    );
    assert_eq!(
        decode_base32_secret("").unwrap_err(),
        TotpError::InvalidSecret
    );
    assert_eq!(
        decode_base32_secret("0189").unwrap_err(),
        TotpError::InvalidSecret
    );
}

#[test]
fn seconds_remaining() {
    let t = Totp::new(SEED_SHA1, Algorithm::Sha1, 6, 30).unwrap();
    assert_eq!(t.seconds_remaining(0), 30);
    assert_eq!(t.seconds_remaining(29), 1);
    assert_eq!(t.seconds_remaining(30), 30);
    assert_eq!(t.seconds_remaining(45), 15);
}

#[test]
fn clock_assessment() {
    assert_eq!(assess_clock(1000, 1000, 30), ClockStatus::InSync);
    assert_eq!(assess_clock(1014, 1000, 30), ClockStatus::InSync);
    assert_eq!(
        assess_clock(1015, 1000, 30),
        ClockStatus::Skewed { seconds: 15 }
    );
    assert_eq!(
        assess_clock(900, 1000, 30),
        ClockStatus::Skewed { seconds: -100 }
    );
}

#[test]
fn debug_hides_secret() {
    let t = Totp::new(SEED_SHA1, Algorithm::Sha1, 6, 30).unwrap();
    let printed = format!("{t:?}");
    assert!(printed.contains("<redacted>"));
    assert!(!printed.contains("12345678901234567890"));
}

#[test]
fn invalid_parameters() {
    assert_eq!(
        Totp::new(b"", Algorithm::Sha1, 6, 30).unwrap_err(),
        TotpError::InvalidSecret
    );
    assert_eq!(
        Totp::new(&[0; 129], Algorithm::Sha1, 6, 30).unwrap_err(),
        TotpError::InvalidSecret
    );
    assert_eq!(
        Totp::new(b"k", Algorithm::Sha1, 9, 30).unwrap_err(),
        TotpError::InvalidDigits
    );
    assert_eq!(
        Totp::new(b"k", Algorithm::Sha1, 6, 601).unwrap_err(),
        TotpError::InvalidPeriod
    );
}
