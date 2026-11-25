//! # lk-totp
//!
//! One-time passwords for the Last Keys authenticator:
//!
//! * HOTP (RFC 4226) and TOTP (RFC 6238) with HMAC-SHA1, HMAC-SHA256 or
//!   HMAC-SHA512, 6 to 8 digits;
//! * `otpauth://totp/...` URI parsing and generation (the format of
//!   authenticator QR codes);
//! * clock-skew assessment against a reference time.
//!
//! Secrets are zeroized on drop and never appear in `Debug` output. This crate
//! reads no clock: callers pass Unix times.

#![forbid(unsafe_code)]

use core::fmt;

use data_encoding::{Encoding, Specification};
use hmac::{Hmac, KeyInit, Mac};
use lk_crypto::Zeroizing;
use thiserror::Error;
use url::Url;

/// Errors returned by `lk-totp`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TotpError {
    /// The secret is empty, too long or not valid Base32.
    #[error("invalid TOTP secret")]
    InvalidSecret,
    /// Digits outside 6–8.
    #[error("TOTP codes must have 6 to 8 digits")]
    InvalidDigits,
    /// Period outside 1–600 seconds.
    #[error("TOTP period must be between 1 and 600 seconds")]
    InvalidPeriod,
    /// Unknown hash algorithm.
    #[error("unsupported TOTP algorithm")]
    UnsupportedAlgorithm,
    /// Not an `otpauth://` URI or malformed.
    #[error("invalid otpauth URI")]
    InvalidUri,
    /// `otpauth://hotp` (counter-based) codes are not supported.
    #[error("only time-based (TOTP) codes are supported")]
    UnsupportedType,
    /// A parameter appears more than once.
    #[error("duplicate otpauth parameter: {0}")]
    DuplicateParameter(&'static str),
    /// Label or issuer too long.
    #[error("otpauth label or issuer is too long")]
    LabelTooLong,
}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, TotpError>;

/// HMAC hash function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// HMAC-SHA1 (default; used by most services).
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl Algorithm {
    /// Parses the `algorithm` parameter of an otpauth URI (case-insensitive).
    ///
    /// # Errors
    /// [`TotpError::UnsupportedAlgorithm`] for other values.
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(TotpError::UnsupportedAlgorithm),
        }
    }

    /// Canonical name used in otpauth URIs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// Minimum number of digits.
pub const MIN_DIGITS: u32 = 6;
/// Maximum number of digits.
pub const MAX_DIGITS: u32 = 8;
/// Maximum period in seconds.
pub const MAX_PERIOD: u64 = 600;
/// Maximum secret length in bytes.
pub const MAX_SECRET_LEN: usize = 128;
/// Maximum label or issuer length in bytes.
pub const MAX_LABEL_LEN: usize = 256;

fn base32() -> Result<Encoding> {
    let mut spec = Specification::new();
    spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    spec.translate.from.push_str("abcdefghijklmnopqrstuvwxyz");
    spec.translate.to.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    // Some providers emit non-zero trailing bits; accept them.
    spec.check_trailing_bits = false;
    spec.encoding().map_err(|_| TotpError::InvalidSecret)
}

/// Decodes a Base32 secret as typed or pasted by a user: case-insensitive,
/// spaces, hyphens and `=` padding ignored.
///
/// # Errors
/// [`TotpError::InvalidSecret`] if the result is empty, too long or invalid.
pub fn decode_base32_secret(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .collect(),
    );
    let decoded = Zeroizing::new(
        base32()?
            .decode(cleaned.as_bytes())
            .map_err(|_| TotpError::InvalidSecret)?,
    );
    if decoded.is_empty() || decoded.len() > MAX_SECRET_LEN {
        return Err(TotpError::InvalidSecret);
    }
    Ok(decoded)
}

fn hmac_digest(algorithm: Algorithm, key: &[u8], message: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    macro_rules! mac {
        ($hash:ty) => {{
            let mut mac =
                Hmac::<$hash>::new_from_slice(key).map_err(|_| TotpError::InvalidSecret)?;
            mac.update(message);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }};
    }
    Ok(match algorithm {
        Algorithm::Sha1 => mac!(sha1::Sha1),
        Algorithm::Sha256 => mac!(sha2::Sha256),
        Algorithm::Sha512 => mac!(sha2::Sha512),
    })
}

/// Computes an HOTP value (RFC 4226 §5.3, dynamic truncation).
///
/// # Errors
/// [`TotpError::InvalidDigits`] outside 6–8 digits,
/// [`TotpError::InvalidSecret`] for an empty or oversized secret.
pub fn hotp(
    secret: &[u8],
    counter: u64,
    digits: u32,
    algorithm: Algorithm,
) -> Result<Zeroizing<String>> {
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(TotpError::InvalidDigits);
    }
    if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
        return Err(TotpError::InvalidSecret);
    }
    let mac = hmac_digest(algorithm, secret, &counter.to_be_bytes())?;
    let last = mac.last().copied().ok_or(TotpError::InvalidSecret)?;
    let offset = usize::from(last & 0x0f);
    let window = mac
        .get(offset..offset.saturating_add(4))
        .ok_or(TotpError::InvalidSecret)?;
    let bytes: [u8; 4] = window.try_into().map_err(|_| TotpError::InvalidSecret)?;
    let binary = u32::from_be_bytes(bytes) & 0x7fff_ffff;
    let modulus = 10u32.checked_pow(digits).ok_or(TotpError::InvalidDigits)?;
    let code = binary
        .checked_rem(modulus)
        .ok_or(TotpError::InvalidDigits)?;
    let width = usize::try_from(digits).map_err(|_| TotpError::InvalidDigits)?;
    Ok(Zeroizing::new(format!("{code:0width$}")))
}

/// A TOTP generator configuration (secret + parameters + display labels).
#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
    issuer: Option<String>,
    account: Option<String>,
}

impl Totp {
    /// Default period (30 s).
    pub const DEFAULT_PERIOD: u64 = 30;
    /// Default number of digits (6).
    pub const DEFAULT_DIGITS: u32 = 6;

    /// Builds a configuration from raw secret bytes.
    ///
    /// # Errors
    /// Fails for invalid secret length, digits or period.
    pub fn new(secret: &[u8], algorithm: Algorithm, digits: u32, period: u64) -> Result<Self> {
        if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
            return Err(TotpError::InvalidSecret);
        }
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
            return Err(TotpError::InvalidDigits);
        }
        if !(1..=MAX_PERIOD).contains(&period) {
            return Err(TotpError::InvalidPeriod);
        }
        Ok(Self {
            secret: Zeroizing::new(secret.to_vec()),
            algorithm,
            digits,
            period,
            issuer: None,
            account: None,
        })
    }

    /// Builds a default configuration (SHA1, 6 digits, 30 s) from a Base32
    /// secret entered manually.
    ///
    /// # Errors
    /// [`TotpError::InvalidSecret`] for an invalid secret.
    pub fn from_base32_secret(secret: &str) -> Result<Self> {
        let bytes = decode_base32_secret(secret)?;
        Self::new(
            &bytes,
            Algorithm::Sha1,
            Self::DEFAULT_DIGITS,
            Self::DEFAULT_PERIOD,
        )
    }

    /// Parses an `otpauth://totp/...` URI (as encoded in authenticator QR
    /// codes). Unknown parameters are ignored; duplicated known parameters
    /// are rejected.
    ///
    /// # Errors
    /// See [`TotpError`].
    pub fn from_uri(uri: &str) -> Result<Self> {
        let url = Url::parse(uri.trim()).map_err(|_| TotpError::InvalidUri)?;
        if url.scheme() != "otpauth" {
            return Err(TotpError::InvalidUri);
        }
        match url.host_str().map(str::to_ascii_lowercase).as_deref() {
            Some("totp") => {}
            Some("hotp") => return Err(TotpError::UnsupportedType),
            _ => return Err(TotpError::InvalidUri),
        }
        let raw_label = url.path().strip_prefix('/').unwrap_or(url.path());
        let label: String = percent_decode(raw_label)?;
        let (label_issuer, account) = match label.split_once(':') {
            Some((issuer, account)) => (Some(issuer.trim().to_owned()), account.trim().to_owned()),
            None => (None, label.trim().to_owned()),
        };

        let mut secret: Option<Zeroizing<Vec<u8>>> = None;
        let mut issuer: Option<String> = None;
        let mut algorithm: Option<Algorithm> = None;
        let mut digits: Option<u32> = None;
        let mut period: Option<u64> = None;
        for (key, value) in url.query_pairs() {
            match key.to_ascii_lowercase().as_str() {
                "secret" => set_once(&mut secret, decode_base32_secret(&value)?, "secret")?,
                "issuer" => set_once(&mut issuer, value.trim().to_owned(), "issuer")?,
                "algorithm" => set_once(&mut algorithm, Algorithm::parse(&value)?, "algorithm")?,
                "digits" => set_once(
                    &mut digits,
                    value.parse().map_err(|_| TotpError::InvalidDigits)?,
                    "digits",
                )?,
                "period" => set_once(
                    &mut period,
                    value.parse().map_err(|_| TotpError::InvalidPeriod)?,
                    "period",
                )?,
                _ => {}
            }
        }
        let secret = secret.ok_or(TotpError::InvalidSecret)?;
        let mut totp = Self::new(
            &secret,
            algorithm.unwrap_or(Algorithm::Sha1),
            digits.unwrap_or(Self::DEFAULT_DIGITS),
            period.unwrap_or(Self::DEFAULT_PERIOD),
        )?;
        // The `issuer` parameter takes precedence over the label prefix.
        totp.issuer = issuer.or(label_issuer).filter(|s| !s.is_empty());
        totp.account = Some(account).filter(|s| !s.is_empty());
        if totp
            .issuer
            .as_ref()
            .is_some_and(|s| s.len() > MAX_LABEL_LEN)
            || totp
                .account
                .as_ref()
                .is_some_and(|s| s.len() > MAX_LABEL_LEN)
        {
            return Err(TotpError::LabelTooLong);
        }
        Ok(totp)
    }

    /// Serializes to an `otpauth://totp/...` URI (for export or QR display).
    /// The result contains the secret and is zeroized on drop.
    ///
    /// # Errors
    /// [`TotpError::InvalidUri`] if the URI can not be built (not expected).
    pub fn to_uri(&self) -> Result<Zeroizing<String>> {
        let mut url = Url::parse("otpauth://totp/").map_err(|_| TotpError::InvalidUri)?;
        let label = match (&self.issuer, &self.account) {
            (Some(i), Some(a)) => format!("{i}:{a}"),
            (None, Some(a)) => a.clone(),
            (Some(i), None) => format!("{i}:"),
            (None, None) => String::new(),
        };
        url.set_path(&format!("/{label}"));
        let secret = Zeroizing::new(data_encoding::BASE32_NOPAD.encode(&self.secret));
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("secret", &secret);
            if let Some(issuer) = &self.issuer {
                q.append_pair("issuer", issuer);
            }
            q.append_pair("algorithm", self.algorithm.as_str());
            q.append_pair("digits", &self.digits.to_string());
            q.append_pair("period", &self.period.to_string());
        }
        Ok(Zeroizing::new(url.into()))
    }

    /// Code valid at `unix_time` (seconds).
    ///
    /// # Errors
    /// Not expected for a validated configuration.
    pub fn code_at(&self, unix_time: u64) -> Result<Zeroizing<String>> {
        let counter = unix_time
            .checked_div(self.period)
            .ok_or(TotpError::InvalidPeriod)?;
        hotp(&self.secret, counter, self.digits, self.algorithm)
    }

    /// Seconds until the code shown at `unix_time` expires (1 to `period`).
    #[must_use]
    pub fn seconds_remaining(&self, unix_time: u64) -> u64 {
        let elapsed = unix_time.checked_rem(self.period).unwrap_or(0);
        self.period.saturating_sub(elapsed)
    }

    /// Hash algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Number of digits.
    #[must_use]
    pub const fn digits(&self) -> u32 {
        self.digits
    }

    /// Period in seconds.
    #[must_use]
    pub const fn period(&self) -> u64 {
        self.period
    }

    /// Issuer (service name), if known.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Account name, if known.
    #[must_use]
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }
}

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .finish()
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &'static str) -> Result<()> {
    if slot.is_some() {
        return Err(TotpError::DuplicateParameter(name));
    }
    *slot = Some(value);
    Ok(())
}

/// Decodes `%XX` escapes of a URI path segment. `+` is a literal plus in a
/// path (only `application/x-www-form-urlencoded` queries treat it as space).
fn percent_decode(s: &str) -> Result<String> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| TotpError::InvalidUri)
}

/// Result of comparing the device clock with a trusted reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockStatus {
    /// Skew below half a period: codes are accepted by servers.
    InSync,
    /// Skew of at least half a period: codes may be rejected; the user should
    /// fix the device clock. Positive means the device is ahead.
    Skewed {
        /// Device time minus reference time, in seconds.
        seconds: i64,
    },
}

/// Compares the device clock with a reference time (for example the `Date`
/// of a sync-server response, from M3).
#[must_use]
pub fn assess_clock(device_unix: u64, reference_unix: u64, period: u64) -> ClockStatus {
    let device = i128::from(device_unix);
    let reference = i128::from(reference_unix);
    let skew = device.saturating_sub(reference);
    let threshold = i128::from(period.max(1)).saturating_add(1) / 2;
    if skew.abs() < threshold {
        ClockStatus::InSync
    } else {
        ClockStatus::Skewed {
            seconds: i64::try_from(skew).unwrap_or(if skew > 0 { i64::MAX } else { i64::MIN }),
        }
    }
}
