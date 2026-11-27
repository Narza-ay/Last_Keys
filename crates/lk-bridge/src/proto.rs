//! Requests received by the desktop: the relay's announcement, then the
//! extension's requests. Responses are built by the desktop (they carry
//! view types of `lk-client`) and documented in `docs/API.md`.

use serde::{Deserialize, Deserializer};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::native::BrowserFamily;

/// Longest accepted page or frame URL (bytes).
pub const MAX_URL: usize = 8 * 1024;
/// Longest accepted text field: username, client name, identifiers (bytes).
pub const MAX_TEXT: usize = 1024;
/// Longest accepted submitted password (bytes).
pub const MAX_PASSWORD: usize = 4 * 1024;

/// A secret text received from the extension (wiped when dropped, never
/// printed).
#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    /// The value. Callers must not log or persist it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretText(..)")
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(Zeroizing::new(String::deserialize(d)?)))
    }
}

/// Field copied by the desktop on behalf of the extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyField {
    /// Username.
    Username,
    /// Password.
    Password,
    /// Current TOTP code.
    Totp,
}

/// A request and its identifier (echoed by the response).
#[derive(Debug, Deserialize)]
pub struct Incoming {
    /// Request identifier chosen by the sender.
    pub id: u32,
    /// The request.
    #[serde(flatten)]
    pub request: Request,
}

/// Every request the desktop accepts.
#[derive(Debug, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
#[non_exhaustive]
pub enum Request {
    /// First frame of a connection, sent by the relay: who started it,
    /// according to the arguments the browser passed.
    Relay {
        /// Chromium extension ID or Firefox add-on ID.
        caller: String,
        /// Browser family.
        browser: BrowserFamily,
        /// Version of the relay (the desktop executable).
        version: String,
    },
    /// Starts a pairing; answered by `pairing` (the code to show) and later
    /// `paired` or an error.
    Pair {
        /// Name the extension gives itself (browser and platform).
        client_name: String,
    },
    /// First step of authentication.
    Hello {
        /// The paired client's ID.
        client_id: String,
        /// The extension's nonce (Base64).
        nonce: String,
    },
    /// Last step of authentication.
    Auth {
        /// The extension's proof (Base64).
        proof: String,
    },
    /// Lock state and versions.
    Status,
    /// Brings the desktop window to the front (to unlock it).
    Focus,
    /// Logins that match the top-level page.
    List {
        /// URL of the active tab.
        page_url: String,
    },
    /// Credentials of one login, for the frame that holds the form.
    Fill {
        /// Item ID.
        item_id: String,
        /// URL of the top-level page.
        page_url: String,
        /// URL of the frame that holds the form.
        frame_url: String,
        /// The user confirmed filling a frame of another origin.
        #[serde(default)]
        cross_origin_confirmed: bool,
    },
    /// The desktop copies one field to the clipboard.
    Copy {
        /// Item ID.
        item_id: String,
        /// URL of the top-level page.
        page_url: String,
        /// Field.
        field: CopyField,
    },
    /// A new password from the desktop's generator.
    Generate,
    /// What to propose for credentials submitted on a page.
    SaveCheck {
        /// URL of the page where they were submitted.
        page_url: String,
        /// Submitted username, if any.
        #[serde(default)]
        username: Option<String>,
        /// Submitted password.
        password: SecretText,
    },
    /// Saves submitted credentials (after the user confirmed in the popup).
    Save {
        /// URL of the page where they were submitted.
        page_url: String,
        /// Submitted username, if any.
        #[serde(default)]
        username: Option<String>,
        /// Submitted password.
        password: SecretText,
        /// Login whose password is replaced; a new login when absent.
        #[serde(default)]
        update_id: Option<String>,
    },
}

/// Why a frame is not an acceptable request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// Not a JSON object of a known request type.
    #[error("malformed request")]
    Malformed,
    /// A field exceeds its limit.
    #[error("{0} is too long")]
    TooLong(&'static str),
}

fn check(value: &str, max: usize, what: &'static str) -> Result<(), ProtoError> {
    if value.len() > max {
        return Err(ProtoError::TooLong(what));
    }
    Ok(())
}

impl Request {
    fn check_lengths(&self) -> Result<(), ProtoError> {
        match self {
            Self::Relay {
                caller, version, ..
            } => {
                check(caller, MAX_TEXT, "caller")?;
                check(version, MAX_TEXT, "version")
            }
            Self::Pair { client_name } => check(client_name, MAX_TEXT, "client name"),
            Self::Hello { client_id, nonce } => {
                check(client_id, MAX_TEXT, "client ID")?;
                check(nonce, MAX_TEXT, "nonce")
            }
            Self::Auth { proof } => check(proof, MAX_TEXT, "proof"),
            Self::Status | Self::Focus | Self::Generate => Ok(()),
            Self::List { page_url } => check(page_url, MAX_URL, "page URL"),
            Self::Fill {
                item_id,
                page_url,
                frame_url,
                ..
            } => {
                check(item_id, MAX_TEXT, "item ID")?;
                check(page_url, MAX_URL, "page URL")?;
                check(frame_url, MAX_URL, "frame URL")
            }
            Self::Copy {
                item_id, page_url, ..
            } => {
                check(item_id, MAX_TEXT, "item ID")?;
                check(page_url, MAX_URL, "page URL")
            }
            Self::SaveCheck {
                page_url,
                username,
                password,
            }
            | Self::Save {
                page_url,
                username,
                password,
                ..
            } => {
                check(page_url, MAX_URL, "page URL")?;
                check(
                    username.as_deref().unwrap_or_default(),
                    MAX_TEXT,
                    "username",
                )?;
                check(password.expose(), MAX_PASSWORD, "password")?;
                if let Self::Save {
                    update_id: Some(id),
                    ..
                } = self
                {
                    check(id, MAX_TEXT, "item ID")?;
                }
                Ok(())
            }
        }
    }
}

/// Parses and checks a request frame.
///
/// # Errors
/// [`ProtoError`].
pub fn parse_request(body: &[u8]) -> Result<Incoming, ProtoError> {
    let incoming: Incoming = serde_json::from_slice(body).map_err(|_| ProtoError::Malformed)?;
    incoming.request.check_lengths()?;
    Ok(incoming)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn parses_every_request() {
        let cases = [
            r#"{"id":0,"type":"relay","caller":"bblheiicocdmmkjnhdeehaedddgcfhok","browser":"chromium","version":"0.1.0"}"#,
            r#"{"id":1,"type":"pair","clientName":"Chrome on Linux"}"#,
            r#"{"id":2,"type":"hello","clientId":"00112233445566778899aabbccddeeff","nonce":"AQ=="}"#,
            r#"{"id":3,"type":"auth","proof":"AQ=="}"#,
            r#"{"id":4,"type":"status"}"#,
            r#"{"id":5,"type":"focus"}"#,
            r#"{"id":6,"type":"list","pageUrl":"https://example.com/"}"#,
            r#"{"id":7,"type":"fill","itemId":"x","pageUrl":"https://a/","frameUrl":"https://a/"}"#,
            r#"{"id":8,"type":"copy","itemId":"x","pageUrl":"https://a/","field":"totp"}"#,
            r#"{"id":9,"type":"generate"}"#,
            r#"{"id":10,"type":"save_check","pageUrl":"https://a/","username":"u","password":"p"}"#,
            r#"{"id":11,"type":"save","pageUrl":"https://a/","password":"p","updateId":"x"}"#,
        ];
        for (i, text) in cases.iter().enumerate() {
            let incoming = parse_request(text.as_bytes()).unwrap();
            assert_eq!(incoming.id as usize, i, "{text}");
        }
        let Request::Fill {
            cross_origin_confirmed,
            ..
        } = parse_request(cases[7].as_bytes()).unwrap().request
        else {
            panic!()
        };
        assert!(!cross_origin_confirmed);
        let Request::Save {
            username, password, ..
        } = parse_request(cases[11].as_bytes()).unwrap().request
        else {
            panic!()
        };
        assert_eq!(username, None);
        assert_eq!(password.expose(), "p");
        assert_eq!(format!("{password:?}"), "SecretText(..)");
    }

    #[test]
    fn refuses_malformed_and_oversized_requests() {
        for bad in [
            "",
            "[]",
            "null",
            r#"{"type":"status"}"#,
            r#"{"id":-1,"type":"status"}"#,
            r#"{"id":1}"#,
            r#"{"id":1,"type":"unknown"}"#,
            r#"{"id":1,"type":"list"}"#,
            r#"{"id":1,"type":"copy","itemId":"x","pageUrl":"https://a/","field":"notes"}"#,
            r#"{"id":1,"type":"fill","itemId":1,"pageUrl":"https://a/","frameUrl":"https://a/"}"#,
        ] {
            assert_eq!(
                parse_request(bad.as_bytes()).unwrap_err(),
                ProtoError::Malformed,
                "{bad}"
            );
        }
        let long_url = format!(
            r#"{{"id":1,"type":"list","pageUrl":"https://a/{}"}}"#,
            "x".repeat(MAX_URL)
        );
        assert_eq!(
            parse_request(long_url.as_bytes()).unwrap_err(),
            ProtoError::TooLong("page URL")
        );
        let long_password = format!(
            r#"{{"id":1,"type":"save","pageUrl":"https://a/","password":"{}"}}"#,
            "p".repeat(MAX_PASSWORD + 1)
        );
        assert_eq!(
            parse_request(long_password.as_bytes()).unwrap_err(),
            ProtoError::TooLong("password")
        );
    }
}
