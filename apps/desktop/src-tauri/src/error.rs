//! Errors sent to the user interface: a stable code (translated by the UI)
//! and a secret-free message (for logs and unexpected cases).

use serde::Serialize;

/// An error as the web view receives it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiError {
    /// Stable code: an `lk_client::ErrorKind` value, or one of `locked`,
    /// `invalid_setting`, `clipboard`, `internal`.
    pub kind: String,
    /// English description without secrets.
    pub message: String,
}

impl UiError {
    /// An error with an explicit code.
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_owned(),
            message: message.into(),
        }
    }

    /// The vault is locked.
    pub fn locked() -> Self {
        Self::new("locked", "the vault is locked")
    }

    /// Unexpected internal failure.
    pub fn internal() -> Self {
        Self::new("internal", "internal error")
    }
}

impl From<lk_client::ClientError> for UiError {
    fn from(e: lk_client::ClientError) -> Self {
        let kind = match serde_json::to_value(e.kind()) {
            Ok(serde_json::Value::String(kind)) => kind,
            _ => "internal".to_owned(),
        };
        Self {
            kind,
            message: e.to_string(),
        }
    }
}

impl From<lk_generator::GeneratorError> for UiError {
    fn from(e: lk_generator::GeneratorError) -> Self {
        Self::new("invalid_input", e.to_string())
    }
}

/// Result alias of the desktop back end.
pub type UiResult<T> = Result<T, UiError>;

#[cfg(test)]
mod tests {
    /// Codes produced by the desktop back end itself.
    const DESKTOP_KINDS: &[&str] = &[
        "locked",
        "invalid_setting",
        "clipboard",
        "internal",
        "invalid_input",
        "invalid_recovery_key",
    ];

    #[test]
    fn every_error_code_is_translated_by_the_ui() {
        let catalogue = include_str!("../../src/i18n/en.ts");
        let mut kinds: Vec<String> = lk_client::ErrorKind::ALL
            .iter()
            .map(|k| match serde_json::to_value(k) {
                Ok(serde_json::Value::String(s)) => s,
                other => panic!("unexpected serialization {other:?}"),
            })
            .collect();
        kinds.extend(DESKTOP_KINDS.iter().map(|k| (*k).to_owned()));
        for kind in kinds {
            assert!(
                catalogue.contains(&format!("\"error.{kind}\":")),
                "no translation for error code {kind}"
            );
        }
    }
}
