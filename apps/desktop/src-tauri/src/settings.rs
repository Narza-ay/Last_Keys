//! Non-secret preferences, stored as JSON next to the vault.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{UiError, UiResult};

/// Interface language.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// Follow the operating system (French if it is French, else English).
    #[default]
    System,
    /// French.
    Fr,
    /// English.
    En,
}

/// Colour theme.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    /// Follow the operating system.
    #[default]
    System,
    /// Light.
    Light,
    /// Dark.
    Dark,
}

/// Allowed auto-lock delays (minutes).
pub const AUTO_LOCK_MINUTES: core::ops::RangeInclusive<u32> = 1..=240;
/// Allowed clipboard clearing delays (seconds).
pub const CLIPBOARD_CLEAR_SECONDS: core::ops::RangeInclusive<u32> = 10..=300;

/// User preferences.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct Settings {
    /// Interface language.
    pub language: Language,
    /// Colour theme.
    pub theme: Theme,
    /// Lock after this many minutes without activity.
    pub auto_lock_minutes: u32,
    /// Clear a copied secret from the clipboard after this many seconds.
    pub clipboard_clear_seconds: u32,
    /// The browser extension may connect (ADR-0011). Off until the user
    /// turns it on; changed only through its own command.
    pub browser_integration: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: Language::System,
            theme: Theme::System,
            auto_lock_minutes: 5,
            clipboard_clear_seconds: 30,
            browser_integration: false,
        }
    }
}

impl Settings {
    /// Checks the ranges.
    ///
    /// # Errors
    /// `invalid_setting` when a value is out of range.
    pub fn validate(&self) -> UiResult<()> {
        if !AUTO_LOCK_MINUTES.contains(&self.auto_lock_minutes) {
            return Err(UiError::new(
                "invalid_setting",
                "auto-lock delay out of range",
            ));
        }
        if !CLIPBOARD_CLEAR_SECONDS.contains(&self.clipboard_clear_seconds) {
            return Err(UiError::new(
                "invalid_setting",
                "clipboard delay out of range",
            ));
        }
        Ok(())
    }

    /// Reads the settings; a missing, unreadable or invalid file gives the
    /// defaults (preferences are never worth refusing to start).
    #[must_use]
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Self>(&bytes).ok())
            .filter(|s| s.validate().is_ok())
            .unwrap_or_default()
    }

    /// Writes the settings atomically (temporary file, then rename).
    ///
    /// # Errors
    /// `internal` on file-system errors.
    pub fn save(&self, path: &Path) -> UiResult<()> {
        let io = |_| UiError::new("internal", "cannot save the settings");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| UiError::internal())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).map_err(io)?;
        std::fs::rename(&tmp, path).map_err(io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn defaults_ranges_and_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("settings.json");
        assert_eq!(Settings::load(&path), Settings::default());
        let s = Settings {
            language: Language::Fr,
            theme: Theme::Dark,
            auto_lock_minutes: 15,
            clipboard_clear_seconds: 45,
            browser_integration: true,
        };
        s.save(&path).unwrap();
        assert_eq!(Settings::load(&path), s);
        for bad in [
            Settings {
                auto_lock_minutes: 0,
                ..s.clone()
            },
            Settings {
                auto_lock_minutes: 241,
                ..s.clone()
            },
            Settings {
                clipboard_clear_seconds: 5,
                ..s.clone()
            },
        ] {
            assert_eq!(bad.validate().unwrap_err().kind, "invalid_setting");
        }
        // Corrupted or out-of-range files fall back to the defaults.
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
        std::fs::write(&path, br#"{"autoLockMinutes": 100000}"#).unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
        // Missing fields take their defaults.
        std::fs::write(&path, br#"{"theme": "light"}"#).unwrap();
        assert_eq!(Settings::load(&path).theme, Theme::Light);
        assert_eq!(Settings::load(&path).auto_lock_minutes, 5);
    }
}
