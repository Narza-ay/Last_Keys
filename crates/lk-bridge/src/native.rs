//! Native messaging: host manifests, where each browser looks for them, and
//! recognition of the arguments a browser passes when it starts the relay.
//!
//! Locations (per user):
//!
//! | Browser | Linux | macOS | Windows (registry key, `HKCU`) |
//! |---------|-------|-------|--------------------------------|
//! | Chrome | `~/.config/google-chrome/NativeMessagingHosts` | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts` | `Software\Google\Chrome\NativeMessagingHosts\<host>` |
//! | Chromium | `~/.config/chromium/NativeMessagingHosts` | `~/Library/Application Support/Chromium/NativeMessagingHosts` | `Software\Chromium\NativeMessagingHosts\<host>` |
//! | Brave | `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts` | `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts` | `Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\<host>` |
//! | Firefox | `~/.mozilla/native-messaging-hosts` | `~/Library/Application Support/Mozilla/NativeMessagingHosts` | `Software\Mozilla\NativeMessagingHosts\<host>` |
//!
//! On Linux, `~/.config` is `$XDG_CONFIG_HOME` when set. On Windows the
//! manifest files live in the application data directory and the registry
//! key's default value points to them.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Name of the native messaging host (provisional, like the application
/// identifier).
pub const HOST_NAME: &str = "app.lastkeys.bridge";

/// Chromium extension IDs allowed to start the relay. The first one is
/// fixed by the development key in `apps/extension/manifest.base.json`;
/// the Chrome Web Store ID is added when the owner publishes the extension.
pub const CHROMIUM_EXTENSION_IDS: &[&str] = &["bblheiicocdmmkjnhdeehaedddgcfhok"];

/// Firefox add-on IDs allowed to start the relay (provisional).
pub const FIREFOX_EXTENSION_IDS: &[&str] = &["browser-extension@lastkeys.app"];

/// Family of a browser: which manifest format and caller arguments it uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserFamily {
    /// Chrome, Chromium, Brave.
    Chromium,
    /// Firefox.
    Firefox,
}

/// A supported browser.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Browser {
    /// Google Chrome.
    Chrome,
    /// Chromium.
    Chromium,
    /// Brave.
    Brave,
    /// Mozilla Firefox.
    Firefox,
}

impl Browser {
    /// Every supported browser.
    pub const ALL: [Self; 4] = [Self::Chrome, Self::Chromium, Self::Brave, Self::Firefox];

    /// Its family.
    #[must_use]
    pub const fn family(self) -> BrowserFamily {
        match self {
            Self::Firefox => BrowserFamily::Firefox,
            _ => BrowserFamily::Chromium,
        }
    }
}

/// Operating system, for locations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    /// Linux.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
}

impl Os {
    /// The system this program was built for.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }
}

/// The user's directories that locations depend on.
#[derive(Clone, Debug)]
pub struct UserDirs {
    /// Home directory.
    pub home: PathBuf,
    /// Configuration directory (`$XDG_CONFIG_HOME` or `~/.config` on Linux).
    pub config: PathBuf,
    /// Application data directory (manifest files on Windows).
    pub app_data: PathBuf,
}

/// Where a browser's manifest goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Place {
    /// Directory whose presence shows that the browser is installed for
    /// this user (Linux, macOS); `None` on Windows, where every key is
    /// written.
    pub browser_dir: Option<PathBuf>,
    /// The manifest file.
    pub manifest: PathBuf,
    /// Registry key whose default value is the manifest's path (Windows).
    pub registry_key: Option<String>,
}

/// Location of a browser's manifest.
#[must_use]
pub fn place(browser: Browser, os: Os, dirs: &UserDirs) -> Place {
    let file = format!("{HOST_NAME}.json");
    match os {
        Os::Linux => {
            let (base, sub) = match browser {
                Browser::Chrome => (dirs.config.join("google-chrome"), "NativeMessagingHosts"),
                Browser::Chromium => (dirs.config.join("chromium"), "NativeMessagingHosts"),
                Browser::Brave => (
                    dirs.config.join("BraveSoftware").join("Brave-Browser"),
                    "NativeMessagingHosts",
                ),
                Browser::Firefox => (dirs.home.join(".mozilla"), "native-messaging-hosts"),
            };
            Place {
                manifest: base.join(sub).join(file),
                browser_dir: Some(base),
                registry_key: None,
            }
        }
        Os::MacOs => {
            let support = dirs.home.join("Library").join("Application Support");
            let base = match browser {
                Browser::Chrome => support.join("Google").join("Chrome"),
                Browser::Chromium => support.join("Chromium"),
                Browser::Brave => support.join("BraveSoftware").join("Brave-Browser"),
                Browser::Firefox => support.join("Mozilla"),
            };
            Place {
                manifest: base.join("NativeMessagingHosts").join(file),
                browser_dir: Some(base),
                registry_key: None,
            }
        }
        Os::Windows => {
            let key = match browser {
                Browser::Chrome => r"Software\Google\Chrome",
                Browser::Chromium => r"Software\Chromium",
                Browser::Brave => r"Software\BraveSoftware\Brave-Browser",
                Browser::Firefox => r"Software\Mozilla",
            };
            let name = match browser.family() {
                BrowserFamily::Chromium => "chromium.json",
                BrowserFamily::Firefox => "firefox.json",
            };
            Place {
                browser_dir: None,
                manifest: dirs.app_data.join("native-messaging").join(name),
                registry_key: Some(format!(r"HKCU\{key}\NativeMessagingHosts\{HOST_NAME}")),
            }
        }
    }
}

#[derive(Serialize)]
struct Manifest<'a> {
    name: &'a str,
    description: &'a str,
    path: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_origins: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_extensions: Option<Vec<String>>,
}

/// Content of a host manifest that starts `host_path` for the allowed
/// extensions of `family`.
#[must_use]
pub fn manifest_json(family: BrowserFamily, host_path: &str) -> String {
    let (allowed_origins, allowed_extensions) = match family {
        BrowserFamily::Chromium => (
            Some(
                CHROMIUM_EXTENSION_IDS
                    .iter()
                    .map(|id| format!("chrome-extension://{id}/"))
                    .collect(),
            ),
            None,
        ),
        BrowserFamily::Firefox => (
            None,
            Some(
                FIREFOX_EXTENSION_IDS
                    .iter()
                    .map(|id| (*id).to_owned())
                    .collect(),
            ),
        ),
    };
    let manifest = Manifest {
        name: HOST_NAME,
        description: "Last Keys browser bridge",
        path: host_path,
        kind: "stdio",
        allowed_origins,
        allowed_extensions,
    };
    // Serializing this struct of strings cannot fail.
    serde_json::to_string_pretty(&manifest).unwrap_or_default()
}

/// The extension that started the relay, as the browser reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// Browser family.
    pub family: BrowserFamily,
    /// Chromium extension ID or Firefox add-on ID.
    pub extension: String,
}

fn is_chromium_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

fn is_firefox_id(id: &str) -> bool {
    let well_formed = id.len() <= 80
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+@{}".contains(&b));
    let shaped = (id.starts_with('{') && id.ends_with('}')) || id.contains('@');
    well_formed && shaped
}

/// Recognises a relay invocation from the process arguments (`args[0]` is
/// the program): Chromium passes `chrome-extension://<id>/` (then, on
/// Windows, `--parent-window=<n>`); Firefox passes the manifest path and the
/// add-on ID. Anything else is a normal start of the application.
#[must_use]
pub fn caller_from_args<S: AsRef<str>>(args: &[S]) -> Option<Caller> {
    let first = args.get(1)?.as_ref();
    if let Some(rest) = first.strip_prefix("chrome-extension://") {
        let id = rest.strip_suffix('/').unwrap_or(rest);
        let extra_ok = args
            .get(2..)
            .unwrap_or_default()
            .iter()
            .all(|a| a.as_ref().starts_with("--parent-window="));
        return (is_chromium_id(id) && extra_ok).then(|| Caller {
            family: BrowserFamily::Chromium,
            extension: id.to_owned(),
        });
    }
    if args.len() == 3 && Path::new(first).extension().is_some_and(|e| e == "json") {
        let id = args.get(2)?.as_ref();
        return is_firefox_id(id).then(|| Caller {
            family: BrowserFamily::Firefox,
            extension: id.to_owned(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn dirs() -> UserDirs {
        UserDirs {
            home: PathBuf::from("/home/alice"),
            config: PathBuf::from("/home/alice/.config"),
            app_data: PathBuf::from("/data"),
        }
    }

    #[test]
    fn places() {
        let p = place(Browser::Chrome, Os::Linux, &dirs());
        assert_eq!(
            p.manifest,
            Path::new(
                "/home/alice/.config/google-chrome/NativeMessagingHosts/app.lastkeys.bridge.json"
            )
        );
        assert_eq!(
            p.browser_dir.unwrap(),
            Path::new("/home/alice/.config/google-chrome")
        );
        assert_eq!(
            place(Browser::Brave, Os::Linux, &dirs()).manifest,
            Path::new(
                "/home/alice/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/app.lastkeys.bridge.json"
            )
        );
        assert_eq!(
            place(Browser::Firefox, Os::Linux, &dirs()).manifest,
            Path::new("/home/alice/.mozilla/native-messaging-hosts/app.lastkeys.bridge.json")
        );
        assert_eq!(
            place(Browser::Chromium, Os::MacOs, &dirs()).manifest,
            Path::new(
                "/home/alice/Library/Application Support/Chromium/NativeMessagingHosts/app.lastkeys.bridge.json"
            )
        );
        assert_eq!(
            place(Browser::Firefox, Os::MacOs, &dirs()).manifest,
            Path::new(
                "/home/alice/Library/Application Support/Mozilla/NativeMessagingHosts/app.lastkeys.bridge.json"
            )
        );
        let w = place(Browser::Brave, Os::Windows, &dirs());
        assert_eq!(w.browser_dir, None);
        assert_eq!(
            w.manifest,
            Path::new("/data/native-messaging/chromium.json")
        );
        assert_eq!(
            w.registry_key.unwrap(),
            r"HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\app.lastkeys.bridge"
        );
        assert_eq!(
            place(Browser::Firefox, Os::Windows, &dirs()).manifest,
            Path::new("/data/native-messaging/firefox.json")
        );
    }

    #[test]
    fn manifests() {
        let chromium: serde_json::Value =
            serde_json::from_str(&manifest_json(BrowserFamily::Chromium, "/opt/lk/last-keys"))
                .unwrap();
        assert_eq!(
            chromium,
            serde_json::json!({
                "name": "app.lastkeys.bridge",
                "description": "Last Keys browser bridge",
                "path": "/opt/lk/last-keys",
                "type": "stdio",
                "allowed_origins": ["chrome-extension://bblheiicocdmmkjnhdeehaedddgcfhok/"]
            })
        );
        let firefox: serde_json::Value = serde_json::from_str(&manifest_json(
            BrowserFamily::Firefox,
            r"C:\LK\last-keys.exe",
        ))
        .unwrap();
        assert_eq!(
            firefox["allowed_extensions"],
            serde_json::json!(["browser-extension@lastkeys.app"])
        );
        assert_eq!(firefox["path"], r"C:\LK\last-keys.exe");
        assert!(firefox.get("allowed_origins").is_none());
        for id in CHROMIUM_EXTENSION_IDS {
            assert!(is_chromium_id(id));
        }
        for id in FIREFOX_EXTENSION_IDS {
            assert!(is_firefox_id(id));
        }
    }

    #[test]
    fn relay_arguments() {
        let id = "bblheiicocdmmkjnhdeehaedddgcfhok";
        let chromium = Caller {
            family: BrowserFamily::Chromium,
            extension: id.to_owned(),
        };
        let origin = format!("chrome-extension://{id}/");
        assert_eq!(caller_from_args(&["lk", &origin]), Some(chromium.clone()));
        assert_eq!(
            caller_from_args(&["lk", &origin, "--parent-window=1234"]),
            Some(chromium)
        );
        let firefox = caller_from_args(&[
            "lk",
            "/home/a/.mozilla/native-messaging-hosts/app.lastkeys.bridge.json",
            "browser-extension@lastkeys.app",
        ]);
        assert_eq!(
            firefox,
            Some(Caller {
                family: BrowserFamily::Firefox,
                extension: "browser-extension@lastkeys.app".to_owned()
            })
        );
        assert!(
            caller_from_args(&[
                "lk",
                "C:\\x\\m.json",
                "{0c1d6f3e-aaaa-4bbb-8ccc-123456789abc}"
            ])
            .is_some()
        );
        for args in [
            &["lk"][..],
            &["lk", "--help"],
            &["lk", "chrome-extension://short/"],
            &["lk", "chrome-extension://BBLHEIICOCDMMKJNHDEEHAEDDDGCFHOK/"],
            &["lk", &origin, "--other"],
            &["lk", "manifest.json", "no-at-sign"],
            &["lk", "manifest.txt", "a@b"],
            &["lk", "manifest.json", "a@b", "extra"],
            &["lk", "manifest.json", "a@b c"],
        ] {
            assert_eq!(caller_from_args(args), None, "{args:?}");
        }
    }
}
