//! Registration of the native messaging host with each browser: manifest
//! files (and, on Windows, registry keys) written when the user turns on
//! browser integration, refreshed at each start (the executable may have
//! moved after an update) and removed when it is turned off.

use std::path::{Path, PathBuf};

use lk_bridge::native::{Os, Place, UserDirs, manifest_json, place};
use lk_bridge::{Browser, HOST_NAME};
use serde::Serialize;

/// State of one browser.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallState {
    /// The manifest is in place and points to this executable.
    Installed,
    /// The browser does not seem to be installed for this user.
    NotDetected,
    /// Not registered (integration off, or the executable moved).
    NotInstalled,
    /// Writing the manifest failed.
    Failed,
}

/// A browser and its state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatus {
    /// Browser.
    pub browser: Browser,
    /// State.
    pub state: InstallState,
}

/// The executable browsers must start: the AppImage file when running from
/// one (the mount point disappears when the application exits), otherwise
/// this executable.
///
/// # Errors
/// When the path of the executable cannot be determined.
pub fn host_path() -> std::io::Result<PathBuf> {
    if let Some(appimage) = std::env::var_os("APPIMAGE").map(PathBuf::from)
        && appimage.is_file()
    {
        return Ok(appimage);
    }
    std::env::current_exe()
}

/// The user's directories for this platform.
#[must_use]
pub fn user_dirs(app_data: &Path) -> Option<UserDirs> {
    let home = dirs::home_dir()?;
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    Some(UserDirs {
        home,
        config,
        app_data: app_data.to_owned(),
    })
}

fn detected(place: &Place) -> bool {
    place.browser_dir.as_ref().is_none_or(|dir| dir.is_dir())
}

fn write_manifest(place: &Place, content: &str) -> std::io::Result<()> {
    if let Some(parent) = place.manifest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = place.manifest.with_extension("json.tmp");
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, &place.manifest)?;
    if let Some(key) = &place.registry_key {
        registry_set(key, &place.manifest)?;
    }
    Ok(())
}

/// Registers the host with every detected browser.
#[must_use]
pub fn install(os: Os, dirs: &UserDirs, host: &Path) -> Vec<BrowserStatus> {
    let host = host.to_string_lossy();
    Browser::ALL
        .iter()
        .map(|&browser| {
            let place = place(browser, os, dirs);
            let state = if !detected(&place) {
                InstallState::NotDetected
            } else if write_manifest(&place, &manifest_json(browser.family(), &host)).is_ok() {
                InstallState::Installed
            } else {
                InstallState::Failed
            };
            BrowserStatus { browser, state }
        })
        .collect()
}

/// Removes what [`install`] wrote (only files that are this host's
/// manifests).
pub fn uninstall(os: Os, dirs: &UserDirs) {
    for browser in Browser::ALL {
        let place = place(browser, os, dirs);
        let ours = std::fs::read_to_string(&place.manifest)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .is_some_and(|v| v.get("name").and_then(|n| n.as_str()) == Some(HOST_NAME));
        if ours {
            let _ = std::fs::remove_file(&place.manifest);
        }
        if let Some(key) = &place.registry_key {
            let _ = registry_delete(key);
        }
    }
}

/// Current state of each browser.
#[must_use]
pub fn status(os: Os, dirs: &UserDirs, host: &Path) -> Vec<BrowserStatus> {
    let host = host.to_string_lossy();
    Browser::ALL
        .iter()
        .map(|&browser| {
            let place = place(browser, os, dirs);
            let expected = manifest_json(browser.family(), &host);
            let state = if !detected(&place) {
                InstallState::NotDetected
            } else if std::fs::read_to_string(&place.manifest).is_ok_and(|t| t == expected) {
                InstallState::Installed
            } else {
                InstallState::NotInstalled
            };
            BrowserStatus { browser, state }
        })
        .collect()
}

#[cfg(windows)]
fn registry_set(key: &str, manifest: &Path) -> std::io::Result<()> {
    let status = std::process::Command::new("reg")
        .args(["add", key, "/ve", "/t", "REG_SZ", "/f", "/d"])
        .arg(manifest)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("reg add failed"))
    }
}

#[cfg(windows)]
fn registry_delete(key: &str) -> std::io::Result<()> {
    std::process::Command::new("reg")
        .args(["delete", key, "/f"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|_| ())
}

#[cfg(not(windows))]
fn registry_set(_key: &str, _manifest: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no registry on this platform",
    ))
}

#[cfg(not(windows))]
fn registry_delete(_key: &str) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn dirs(root: &Path) -> UserDirs {
        UserDirs {
            home: root.join("home"),
            config: root.join("home/.config"),
            app_data: root.join("data"),
        }
    }

    #[test]
    fn install_status_uninstall_on_linux_and_macos() {
        for os in [Os::Linux, Os::MacOs] {
            let root = tempfile::tempdir().unwrap();
            let d = dirs(root.path());
            let host = Path::new("/opt/Last Keys/last-keys");
            // Only Chromium and Firefox are installed for this user.
            for browser in [Browser::Chromium, Browser::Firefox] {
                std::fs::create_dir_all(place(browser, os, &d).browser_dir.unwrap()).unwrap();
            }
            let states: Vec<_> = install(os, &d, host).into_iter().map(|s| s.state).collect();
            assert_eq!(
                states,
                [
                    InstallState::NotDetected,
                    InstallState::Installed,
                    InstallState::NotDetected,
                    InstallState::Installed
                ],
                "{os:?}"
            );
            let chromium = place(Browser::Chromium, os, &d).manifest;
            let text = std::fs::read_to_string(&chromium).unwrap();
            assert_eq!(
                text,
                manifest_json(Browser::Chromium.family(), &host.to_string_lossy())
            );
            assert!(!place(Browser::Chrome, os, &d).manifest.exists());
            assert_eq!(status(os, &d, host), install(os, &d, host));
            // After the executable moved, the manifests are stale.
            let moved = status(os, &d, Path::new("/elsewhere/last-keys"));
            assert_eq!(moved[1].state, InstallState::NotInstalled);
            // A foreign file with the same name is not removed.
            let firefox = place(Browser::Firefox, os, &d).manifest;
            std::fs::write(&firefox, r#"{"name":"something.else"}"#).unwrap();
            uninstall(os, &d);
            assert!(!chromium.exists());
            assert!(firefox.exists());
            assert_eq!(status(os, &d, host)[1].state, InstallState::NotInstalled);
        }
    }
}
