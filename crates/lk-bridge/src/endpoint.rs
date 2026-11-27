//! Name of the desktop's local endpoint, derived from the application data
//! directory so that the desktop and its relay always agree (including with
//! `LK_DESKTOP_DATA_DIR`).

use std::path::{Path, PathBuf};

use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};

/// Application identifier (provisional, ADR-0010); must equal the
/// `identifier` of `tauri.conf.json`.
pub const APP_IDENTIFIER: &str = "app.lastkeys.desktop";

/// The local endpoint of the desktop bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// Unix domain socket (Linux, macOS).
    Unix(PathBuf),
    /// Named pipe (Windows).
    Pipe(String),
}

/// Directory of the socket: private to the user (created with mode `0700`).
#[must_use]
pub fn socket_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("bridge")
}

/// Unix socket path for a data directory.
#[must_use]
pub fn socket_path(data_dir: &Path) -> PathBuf {
    socket_dir(data_dir).join("bridge.sock")
}

/// Named pipe for a data directory: the pipe namespace is shared by every
/// user of a Windows machine, so the name includes a digest of the user's
/// data directory (case-insensitive, as Windows paths are).
#[must_use]
pub fn pipe_name(data_dir: &Path) -> String {
    let path = data_dir.to_string_lossy().to_lowercase();
    let digest = Sha256::digest(path.as_bytes());
    let short = HEXLOWER.encode(digest.get(..8).unwrap_or_default());
    format!(r"\\.\pipe\{APP_IDENTIFIER}.bridge.{short}")
}

/// The endpoint of this platform.
#[must_use]
pub fn endpoint(data_dir: &Path) -> Endpoint {
    if cfg!(windows) {
        Endpoint::Pipe(pipe_name(data_dir))
    } else {
        Endpoint::Unix(socket_path(data_dir))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let dir = Path::new("/home/alice/.local/share/app.lastkeys.desktop");
        assert_eq!(
            socket_path(dir),
            Path::new("/home/alice/.local/share/app.lastkeys.desktop/bridge/bridge.sock")
        );
        let pipe = pipe_name(Path::new(
            r"C:\Users\Alice\AppData\Roaming\app.lastkeys.desktop",
        ));
        assert!(pipe.starts_with(r"\\.\pipe\app.lastkeys.desktop.bridge."));
        assert_eq!(
            pipe.len(),
            r"\\.\pipe\app.lastkeys.desktop.bridge.".len() + 16
        );
        // Case-insensitive, distinct per user.
        assert_eq!(
            pipe,
            pipe_name(Path::new(
                r"c:\users\alice\appdata\roaming\app.lastkeys.desktop"
            ))
        );
        assert_ne!(
            pipe,
            pipe_name(Path::new(
                r"C:\Users\Bob\AppData\Roaming\app.lastkeys.desktop"
            ))
        );
        match endpoint(dir) {
            Endpoint::Unix(p) if !cfg!(windows) => assert_eq!(p, socket_path(dir)),
            Endpoint::Pipe(p) if cfg!(windows) => assert_eq!(p, pipe_name(dir)),
            other => unreachable!("{other:?}"),
        }
    }
}
