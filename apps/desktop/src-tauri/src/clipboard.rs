//! Clipboard access from Rust only (ADR-0010): copied secrets are marked
//! as excluded from clipboard history where supported, and cleared after a
//! delay or on lock, but only if the clipboard still holds them (the user
//! may have copied something else meanwhile).

use std::time::{Duration, Instant};

use lk_client::Zeroizing;
use sha2::{Digest, Sha256};

use crate::error::{UiError, UiResult};

/// A system clipboard (an in-memory one in tests).
pub trait ClipboardBackend: Send {
    /// Puts a secret on the clipboard.
    ///
    /// # Errors
    /// A description of the platform error.
    fn set_secret(&mut self, text: &str) -> Result<(), String>;
    /// Current text, if any.
    fn text(&mut self) -> Option<Zeroizing<String>>;
    /// Empties the clipboard.
    ///
    /// # Errors
    /// A description of the platform error.
    fn clear(&mut self) -> Result<(), String>;
}

/// The operating system clipboard through `arboard`. The handle is kept for
/// the life of the application: on X11 and Wayland the content is served by
/// the owning process.
#[derive(Default)]
pub struct SystemClipboard {
    inner: Option<arboard::Clipboard>,
}

impl SystemClipboard {
    fn handle(&mut self) -> Result<&mut arboard::Clipboard, String> {
        if self.inner.is_none() {
            self.inner = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
        }
        self.inner
            .as_mut()
            .ok_or_else(|| "clipboard unavailable".to_owned())
    }
}

impl ClipboardBackend for SystemClipboard {
    fn set_secret(&mut self, text: &str) -> Result<(), String> {
        let set = self.handle()?.set();
        #[cfg(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        let set = {
            use arboard::SetExtLinux;
            set.exclude_from_history()
        };
        #[cfg(target_os = "macos")]
        let set = {
            use arboard::SetExtApple;
            set.exclude_from_history()
        };
        #[cfg(target_os = "windows")]
        let set = {
            use arboard::SetExtWindows;
            set.exclude_from_monitoring()
        };
        set.text(text).map_err(|e| e.to_string())
    }

    fn text(&mut self) -> Option<Zeroizing<String>> {
        self.handle().ok()?.get_text().ok().map(Zeroizing::new)
    }

    fn clear(&mut self) -> Result<(), String> {
        self.handle()?.clear().map_err(|e| e.to_string())
    }
}

fn digest(text: &str) -> [u8; 32] {
    let digest = Sha256::new()
        .chain_update(b"lk-desktop clipboard\0")
        .chain_update(text.as_bytes())
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

struct Pending {
    /// Hash of the copied value (the value itself is not kept).
    digest: [u8; 32],
    clear_at: Instant,
}

/// Copies values and clears them later.
pub struct ClipboardGuard {
    backend: Box<dyn ClipboardBackend>,
    pending: Option<Pending>,
}

impl ClipboardGuard {
    /// Wraps a backend.
    pub fn new(backend: Box<dyn ClipboardBackend>) -> Self {
        Self {
            backend,
            pending: None,
        }
    }

    /// Copies `value`, to be cleared after `clear_after`.
    ///
    /// # Errors
    /// `clipboard` if the platform refuses.
    pub fn copy(&mut self, value: &str, now: Instant, clear_after: Duration) -> UiResult<()> {
        self.backend
            .set_secret(value)
            .map_err(|_| UiError::new("clipboard", "the clipboard is not available"))?;
        self.pending = Some(Pending {
            digest: digest(value),
            clear_at: now.checked_add(clear_after).unwrap_or(now),
        });
        Ok(())
    }

    /// Clears the clipboard if the delay is over and it still holds the
    /// copied value.
    pub fn tick(&mut self, now: Instant) {
        if self.pending.as_ref().is_some_and(|p| p.clear_at <= now) {
            self.clear_if_ours();
        }
    }

    /// Clears the clipboard now if it still holds the copied value (lock,
    /// exit).
    pub fn clear_if_ours(&mut self) {
        if let Some(pending) = self.pending.take() {
            let ours = self
                .backend
                .text()
                .is_some_and(|current| digest(&current) == pending.digest);
            if ours {
                let _ = self.backend.clear();
            }
        }
    }

    /// Whether a copied value is waiting to be cleared.
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }
}

/// In-memory clipboard for tests.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct MemoryClipboard(pub std::sync::Arc<std::sync::Mutex<Option<String>>>);

#[cfg(test)]
impl ClipboardBackend for MemoryClipboard {
    fn set_secret(&mut self, text: &str) -> Result<(), String> {
        *self.0.lock().map_err(|e| e.to_string())? = Some(text.to_owned());
        Ok(())
    }

    fn text(&mut self) -> Option<Zeroizing<String>> {
        self.0.lock().ok()?.clone().map(Zeroizing::new)
    }

    fn clear(&mut self) -> Result<(), String> {
        *self.0.lock().map_err(|e| e.to_string())? = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn clears_after_the_delay_only_if_still_ours() {
        let memory = MemoryClipboard::default();
        let mut guard = ClipboardGuard::new(Box::new(memory.clone()));
        let t0 = Instant::now();
        guard.copy("s3cret", t0, Duration::from_secs(30)).unwrap();
        assert_eq!(memory.0.lock().unwrap().as_deref(), Some("s3cret"));
        guard.tick(t0 + Duration::from_secs(29));
        assert_eq!(memory.0.lock().unwrap().as_deref(), Some("s3cret"));
        guard.tick(t0 + Duration::from_secs(30));
        assert_eq!(memory.0.lock().unwrap().as_deref(), None);
        assert!(!guard.is_pending());

        // The user copied something else meanwhile: it is left alone.
        guard.copy("s3cret", t0, Duration::from_secs(30)).unwrap();
        *memory.0.lock().unwrap() = Some("something else".to_owned());
        guard.tick(t0 + Duration::from_secs(31));
        assert_eq!(memory.0.lock().unwrap().as_deref(), Some("something else"));

        // Lock clears immediately.
        guard.copy("other", t0, Duration::from_secs(30)).unwrap();
        guard.clear_if_ours();
        assert_eq!(memory.0.lock().unwrap().as_deref(), None);
    }
}
