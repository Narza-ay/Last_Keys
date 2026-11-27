//! Paired extensions (stored in `bridge.json`) and the pending pairing
//! request shown to the user.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lk_bridge::{BrowserFamily, Caller, ClientId, PairingKey, pairing_code};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::error::{UiError, UiResult};

/// How long a pairing request waits for the user.
pub const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);
/// Most paired extensions kept at once.
pub const MAX_CLIENTS: usize = 32;
/// Longest client name kept (characters).
const MAX_NAME_CHARS: usize = 64;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredClient {
    client_id: String,
    name: String,
    browser: BrowserFamily,
    extension: String,
    key: String,
    created_at: u64,
    #[serde(default)]
    last_used_at: Option<u64>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFile {
    version: u32,
    clients: Vec<StoredClient>,
}

/// A paired extension as the settings page shows it (no key).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedClientView {
    /// Client ID (used to revoke it).
    pub client_id: String,
    /// Name the extension gave itself.
    pub name: String,
    /// Browser family.
    pub browser: BrowserFamily,
    /// Extension ID reported by the browser.
    pub extension: String,
    /// Pairing time (Unix seconds).
    pub created_at: u64,
    /// Last authenticated connection (Unix seconds).
    pub last_used_at: Option<u64>,
}

/// The paired extensions and their keys.
pub struct PairingStore {
    path: PathBuf,
    clients: Vec<StoredClient>,
}

impl PairingStore {
    /// Reads `path`; a missing or invalid file means no pairing (the
    /// extensions then ask to pair again).
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let clients = std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<StoredFile>(&bytes).ok())
            .filter(|f| f.version == 1)
            .map(|f| f.clients)
            .unwrap_or_default();
        Self {
            path: path.to_owned(),
            clients,
        }
    }

    fn save(&self) -> UiResult<()> {
        let io = |_| UiError::new("internal", "cannot save the paired browsers");
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let file = StoredFile {
            version: 1,
            clients: self.clients.clone(),
        };
        let bytes = lk_client::Zeroizing::new(
            serde_json::to_vec_pretty(&file).map_err(|_| UiError::internal())?,
        );
        let tmp = self.path.with_extension("json.tmp");
        write_private(&tmp, &bytes).map_err(io)?;
        std::fs::rename(&tmp, &self.path).map_err(io)?;
        Ok(())
    }

    /// Adds a pairing; returns its ID and key.
    ///
    /// # Errors
    /// `rate_limited` with [`MAX_CLIENTS`] pairings; `internal` on random
    /// generator or file errors.
    pub fn add(
        &mut self,
        name: &str,
        caller: &Caller,
        now: u64,
    ) -> UiResult<(ClientId, PairingKey)> {
        if self.clients.len() >= MAX_CLIENTS {
            return Err(UiError::new("rate_limited", "too many paired browsers"));
        }
        let id = ClientId::generate().map_err(|_| UiError::internal())?;
        let key = PairingKey::generate().map_err(|_| UiError::internal())?;
        self.clients.push(StoredClient {
            client_id: id.as_str().to_owned(),
            name: name.trim().chars().take(MAX_NAME_CHARS).collect(),
            browser: caller.family,
            extension: caller.extension.clone(),
            key: key.to_base64().as_str().to_owned(),
            created_at: now,
            last_used_at: None,
        });
        if let Err(e) = self.save() {
            self.clients.pop();
            return Err(e);
        }
        Ok((id, key))
    }

    /// The key of a paired client.
    #[must_use]
    pub fn key(&self, id: &ClientId) -> Option<PairingKey> {
        self.clients
            .iter()
            .find(|c| c.client_id == id.as_str())
            .and_then(|c| PairingKey::from_base64(&c.key).ok())
    }

    /// Records a successful connection (best effort).
    pub fn touch(&mut self, id: &ClientId, now: u64) {
        if let Some(c) = self.clients.iter_mut().find(|c| c.client_id == id.as_str()) {
            c.last_used_at = Some(now);
            let _ = self.save();
        }
    }

    /// Removes a pairing.
    ///
    /// # Errors
    /// `not_found`; `internal` if the file cannot be written.
    pub fn revoke(&mut self, id: &ClientId) -> UiResult<()> {
        let before = self.clients.len();
        self.clients.retain(|c| c.client_id != id.as_str());
        if self.clients.len() == before {
            return Err(UiError::new("not_found", "no such browser"));
        }
        self.save()
    }

    /// Paired extensions, most recently paired first.
    #[must_use]
    pub fn list(&self) -> Vec<PairedClientView> {
        let mut rows: Vec<_> = self
            .clients
            .iter()
            .map(|c| PairedClientView {
                client_id: c.client_id.clone(),
                name: c.name.clone(),
                browser: c.browser,
                extension: c.extension.clone(),
                created_at: c.created_at,
                last_used_at: c.last_used_at,
            })
            .collect();
        rows.sort_by_key(|c| core::cmp::Reverse(c.created_at));
        rows
    }
}

/// Writes a file readable by the user only (Unix); elsewhere the user
/// profile's permissions apply.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

/// A pairing request as the dialog shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRequestView {
    /// Request number (to answer it).
    pub id: u64,
    /// Code shown both here and in the extension's popup.
    pub code: String,
    /// Name the extension gave itself.
    pub client_name: String,
    /// Browser family reported by the relay.
    pub browser: BrowserFamily,
    /// Extension ID reported by the browser.
    pub extension: String,
}

struct Pending {
    view: PairingRequestView,
    answer: oneshot::Sender<bool>,
}

#[derive(Default)]
struct BrokerState {
    next_id: u64,
    pending: Option<Pending>,
    refusals: u32,
    blocked_until: Option<Instant>,
}

/// How a pairing request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Approved by the user.
    Approved,
    /// Refused by the user, or expired.
    Refused,
    /// The extension went away.
    Cancelled,
}

/// The single pending pairing request, and the delay imposed after
/// refusals (10 s, doubling, at most 5 minutes; reset by an approval).
#[derive(Default)]
pub struct Broker {
    state: Mutex<BrokerState>,
}

impl Broker {
    /// Opens a request; the receiver gets the user's answer.
    ///
    /// # Errors
    /// `pairing_busy` while another request waits; `rate_limited` during
    /// the delay that follows refusals.
    pub fn start(
        &self,
        client_name: &str,
        caller: &Caller,
        now: Instant,
    ) -> UiResult<(PairingRequestView, oneshot::Receiver<bool>)> {
        let mut state = self.state.lock().map_err(|_| UiError::internal())?;
        if state.pending.is_some() {
            return Err(UiError::new(
                "pairing_busy",
                "another pairing request is waiting",
            ));
        }
        if state.blocked_until.is_some_and(|until| now < until) {
            return Err(UiError::new("rate_limited", "wait before asking again"));
        }
        state.next_id = state.next_id.saturating_add(1);
        let view = PairingRequestView {
            id: state.next_id,
            code: pairing_code().map_err(|_| UiError::internal())?,
            client_name: client_name.trim().chars().take(MAX_NAME_CHARS).collect(),
            browser: caller.family,
            extension: caller.extension.clone(),
        };
        let (answer, receiver) = oneshot::channel();
        state.pending = Some(Pending {
            view: view.clone(),
            answer,
        });
        Ok((view, receiver))
    }

    /// The user's answer; `false` if no such request is waiting.
    pub fn decide(&self, id: u64, approve: bool) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.pending.as_ref().is_some_and(|p| p.view.id == id)
            && let Some(pending) = state.pending.take()
        {
            return pending.answer.send(approve).is_ok();
        }
        false
    }

    /// Closes a request and updates the delay.
    pub fn finish(&self, id: u64, outcome: Outcome, now: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.pending.as_ref().is_some_and(|p| p.view.id == id) {
            state.pending = None;
        }
        match outcome {
            Outcome::Approved => {
                state.refusals = 0;
                state.blocked_until = None;
            }
            Outcome::Refused => {
                state.refusals = state.refusals.saturating_add(1);
                let exponent = state.refusals.saturating_sub(1).min(5);
                let delay = Duration::from_secs(10)
                    .saturating_mul(1_u32 << exponent)
                    .min(Duration::from_secs(300));
                state.blocked_until = now.checked_add(delay);
            }
            Outcome::Cancelled => {}
        }
    }

    /// The waiting request, if any (for a window opened after it arrived).
    #[must_use]
    pub fn pending(&self) -> Option<PairingRequestView> {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.pending.as_ref().map(|p| p.view.clone()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn caller() -> Caller {
        Caller {
            family: BrowserFamily::Chromium,
            extension: "bblheiicocdmmkjnhdeehaedddgcfhok".to_owned(),
        }
    }

    #[test]
    fn store_round_trip_and_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge.json");
        let mut store = PairingStore::load(&path);
        assert!(store.list().is_empty());
        let (id, key) = store.add("  Chrome on Linux  ", &caller(), 100).unwrap();
        let (id2, _) = store.add(&"x".repeat(200), &caller(), 200).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let reloaded = PairingStore::load(&path);
        assert_eq!(reloaded.key(&id).unwrap().to_base64(), key.to_base64());
        let list = reloaded.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].name, "Chrome on Linux");
        assert_eq!(list[0].name.chars().count(), MAX_NAME_CHARS);
        assert_eq!(list[0].client_id, id2.as_str());
        // The list never contains keys.
        let text = serde_json::to_string(&list).unwrap();
        assert!(!text.contains(key.to_base64().as_str()));

        store.touch(&id, 300);
        assert_eq!(PairingStore::load(&path).list()[1].last_used_at, Some(300));
        store.revoke(&id).unwrap();
        assert!(store.key(&id).is_none());
        assert_eq!(store.revoke(&id).unwrap_err().kind, "not_found");
        assert!(PairingStore::load(&path).key(&id).is_none());

        std::fs::write(&path, b"{broken").unwrap();
        assert!(PairingStore::load(&path).list().is_empty());
    }

    #[test]
    fn store_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PairingStore::load(&dir.path().join("bridge.json"));
        for i in 0..MAX_CLIENTS {
            store.add("b", &caller(), i as u64).unwrap();
        }
        assert_eq!(
            store.add("b", &caller(), 0).unwrap_err().kind,
            "rate_limited"
        );
    }

    #[test]
    fn broker_one_request_and_refusal_delays() {
        let broker = Broker::default();
        let t0 = Instant::now();
        let (view, mut rx) = broker.start("Chrome", &caller(), t0).unwrap();
        assert_eq!(view.code.len(), 7);
        assert_eq!(broker.pending().unwrap(), view);
        assert_eq!(
            broker.start("Other", &caller(), t0).unwrap_err().kind,
            "pairing_busy"
        );
        assert!(!broker.decide(view.id + 1, true));
        assert!(broker.decide(view.id, true));
        assert!(rx.try_recv().unwrap());
        broker.finish(view.id, Outcome::Approved, t0);
        assert!(broker.pending().is_none());

        // Refusals impose a growing delay.
        let (v, _rx) = broker.start("Chrome", &caller(), t0).unwrap();
        broker.finish(v.id, Outcome::Refused, t0);
        assert_eq!(
            broker.start("Chrome", &caller(), t0).unwrap_err().kind,
            "rate_limited"
        );
        let t1 = t0 + Duration::from_secs(11);
        let (v, _rx) = broker.start("Chrome", &caller(), t1).unwrap();
        broker.finish(v.id, Outcome::Refused, t1);
        assert!(
            broker
                .start("Chrome", &caller(), t1 + Duration::from_secs(15))
                .is_err()
        );
        let t2 = t1 + Duration::from_secs(21);
        let (v, _rx) = broker.start("Chrome", &caller(), t2).unwrap();
        // A cancelled request does not count.
        broker.finish(v.id, Outcome::Cancelled, t2);
        assert!(broker.start("Chrome", &caller(), t2).is_ok());
    }
}
