//! Browser bridge (ADR-0011): the local endpoint that the browser
//! extension reaches through native messaging, the pairing of extensions,
//! the relay mode of the executable and the installation of native host
//! manifests. Every decision on secrets is taken by [`crate::core`] and
//! `lk-client`; this module only authenticates, routes and frames.

pub mod install;
pub mod io;
pub mod pairing;
pub mod relay;
pub mod server;
mod session;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use lk_bridge::{APP_IDENTIFIER, ClientId};
use tokio::sync::broadcast;

use crate::commands::Shared;
use crate::core::VaultEvent;
pub use pairing::{Broker, PairedClientView, PairingRequestView, PairingStore};

/// Application data directory, shared by the application and its relay:
/// `LK_DESKTOP_DATA_DIR` if set (tests, portable use), otherwise the
/// platform's data directory followed by the application identifier
/// (the directory Tauri uses).
#[must_use]
pub fn data_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("LK_DESKTOP_DATA_DIR") {
        return Some(PathBuf::from(dir));
    }
    dirs::data_dir().map(|d| d.join(APP_IDENTIFIER))
}

/// What connected extensions must learn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeEvent {
    /// The vault was locked or unlocked.
    Vault(VaultEvent),
    /// A pairing was revoked: its connections end.
    Revoked(ClientId),
    /// Browser integration was turned off: every connection ends.
    Disabled,
}

/// What the bridge asks of the user interface.
pub trait Notifier: Send + Sync {
    /// Show the pairing dialog (and bring the window to the front).
    fn pairing_requested(&self, request: &PairingRequestView);
    /// Close the dialog of this request (decided, expired or cancelled).
    fn pairing_closed(&self, id: u64);
    /// Bring the window to the front (so that the user can unlock).
    fn focus(&self);
}

/// Everything a connection needs.
pub struct BridgeContext {
    /// The application state (vault, settings, clipboard).
    pub core: Shared,
    /// Paired extensions.
    pub pairings: Mutex<PairingStore>,
    /// The pending pairing request, if any.
    pub broker: Broker,
    /// Events for connected extensions.
    pub events: broadcast::Sender<BridgeEvent>,
    /// The user interface.
    pub notifier: Arc<dyn Notifier>,
}

impl BridgeContext {
    /// A context whose pairings are stored in `pairings`.
    #[must_use]
    pub fn new(core: Shared, pairings: PairingStore, notifier: Arc<dyn Notifier>) -> Self {
        let (events, _) = broadcast::channel(32);
        Self {
            core,
            pairings: Mutex::new(pairings),
            broker: Broker::default(),
            events,
            notifier,
        }
    }

    /// Forwards a vault event to connected extensions.
    pub fn vault_event(&self, event: VaultEvent) {
        if matches!(event, VaultEvent::Locked | VaultEvent::Unlocked) {
            // No receiver simply means no extension is connected.
            let _ = self.events.send(BridgeEvent::Vault(event));
        }
    }

    /// Paired extensions, for the settings page.
    #[must_use]
    pub fn clients(&self) -> Vec<PairedClientView> {
        self.pairings.lock().map(|p| p.list()).unwrap_or_default()
    }

    /// Revokes a pairing and ends its connections.
    ///
    /// # Errors
    /// `not_found` for an unknown client; `internal` if the file cannot be
    /// written.
    pub fn revoke(&self, client_id: &str) -> crate::error::UiResult<()> {
        let id = ClientId::parse(client_id)
            .map_err(|_| crate::error::UiError::new("not_found", "no such browser"))?;
        self.pairings
            .lock()
            .map_err(|_| crate::error::UiError::internal())?
            .revoke(&id)?;
        let _ = self.events.send(BridgeEvent::Revoked(id));
        Ok(())
    }
}

/// What the settings page shows about browser integration.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeStatus {
    /// Integration is turned on.
    pub enabled: bool,
    /// The endpoint is served.
    pub running: bool,
    /// Why it could not be started (`in_use` when another instance serves
    /// it, `unavailable` otherwise).
    pub error: Option<String>,
    /// Registration of the host with each browser.
    pub browsers: Vec<install::BrowserStatus>,
    /// Paired extensions.
    pub clients: Vec<PairedClientView>,
    /// The waiting pairing request, if any.
    pub pending: Option<PairingRequestView>,
}

/// Turns the endpoint and the browser registrations on and off.
pub struct BridgeService {
    ctx: Arc<BridgeContext>,
    data_dir: PathBuf,
    enabled: std::sync::atomic::AtomicBool,
    server: tokio::sync::Mutex<Option<server::ServerHandle>>,
    error: Mutex<Option<String>>,
}

impl BridgeService {
    /// A stopped service for the application data directory `data_dir`.
    #[must_use]
    pub fn new(ctx: Arc<BridgeContext>, data_dir: PathBuf) -> Self {
        Self {
            ctx,
            data_dir,
            enabled: std::sync::atomic::AtomicBool::new(false),
            server: tokio::sync::Mutex::new(None),
            error: Mutex::new(None),
        }
    }

    /// The shared context.
    #[must_use]
    pub const fn context(&self) -> &Arc<BridgeContext> {
        &self.ctx
    }

    fn set_error(&self, error: Option<&str>) {
        if let Ok(mut e) = self.error.lock() {
            *e = error.map(str::to_owned);
        }
    }

    /// Registers the host with the browsers (refreshing the path of the
    /// executable) and serves the endpoint.
    pub async fn enable(&self) {
        self.enabled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let (Some(dirs), Ok(host)) = (install::user_dirs(&self.data_dir), install::host_path()) {
            let _ = install::install(lk_bridge::native::Os::current(), &dirs, &host);
        }
        let mut server = self.server.lock().await;
        if server.is_some() {
            return;
        }
        match server::start(Arc::clone(&self.ctx), lk_bridge::endpoint(&self.data_dir)).await {
            Ok(handle) => {
                *server = Some(handle);
                self.set_error(None);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => self.set_error(Some("in_use")),
            Err(_) => self.set_error(Some("unavailable")),
        }
    }

    /// Stops serving (open connections end).
    pub async fn shutdown(&self) {
        if let Some(handle) = self.server.lock().await.take() {
            handle.stop(&self.ctx);
        }
    }

    /// Stops serving and removes the browser registrations.
    pub async fn disable(&self) {
        self.enabled
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.shutdown().await;
        self.set_error(None);
        if let Some(dirs) = install::user_dirs(&self.data_dir) {
            install::uninstall(lk_bridge::native::Os::current(), &dirs);
        }
    }

    /// Current state.
    pub async fn status(&self) -> BridgeStatus {
        let enabled = self.enabled.load(std::sync::atomic::Ordering::SeqCst);
        let browsers = match (install::user_dirs(&self.data_dir), install::host_path()) {
            (Some(dirs), Ok(host)) => {
                install::status(lk_bridge::native::Os::current(), &dirs, &host)
            }
            _ => Vec::new(),
        };
        BridgeStatus {
            enabled,
            running: self.server.lock().await.is_some(),
            error: self.error.lock().ok().and_then(|e| e.clone()),
            browsers,
            clients: self.ctx.clients(),
            pending: self.ctx.broker.pending(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    #[test]
    fn identifier_matches_the_tauri_configuration() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../../tauri.conf.json")).unwrap();
        assert_eq!(conf["identifier"], lk_bridge::APP_IDENTIFIER);
    }
}
