//! Last Keys desktop application: the Rust back end of the Tauri window
//! (ADR-0010). All secrets and cryptography stay here; the web view only
//! calls [`commands`].

#![forbid(unsafe_code)]

pub mod bridge;
pub mod clipboard;
pub mod commands;
pub mod core;
pub mod error;
pub mod settings;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri::{Emitter, Manager, RunEvent};

use crate::bridge::{BridgeContext, BridgeService, Notifier, PairingRequestView, PairingStore};
use crate::clipboard::SystemClipboard;
use crate::commands::Shared;
use crate::core::{DesktopCore, Paths, VaultEvent, current_platform};

/// Event sent to the web view when the vault locks by itself.
pub const LOCKED_EVENT: &str = "vault-locked";
/// Event sent to the web view when items changed outside it (a login saved
/// from the browser).
pub const CHANGED_EVENT: &str = "vault-changed";
/// Event sent to the web view when an extension asks to pair.
pub const PAIRING_EVENT: &str = "bridge-pairing";
/// Event sent to the web view when a pairing request ends.
pub const PAIRING_CLOSED_EVENT: &str = "bridge-pairing-closed";

/// Interval of the background tick (auto-lock, clipboard clearing).
const TICK: Duration = Duration::from_millis(500);

/// Data directory: `LK_DESKTOP_DATA_DIR` if set (tests, portable use),
/// otherwise the platform's application data directory.
fn data_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    bridge::data_dir().ok_or_else(|| "no application data directory".into())
}

/// The bridge's requests to the window.
struct TauriNotifier(tauri::AppHandle);

impl Notifier for TauriNotifier {
    fn pairing_requested(&self, request: &PairingRequestView) {
        let _ = self.0.emit(PAIRING_EVENT, request);
        self.focus();
    }

    fn pairing_closed(&self, id: u64) {
        let _ = self.0.emit(PAIRING_CLOSED_EVENT, id);
    }

    fn focus(&self) {
        if let Some(window) = self.0.get_webview_window("main") {
            let _ = window.unminimize();
            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

fn lock(state: &Shared) {
    if let Ok(mut core) = state.lock() {
        core.lock();
    }
}

/// Runs the application.
///
/// # Errors
/// Fails if the window cannot be created.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let app = tauri::Builder::default()
        .setup(|app| {
            let dir = data_dir()?;
            let core = DesktopCore::new(
                Paths::in_dir(&dir),
                current_platform(),
                Box::new(SystemClipboard::default()),
                Instant::now(),
            );
            let integration = core.settings().browser_integration;
            let shared: Shared = Arc::new(Mutex::new(core));
            app.manage(Arc::clone(&shared));

            // Browser bridge (ADR-0011).
            let ctx = Arc::new(BridgeContext::new(
                Arc::clone(&shared),
                PairingStore::load(&dir.join("bridge.json")),
                Arc::new(TauriNotifier(app.handle().clone())),
            ));
            let weak = Arc::downgrade(&ctx);
            let events = app.handle().clone();
            if let Ok(mut core) = shared.lock() {
                core.set_observer(Box::new(move |event| {
                    if let Some(ctx) = weak.upgrade() {
                        ctx.vault_event(event);
                    }
                    if event == VaultEvent::Changed {
                        let _ = events.emit(CHANGED_EVENT, ());
                    }
                }));
            }
            let service = Arc::new(BridgeService::new(ctx, dir));
            app.manage(Arc::clone(&service));
            if integration {
                tauri::async_runtime::spawn(async move { service.enable().await });
            }

            let handle = app.handle().clone();
            std::thread::Builder::new()
                .name("lk-ticker".to_owned())
                .spawn(move || {
                    loop {
                        std::thread::sleep(TICK);
                        let locked = shared
                            .lock()
                            .map(|mut core| core.tick(Instant::now()))
                            .unwrap_or(false);
                        if locked {
                            let _ = handle.emit(LOCKED_EVENT, ());
                        }
                    }
                })?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_status,
            commands::get_settings,
            commands::set_settings,
            commands::touch,
            commands::lock,
            commands::create_vault,
            commands::enroll_device,
            commands::unlock,
            commands::unlock_with_recovery_key,
            commands::vault_info,
            commands::list_items,
            commands::get_item,
            commands::reveal_field,
            commands::copy_field,
            commands::copy_text,
            commands::totp,
            commands::create_item,
            commands::update_item,
            commands::delete_item,
            commands::restore_password,
            commands::delete_history_entry,
            commands::generate_password,
            commands::generate_passphrase,
            commands::change_master_password,
            commands::rotate_recovery_key,
            commands::register,
            commands::sync,
            commands::devices,
            commands::revoke_device,
            commands::bridge_status,
            commands::set_browser_integration,
            commands::bridge_pairing_decision,
            commands::revoke_browser,
        ])
        .build(tauri::generate_context!())?;
    app.run(|handle, event| {
        // Lock (and clear a copied secret) when the application ends.
        if let RunEvent::ExitRequested { .. } | RunEvent::Exit = event {
            if let Some(state) = handle.try_state::<Shared>() {
                lock(&state);
            }
            if let RunEvent::Exit = event
                && let Some(service) = handle.try_state::<Arc<BridgeService>>()
            {
                tauri::async_runtime::block_on(service.shutdown());
            }
        }
    });
    Ok(())
}
