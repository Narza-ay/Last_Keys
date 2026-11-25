//! Last Keys desktop application: the Rust back end of the Tauri window
//! (ADR-0010). All secrets and cryptography stay here; the web view only
//! calls [`commands`].

#![forbid(unsafe_code)]

pub mod clipboard;
pub mod commands;
pub mod core;
pub mod error;
pub mod settings;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri::{Emitter, Manager, RunEvent};

use crate::clipboard::SystemClipboard;
use crate::commands::Shared;
use crate::core::{DesktopCore, Paths, current_platform};

/// Event sent to the web view when the vault locks by itself.
pub const LOCKED_EVENT: &str = "vault-locked";

/// Interval of the background tick (auto-lock, clipboard clearing).
const TICK: Duration = Duration::from_millis(500);

/// Data directory: `LK_DESKTOP_DATA_DIR` if set (tests, portable use),
/// otherwise the platform's application data directory.
fn data_dir(app: &tauri::App) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(dir) = std::env::var_os("LK_DESKTOP_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    Ok(app.path().app_data_dir()?)
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
            let core = DesktopCore::new(
                Paths::in_dir(&data_dir(app)?),
                current_platform(),
                Box::new(SystemClipboard::default()),
                Instant::now(),
            );
            let shared: Shared = Arc::new(Mutex::new(core));
            app.manage(Arc::clone(&shared));
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
        ])
        .build(tauri::generate_context!())?;
    app.run(|handle, event| {
        // Lock (and clear a copied secret) when the application ends.
        if let RunEvent::ExitRequested { .. } | RunEvent::Exit = event
            && let Some(state) = handle.try_state::<Shared>()
        {
            lock(&state);
        }
    });
    Ok(())
}
