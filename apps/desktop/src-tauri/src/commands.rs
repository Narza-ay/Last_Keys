//! Tauri commands: the only interface between the web view and Rust. Each
//! one runs the corresponding [`DesktopCore`] method on a blocking thread
//! (key derivation and network calls must never freeze the window).

use std::sync::{Arc, Mutex};
use std::time::Instant;

use lk_client::{
    DeviceId, DeviceView, Field, ItemDraft, ItemId, ItemSummary, ItemView, SyncSummary, TotpView,
    VaultInfo,
};
use tauri::State;

use crate::bridge::{BridgeService, BridgeStatus};
use crate::core::{
    AppStatus, CopyResult, DesktopCore, GeneratedView, PassphraseOptions, PasswordOptions,
};
use crate::error::{UiError, UiResult};
use crate::settings::Settings;

/// Shared back-end state.
pub type Shared = Arc<Mutex<DesktopCore>>;

async fn run<T, F>(state: State<'_, Shared>, work: F) -> UiResult<T>
where
    T: Send + 'static,
    F: FnOnce(&mut DesktopCore) -> UiResult<T> + Send + 'static,
{
    let core = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let mut core = core.lock().map_err(|_| UiError::internal())?;
        work(&mut core)
    })
    .await
    .map_err(|_| UiError::internal())?
}

/// Start-up information.
#[tauri::command]
pub async fn app_status(state: State<'_, Shared>) -> UiResult<AppStatus> {
    run(state, |c| Ok(c.status())).await
}

/// Current preferences.
#[tauri::command]
pub async fn get_settings(state: State<'_, Shared>) -> UiResult<Settings> {
    run(state, |c| Ok(c.settings())).await
}

/// Replaces the preferences (browser integration excepted: it has its own
/// command, which also registers the browsers).
#[tauri::command]
pub async fn set_settings(state: State<'_, Shared>, mut settings: Settings) -> UiResult<Settings> {
    run(state, move |c| {
        settings.browser_integration = c.settings().browser_integration;
        c.set_settings(settings)
    })
    .await
}

/// User activity (postpones auto-lock).
#[tauri::command]
pub async fn touch(state: State<'_, Shared>) -> UiResult<()> {
    run(state, |c| {
        c.touch(Instant::now());
        Ok(())
    })
    .await
}

/// Locks now.
#[tauri::command]
pub async fn lock(state: State<'_, Shared>) -> UiResult<()> {
    run(state, |c| {
        c.lock();
        Ok(())
    })
    .await
}

/// Creates the account and vault; returns the recovery key (shown once).
#[tauri::command]
pub async fn create_vault(
    state: State<'_, Shared>,
    password: String,
    confirmation: String,
    device_name: String,
) -> UiResult<String> {
    let password = lk_client::Zeroizing::new(password);
    let confirmation = lk_client::Zeroizing::new(confirmation);
    run(state, move |c| {
        c.create_vault(&password, &confirmation, &device_name, Instant::now())
    })
    .await
}

/// Enrolls this device in an existing account.
#[tauri::command]
pub async fn enroll_device(
    state: State<'_, Shared>,
    server: String,
    email: String,
    password: String,
    device_name: String,
) -> UiResult<usize> {
    let password = lk_client::Zeroizing::new(password);
    run(state, move |c| {
        c.enroll(&server, &email, &password, &device_name, Instant::now())
    })
    .await
}

/// Unlocks with the master password.
#[tauri::command]
pub async fn unlock(state: State<'_, Shared>, password: String) -> UiResult<()> {
    let password = lk_client::Zeroizing::new(password);
    run(state, move |c| c.unlock(&password, Instant::now())).await
}

/// Unlocks with the recovery key.
#[tauri::command]
pub async fn unlock_with_recovery_key(state: State<'_, Shared>, key: String) -> UiResult<()> {
    let key = lk_client::Zeroizing::new(key);
    run(state, move |c| {
        c.unlock_with_recovery_key(&key, Instant::now())
    })
    .await
}

/// Vault information.
#[tauri::command]
pub async fn vault_info(state: State<'_, Shared>) -> UiResult<VaultInfo> {
    run(state, |c| c.info()).await
}

/// Item list.
#[tauri::command]
pub async fn list_items(state: State<'_, Shared>, query: String) -> UiResult<Vec<ItemSummary>> {
    run(state, move |c| c.list_items(&query)).await
}

/// Item view (no secret values).
#[tauri::command]
pub async fn get_item(state: State<'_, Shared>, id: ItemId) -> UiResult<ItemView> {
    run(state, move |c| c.get_item(&id)).await
}

/// Value of one field (explicit reveal).
#[tauri::command]
pub async fn reveal_field(state: State<'_, Shared>, id: ItemId, field: Field) -> UiResult<String> {
    run(state, move |c| c.reveal_field(&id, field)).await
}

/// Copies one field to the clipboard (the value never reaches the UI).
#[tauri::command]
pub async fn copy_field(
    state: State<'_, Shared>,
    id: ItemId,
    field: Field,
) -> UiResult<CopyResult> {
    run(state, move |c| c.copy_field(&id, field, Instant::now())).await
}

/// Copies a text shown in the UI (generated password).
#[tauri::command]
pub async fn copy_text(state: State<'_, Shared>, value: String) -> UiResult<CopyResult> {
    let value = lk_client::Zeroizing::new(value);
    run(state, move |c| c.copy_text(&value, Instant::now())).await
}

/// Current TOTP code.
#[tauri::command]
pub async fn totp(state: State<'_, Shared>, id: ItemId) -> UiResult<TotpView> {
    run(state, move |c| c.totp(&id)).await
}

/// Adds an item.
#[tauri::command]
pub async fn create_item(state: State<'_, Shared>, draft: ItemDraft) -> UiResult<ItemId> {
    run(state, move |c| c.create_item(draft)).await
}

/// Modifies an item.
#[tauri::command]
pub async fn update_item(state: State<'_, Shared>, id: ItemId, draft: ItemDraft) -> UiResult<()> {
    run(state, move |c| c.update_item(&id, draft)).await
}

/// Deletes an item.
#[tauri::command]
pub async fn delete_item(state: State<'_, Shared>, id: ItemId) -> UiResult<()> {
    run(state, move |c| c.delete_item(&id)).await
}

/// Restores a previous password.
#[tauri::command]
pub async fn restore_password(state: State<'_, Shared>, id: ItemId, index: usize) -> UiResult<()> {
    run(state, move |c| c.restore_password(&id, index)).await
}

/// Deletes a previous password.
#[tauri::command]
pub async fn delete_history_entry(
    state: State<'_, Shared>,
    id: ItemId,
    index: usize,
) -> UiResult<()> {
    run(state, move |c| c.delete_history_entry(&id, index)).await
}

/// Generates a password.
#[tauri::command]
pub async fn generate_password(
    state: State<'_, Shared>,
    options: PasswordOptions,
) -> UiResult<GeneratedView> {
    run(state, move |c| c.generate_password(&options)).await
}

/// Generates a passphrase.
#[tauri::command]
pub async fn generate_passphrase(
    state: State<'_, Shared>,
    options: PassphraseOptions,
) -> UiResult<GeneratedView> {
    run(state, move |c| c.generate_passphrase(&options)).await
}

/// Changes (or resets) the master password.
#[tauri::command]
pub async fn change_master_password(
    state: State<'_, Shared>,
    current: Option<String>,
    password: String,
    confirmation: String,
) -> UiResult<()> {
    let current = current.map(lk_client::Zeroizing::new);
    let password = lk_client::Zeroizing::new(password);
    let confirmation = lk_client::Zeroizing::new(confirmation);
    run(state, move |c| {
        c.change_master_password(
            current.as_deref().map(String::as_str),
            &password,
            &confirmation,
        )
    })
    .await
}

/// Replaces the recovery key; returns the new one (shown once).
#[tauri::command]
pub async fn rotate_recovery_key(state: State<'_, Shared>, password: String) -> UiResult<String> {
    let password = lk_client::Zeroizing::new(password);
    run(state, move |c| c.rotate_recovery_key(&password)).await
}

/// Registers the account on a server.
#[tauri::command]
pub async fn register(
    state: State<'_, Shared>,
    server: String,
    email: String,
    recovery_key: String,
) -> UiResult<SyncSummary> {
    let recovery_key = lk_client::Zeroizing::new(recovery_key);
    run(state, move |c| c.register(&server, &email, &recovery_key)).await
}

/// Synchronizes.
#[tauri::command]
pub async fn sync(state: State<'_, Shared>, reset: bool) -> UiResult<SyncSummary> {
    run(state, move |c| c.sync(reset)).await
}

/// The account's devices.
#[tauri::command]
pub async fn devices(state: State<'_, Shared>) -> UiResult<Vec<DeviceView>> {
    run(state, |c| c.devices()).await
}

/// Revokes another device.
#[tauri::command]
pub async fn revoke_device(state: State<'_, Shared>, id: DeviceId) -> UiResult<()> {
    run(state, move |c| c.revoke_device(id)).await
}

/// Browser integration: state, registered browsers, paired extensions.
#[tauri::command]
pub async fn bridge_status(bridge: State<'_, Arc<BridgeService>>) -> UiResult<BridgeStatus> {
    Ok(bridge.status().await)
}

/// Turns browser integration on or off.
#[tauri::command]
pub async fn set_browser_integration(
    state: State<'_, Shared>,
    bridge: State<'_, Arc<BridgeService>>,
    enabled: bool,
) -> UiResult<BridgeStatus> {
    run(state, move |c| {
        let mut settings = c.settings();
        settings.browser_integration = enabled;
        c.set_settings(settings).map(|_| ())
    })
    .await?;
    if enabled {
        bridge.enable().await;
    } else {
        bridge.disable().await;
    }
    Ok(bridge.status().await)
}

/// The user's answer to a pairing request.
#[tauri::command]
pub async fn bridge_pairing_decision(
    bridge: State<'_, Arc<BridgeService>>,
    id: u64,
    approve: bool,
) -> UiResult<bool> {
    Ok(bridge.context().broker.decide(id, approve))
}

/// Revokes a paired extension.
#[tauri::command]
pub async fn revoke_browser(
    bridge: State<'_, Arc<BridgeService>>,
    client_id: String,
) -> UiResult<BridgeStatus> {
    bridge.context().revoke(&client_id)?;
    Ok(bridge.status().await)
}
