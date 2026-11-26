// The only way the UI talks to Rust (ADR-0010). In a release build this is
// always the Tauri back end; the scripted back end (mock.ts) is only bundled
// when VITE_LK_MOCK=1 (browser preview, UI tests, screenshots).

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  AppStatus,
  CopyResult,
  DeviceView,
  Field,
  GeneratedView,
  ItemDraft,
  ItemSummary,
  ItemView,
  PassphraseOptions,
  PasswordOptions,
  Settings,
  SyncSummary,
  TotpView,
  VaultInfo,
} from "./types";

export interface Backend {
  appStatus(): Promise<AppStatus>;
  getSettings(): Promise<Settings>;
  setSettings(settings: Settings): Promise<Settings>;
  touch(): Promise<void>;
  lock(): Promise<void>;
  createVault(password: string, confirmation: string, deviceName: string): Promise<string>;
  enrollDevice(server: string, email: string, password: string, deviceName: string): Promise<number>;
  unlock(password: string): Promise<void>;
  unlockWithRecoveryKey(key: string): Promise<void>;
  vaultInfo(): Promise<VaultInfo>;
  listItems(query: string): Promise<ItemSummary[]>;
  getItem(id: string): Promise<ItemView>;
  revealField(id: string, field: Field): Promise<string>;
  copyField(id: string, field: Field): Promise<CopyResult>;
  copyText(value: string): Promise<CopyResult>;
  totp(id: string): Promise<TotpView>;
  createItem(draft: ItemDraft): Promise<string>;
  updateItem(id: string, draft: ItemDraft): Promise<void>;
  deleteItem(id: string): Promise<void>;
  restorePassword(id: string, index: number): Promise<void>;
  deleteHistoryEntry(id: string, index: number): Promise<void>;
  generatePassword(options: PasswordOptions): Promise<GeneratedView>;
  generatePassphrase(options: PassphraseOptions): Promise<GeneratedView>;
  changeMasterPassword(current: string | null, password: string, confirmation: string): Promise<void>;
  rotateRecoveryKey(password: string): Promise<string>;
  register(server: string, email: string, recoveryKey: string): Promise<SyncSummary>;
  sync(reset: boolean): Promise<SyncSummary>;
  devices(): Promise<DeviceView[]>;
  revokeDevice(id: string): Promise<void>;
  /** Called when the vault locks by itself (inactivity). */
  onLocked(callback: () => void): Promise<() => void>;
}

export const tauriBackend: Backend = {
  appStatus: () => invoke("app_status"),
  getSettings: () => invoke("get_settings"),
  setSettings: (settings) => invoke("set_settings", { settings }),
  touch: () => invoke("touch"),
  lock: () => invoke("lock"),
  createVault: (password, confirmation, deviceName) =>
    invoke("create_vault", { password, confirmation, deviceName }),
  enrollDevice: (server, email, password, deviceName) =>
    invoke("enroll_device", { server, email, password, deviceName }),
  unlock: (password) => invoke("unlock", { password }),
  unlockWithRecoveryKey: (key) => invoke("unlock_with_recovery_key", { key }),
  vaultInfo: () => invoke("vault_info"),
  listItems: (query) => invoke("list_items", { query }),
  getItem: (id) => invoke("get_item", { id }),
  revealField: (id, field) => invoke("reveal_field", { id, field }),
  copyField: (id, field) => invoke("copy_field", { id, field }),
  copyText: (value) => invoke("copy_text", { value }),
  totp: (id) => invoke("totp", { id }),
  createItem: (draft) => invoke("create_item", { draft }),
  updateItem: (id, draft) => invoke("update_item", { id, draft }),
  deleteItem: (id) => invoke("delete_item", { id }),
  restorePassword: (id, index) => invoke("restore_password", { id, index }),
  deleteHistoryEntry: (id, index) => invoke("delete_history_entry", { id, index }),
  generatePassword: (options) => invoke("generate_password", { options }),
  generatePassphrase: (options) => invoke("generate_passphrase", { options }),
  changeMasterPassword: (current, password, confirmation) =>
    invoke("change_master_password", { current, password, confirmation }),
  rotateRecoveryKey: (password) => invoke("rotate_recovery_key", { password }),
  register: (server, email, recoveryKey) => invoke("register", { server, email, recoveryKey }),
  sync: (reset) => invoke("sync", { reset }),
  devices: () => invoke("devices"),
  revokeDevice: (id) => invoke("revoke_device", { id }),
  onLocked: (callback) => listen("vault-locked", () => callback()),
};

/** The back end of this build. */
export async function loadBackend(): Promise<Backend> {
  if (import.meta.env.VITE_LK_MOCK === "1") {
    const { createMockBackend } = await import("./mock");
    return createMockBackend();
  }
  return tauriBackend;
}
