// Types mirroring the Rust view models (crates/lk-client/src/view.rs,
// draft.rs) and the desktop back end (apps/desktop/src-tauri/src/core.rs).
// No secret value appears in a view: secrets are fetched one at a time.

export type ItemKind = "login" | "secure_note" | "payment_card" | "identity";

export type Platform =
  | "windows"
  | "mac_os"
  | "linux"
  | "android"
  | "ios"
  | "web"
  | "browser_extension"
  | "cli";

export interface ItemSummary {
  id: string;
  kind: ItemKind;
  title: string;
  subtitle: string | null;
  favorite: boolean;
  folder: string | null;
  tags: string[];
  host: string | null;
  hasTotp: boolean;
  updatedAt: number;
}

export interface AddressView {
  line1: string | null;
  line2: string | null;
  city: string | null;
  postalCode: string | null;
  region: string | null;
  country: string | null;
}

export type FieldKind = "text" | "hidden" | "url" | "email";

export interface CustomFieldView {
  name: string;
  kind: FieldKind;
  value: string | null;
  hasValue: boolean;
}

export type DocumentKind =
  | "passport"
  | "national_id"
  | "driver_license"
  | "social_security"
  | "other";

export interface DocumentView {
  kind: DocumentKind;
  issuingCountry: string | null;
  expiryDate: string | null;
  hasNumber: boolean;
}

export type ContentView =
  | {
      type: "login";
      username: string | null;
      hasPassword: boolean;
      urls: string[];
      hasTotp: boolean;
      backupCodes: number;
    }
  | { type: "secure_note" }
  | {
      type: "payment_card";
      cardholderName: string | null;
      hasNumber: boolean;
      numberLast4: string | null;
      expiryMonth: number | null;
      expiryYear: number | null;
      hasSecurityCode: boolean;
      hasPin: boolean;
      billingAddress: AddressView | null;
    }
  | {
      type: "identity";
      honorific: string | null;
      firstName: string | null;
      middleName: string | null;
      lastName: string | null;
      birthDate: string | null;
      email: string | null;
      phone: string | null;
      company: string | null;
      address: AddressView | null;
      documents: DocumentView[];
    };

export interface ItemView {
  id: string;
  kind: ItemKind;
  title: string;
  favorite: boolean;
  folder: string | null;
  tags: string[];
  hasNotes: boolean;
  customFields: CustomFieldView[];
  history: { replacedAt: number }[];
  createdAt: number;
  updatedAt: number;
  content: ContentView;
}

/** A field whose value can be revealed or copied. */
export type Field =
  | { field: "username" }
  | { field: "password" }
  | { field: "url"; index: number }
  | { field: "totpCode" }
  | { field: "totpSecret" }
  | { field: "backupCode"; index: number }
  | { field: "notes" }
  | { field: "cardNumber" }
  | { field: "securityCode" }
  | { field: "pin" }
  | { field: "customField"; index: number }
  | { field: "historyPassword"; index: number }
  | { field: "documentNumber"; index: number };

export type SecretChange =
  | { op: "keep" }
  | { op: "set"; value: string }
  | { op: "clear" };

export type ListChange =
  | { op: "keep" }
  | { op: "set"; values: string[] }
  | { op: "clear" };

export interface CustomFieldDraft {
  name: string;
  kind: FieldKind;
  value: SecretChange;
  source: number | null;
}

export interface DocumentDraft {
  kind: DocumentKind;
  number: SecretChange;
  source: number | null;
  issuingCountry: string | null;
  expiryDate: string | null;
}

export type ContentDraft =
  | {
      type: "login";
      username: string | null;
      password: SecretChange;
      urls: string[];
      totp: SecretChange;
      backupCodes: ListChange;
    }
  | { type: "secure_note" }
  | {
      type: "payment_card";
      cardholderName: string | null;
      number: SecretChange;
      expiryMonth: number | null;
      expiryYear: number | null;
      securityCode: SecretChange;
      pin: SecretChange;
      billingAddress: AddressView | null;
    }
  | {
      type: "identity";
      honorific: string | null;
      firstName: string | null;
      middleName: string | null;
      lastName: string | null;
      birthDate: string | null;
      email: string | null;
      phone: string | null;
      company: string | null;
      address: AddressView | null;
      documents: DocumentDraft[];
    };

export interface ItemDraft {
  title: string;
  favorite: boolean;
  folder: string | null;
  tags: string[];
  notes: SecretChange;
  customFields: CustomFieldDraft[];
  content: ContentDraft;
}

export interface TotpView {
  code: string;
  period: number;
  remaining: number;
}

export type DeviceStatus = "this_device" | "active" | "revoked";

export interface DeviceView {
  id: string;
  name: string;
  platform: Platform;
  status: DeviceStatus;
  enrolledAt: number;
  lastSeen: number | null;
}

export interface VaultInfo {
  accountId: string;
  deviceId: string;
  deviceName: string;
  platform: Platform;
  enrolledAt: number;
  kdf: { memoryKib: number; iterations: number; parallelism: number };
  recoveryKeyConfigured: boolean;
  items: number;
  pendingChanges: number;
  remote: { server: string; email: string } | null;
  unlockedWith: "master_password" | "recovery_key";
}

export interface SyncSummary {
  received: number;
  sent: number;
  conflicts: number;
  conflictCopies: number;
}

export interface AppStatus {
  vaultExists: boolean;
  unlocked: boolean;
  platform: Platform;
  version: string;
  defaultDeviceName: string;
}

export type Language = "system" | "fr" | "en";
export type Theme = "system" | "light" | "dark";

export interface Settings {
  language: Language;
  theme: Theme;
  autoLockMinutes: number;
  clipboardClearSeconds: number;
  /** Changed only through `setBrowserIntegration` (it registers browsers). */
  browserIntegration: boolean;
}

// Browser integration (apps/desktop/src-tauri/src/bridge, ADR-0011).
export type BrowserName = "chrome" | "chromium" | "brave" | "firefox";
export type BrowserFamily = "chromium" | "firefox";
export type InstallState = "installed" | "not_detected" | "not_installed" | "failed";

export interface BrowserStatus {
  browser: BrowserName;
  state: InstallState;
}

export interface PairedClientView {
  clientId: string;
  name: string;
  browser: BrowserFamily;
  extension: string;
  createdAt: number;
  lastUsedAt: number | null;
}

export interface PairingRequestView {
  id: number;
  code: string;
  clientName: string;
  browser: BrowserFamily;
  extension: string;
}

export interface BridgeStatus {
  enabled: boolean;
  running: boolean;
  /** `in_use` (another instance serves it) or `unavailable`. */
  error: string | null;
  browsers: BrowserStatus[];
  clients: PairedClientView[];
  pending: PairingRequestView | null;
}

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export type StrengthLevel = "very_weak" | "weak" | "fair" | "strong" | "very_strong";

export interface GeneratedView {
  value: string;
  entropyBits: number;
  level: StrengthLevel;
}

export interface CopyResult {
  clearsInSeconds: number;
}

/** Error returned by the back end: a stable code and an English message. */
export interface UiError {
  kind: string;
  message: string;
}

export function isUiError(value: unknown): value is UiError {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as UiError).kind === "string" &&
    typeof (value as UiError).message === "string"
  );
}
