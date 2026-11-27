// Messages between the popup, the background and the content scripts
// (ADR-0011). Secrets cross only these paths: credentials of one fill
// (background → content script of the checked frame), submitted credentials
// (content script → background) and a generated password (background →
// popup → content script).

/** Connection to the desktop application, as the popup shows it. */
export type ConnectionState =
  | { state: "unavailable" }
  | { state: "unpaired"; refused?: "refused" | "timeout" | "busy" | "rate_limited" }
  | { state: "pairing"; code: string }
  | { state: "ready"; locked: boolean };

export type MatchKind = "exact_host" | "same_site";

/** A login offered for the page (no secret). */
export interface Login {
  id: string;
  title: string;
  username: string | null;
  matched: MatchKind;
  hasPassword: boolean;
  hasTotp: boolean;
  favorite: boolean;
}

export type SaveProposal =
  | { action: "new"; title: string; url: string }
  | { action: "update_password"; id: string; title: string }
  | { action: "unchanged"; id: string };

/** Credentials submitted on a page, waiting for the user's decision. */
export interface PendingSave {
  host: string;
  username: string | null;
  proposal: SaveProposal | null;
}

/** What the popup shows for the active tab. */
export interface PageView {
  /** `http`/`https` page. */
  eligible: boolean;
  /** Host in ASCII (punycode) form. */
  host: string | null;
  /** The host has an internationalized (punycode) label. */
  internationalized: boolean;
  logins: Login[];
  pendingSave: PendingSave | null;
  /** A frame of the page reported a login form. */
  hasLoginForm: boolean;
  /** A frame reported a new-password field (registration, change). */
  hasNewPasswordField: boolean;
  /** Access to every site is granted: forms are detected and submitted
   * credentials captured on every page (AUDIT P-9). */
  detection: boolean;
}

export type CopyField = "username" | "password" | "totp";

/** Result of a fill request. */
export type FillResult =
  | { filled: number }
  | { confirm: { frameId: number; frameHost: string } };

/** Requests from the popup (an extension page) to the background. */
export type PopupRequest =
  | { kind: "state" }
  | { kind: "pair" }
  | { kind: "focus" }
  | { kind: "page"; tabId: number }
  | { kind: "fill"; tabId: number; itemId: string; confirmFrame?: number }
  | { kind: "copy"; tabId: number; itemId: string; field: CopyField }
  | { kind: "generate" }
  | { kind: "fillGenerated"; tabId: number; password: string }
  | { kind: "save"; tabId: number }
  | { kind: "dismissSave"; tabId: number };

export type Reply<T> = { ok: true; value: T } | { ok: false; code: string };

/** Messages from content scripts to the background. */
export type ContentMessage =
  | { kind: "forms"; login: boolean; newPassword: boolean; otp: boolean }
  | { kind: "submitted"; username: string | null; password: string };

/** Messages from the background to a content script. */
export type ToContent =
  | {
      kind: "fill";
      /** The frame's origin checked by the desktop; the content script refuses to fill elsewhere. */
      origin: string;
      username: string | null;
      password: string | null;
      totp: string | null;
    }
  | { kind: "fillNewPassword"; origin: string; password: string };

/** Notification from the background to an open popup. */
export interface StateChanged {
  kind: "stateChanged";
}
