// Requests from the popup and reports from content scripts. Every origin
// comes from the browser (tab URL, sender URL); the desktop re-checks each
// login against the page and the frame before answering (ADR-0011).

import type {
  ContentMessage,
  FillResult,
  Login,
  PageView,
  PopupRequest,
  Reply,
  SaveProposal,
  ToContent,
} from "../shared/messages";
import { BridgeError } from "./connection";
import type { Session } from "./session";
import type { FrameInfo, Frames, Saves } from "./state";

export interface TabsApi {
  /** URL of a tab as the browser reports it. */
  url(tabId: number): Promise<string | undefined>;
  /** Makes sure the content script runs in a tab the popup is opened on;
   * returns whether access to every site is granted. */
  prepare(tabId: number): Promise<boolean>;
  /** Sends a message to one frame (one document when its ID is known). */
  send(tabId: number, frame: FrameInfo, message: ToContent): Promise<unknown>;
  /** Marks the toolbar button of a tab (credentials to save). */
  badge(tabId: number, on: boolean): Promise<void>;
}

export interface RouterDeps {
  session: Session;
  frames: Frames;
  saves: Saves;
  tabs: TabsApi;
  now?: () => number;
}

const ok = <T>(value: T): Reply<T> => ({ ok: true, value });
const fail = (code: string): Reply<never> => ({ ok: false, code });

export function isEligible(url: string | undefined): url is string {
  return url !== undefined && /^https?:\/\//i.test(url);
}

function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

async function errorReply(e: unknown): Promise<Reply<never>> {
  return fail(e instanceof BridgeError ? e.code : "internal");
}

async function proposalFor(
  deps: RouterDeps,
  url: string,
  username: string | null,
  password: string,
): Promise<SaveProposal | null> {
  const state = deps.session.current();
  if (state.state !== "ready" || state.locked) return null;
  try {
    const answer = await deps.session.call("save_check", { pageUrl: url, username, password });
    return answer.proposal as SaveProposal;
  } catch {
    return null;
  }
}

async function page(deps: RouterDeps, tabId: number): Promise<PageView> {
  const url = await deps.tabs.url(tabId);
  const frames = await deps.frames.list(tabId);
  const empty: PageView = {
    eligible: false,
    host: null,
    internationalized: false,
    logins: [],
    pendingSave: null,
    hasLoginForm: false,
    hasNewPasswordField: false,
    detection: false,
  };
  if (!isEligible(url)) return empty;
  const detection = await deps.tabs.prepare(tabId);
  const host = hostOf(url);
  const state = await deps.session.ensure();
  let logins: Login[] = [];
  let pending = await deps.saves.get(tabId);
  if (state.state === "ready" && !state.locked) {
    const answer = await deps.session.call("list", { pageUrl: url });
    logins = (answer.logins as Login[] | undefined) ?? [];
    if (pending && !pending.proposal) {
      const proposal = await proposalFor(deps, pending.url, pending.username, pending.password);
      if (proposal?.action === "unchanged") {
        await deps.saves.clear(tabId);
        await deps.tabs.badge(tabId, false);
        pending = null;
      } else if (proposal) {
        pending = { ...pending, proposal };
        await deps.saves.put(tabId, pending);
      }
    }
  }
  return {
    ...empty,
    eligible: true,
    host,
    internationalized: (host ?? "").split(".").some((label) => label.startsWith("xn--")),
    logins,
    pendingSave: pending
      ? { host: hostOf(pending.url) ?? "", username: pending.username, proposal: pending.proposal }
      : null,
    hasLoginForm: frames.some((f) => f.login),
    hasNewPasswordField: frames.some((f) => f.newPassword),
    detection,
  };
}

/** Frames to try for a fill: the top-level frame, then frames with a login form. */
function fillCandidates(frames: FrameInfo[], pageUrl: string): FrameInfo[] {
  const withForms = frames.filter((f) => f.login || f.otp);
  const top = frames.find((f) => f.frameId === 0) ?? { frameId: 0, url: pageUrl, login: false, newPassword: false, otp: false };
  const rest = withForms.filter((f) => f.frameId !== 0);
  return top.login || top.otp || rest.length === 0 ? [top, ...rest] : rest;
}

async function fill(
  deps: RouterDeps,
  tabId: number,
  itemId: string,
  confirmFrame: number | undefined,
): Promise<Reply<FillResult>> {
  const url = await deps.tabs.url(tabId);
  if (!isEligible(url)) return fail("ineligible_page");
  const frames = await deps.frames.list(tabId);
  let lastError = "origin_mismatch";
  for (const frame of fillCandidates(frames, url)) {
    const origin = originOf(frame.url);
    if (!origin || !isEligible(frame.url)) continue;
    let credentials;
    try {
      credentials = await deps.session.call("fill", {
        itemId,
        pageUrl: url,
        frameUrl: frame.url,
        crossOriginConfirmed: confirmFrame === frame.frameId,
      });
    } catch (e) {
      const code = e instanceof BridgeError ? e.code : "internal";
      if (code === "confirmation_required") {
        return ok({ confirm: { frameId: frame.frameId, frameHost: hostOf(frame.url) ?? "" } });
      }
      if (code === "origin_mismatch" || code === "ineligible_page") {
        lastError = code;
        continue;
      }
      return fail(code);
    }
    const message: ToContent = {
      kind: "fill",
      origin,
      username: (credentials.username as string | null) ?? null,
      password: (credentials.password as string | null) ?? null,
      totp: (credentials.totp as string | null) ?? null,
    };
    const result = (await deps.tabs.send(tabId, frame, message).catch(() => null)) as { filled?: number } | null;
    return ok({ filled: result?.filled ?? 0 });
  }
  return fail(lastError);
}

async function fillGenerated(deps: RouterDeps, tabId: number, password: string): Promise<Reply<FillResult>> {
  const url = await deps.tabs.url(tabId);
  if (!isEligible(url)) return fail("ineligible_page");
  const pageOrigin = originOf(url);
  const frames = await deps.frames.list(tabId);
  // Only frames of the page's own origin receive a generated password.
  const targets = frames.filter((f) => f.newPassword && originOf(f.url) === pageOrigin);
  const list = targets.length > 0 ? targets : frames.filter((f) => f.frameId === 0);
  let filled = 0;
  for (const frame of list) {
    const origin = originOf(frame.url);
    if (!origin) continue;
    const result = (await deps.tabs
      .send(tabId, frame, { kind: "fillNewPassword", origin, password })
      .catch(() => null)) as { filled?: number } | null;
    filled += result?.filled ?? 0;
  }
  return ok({ filled });
}

export async function handlePopup(request: PopupRequest, deps: RouterDeps): Promise<Reply<unknown>> {
  try {
    switch (request.kind) {
      case "state":
        return ok(await deps.session.ensure());
      case "pair":
        return ok(await deps.session.pair());
      case "focus":
        await deps.session.call("focus");
        return ok(null);
      case "page":
        return ok(await page(deps, request.tabId));
      case "fill":
        return await fill(deps, request.tabId, request.itemId, request.confirmFrame);
      case "copy": {
        const url = await deps.tabs.url(request.tabId);
        if (!isEligible(url)) return fail("ineligible_page");
        const answer = await deps.session.call("copy", {
          itemId: request.itemId,
          pageUrl: url,
          field: request.field,
        });
        return ok({ clearsInSeconds: answer.clearsInSeconds });
      }
      case "generate": {
        const answer = await deps.session.call("generate");
        return ok({ password: answer.password });
      }
      case "fillGenerated":
        return await fillGenerated(deps, request.tabId, request.password);
      case "save": {
        const pending = await deps.saves.get(request.tabId);
        if (!pending) return fail("not_found");
        const updateId = pending.proposal?.action === "update_password" ? pending.proposal.id : undefined;
        await deps.session.call("save", {
          pageUrl: pending.url,
          username: pending.username,
          password: pending.password,
          ...(updateId ? { updateId } : {}),
        });
        await deps.saves.clear(request.tabId);
        await deps.tabs.badge(request.tabId, false);
        return ok(null);
      }
      case "dismissSave":
        await deps.saves.clear(request.tabId);
        await deps.tabs.badge(request.tabId, false);
        return ok(null);
    }
  } catch (e) {
    return errorReply(e);
  }
}

export interface ContentSender {
  tabId: number;
  frameId: number;
  url: string;
  documentId?: string;
}

export async function handleContent(message: ContentMessage, sender: ContentSender, deps: RouterDeps): Promise<void> {
  if (!isEligible(sender.url)) return;
  if (message.kind === "forms") {
    await deps.frames.update(sender.tabId, {
      frameId: sender.frameId,
      url: sender.url,
      ...(sender.documentId ? { documentId: sender.documentId } : {}),
      login: message.login,
      newPassword: message.newPassword,
      otp: message.otp,
    });
    return;
  }
  if (message.password.length === 0 || message.password.length > 4096) return;
  const username = message.username?.trim() ? message.username.trim().slice(0, 1024) : null;
  const now = deps.now ?? Date.now;
  await deps.saves.put(sender.tabId, {
    url: sender.url,
    username,
    password: message.password,
    proposal: null,
    at: now(),
  });
  const proposal = await proposalFor(deps, sender.url, username, message.password);
  if (proposal?.action === "unchanged") {
    await deps.saves.clear(sender.tabId);
    await deps.tabs.badge(sender.tabId, false);
    return;
  }
  const stored = await deps.saves.get(sender.tabId);
  if (stored) await deps.saves.put(sender.tabId, { ...stored, proposal });
  await deps.tabs.badge(sender.tabId, true);
}
