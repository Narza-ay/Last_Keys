// Background (service worker on Chromium, event page on Firefox): the only
// part of the extension that talks to the desktop application.

import type { ContentMessage, PopupRequest, StateChanged, ToContent } from "../shared/messages";
import { NATIVE_HOST, ext } from "../shared/ext";
import { hasHostAccess, injectInto, syncContentScripts } from "./access";
import { indexedDbKeyStore } from "./keystore";
import { handleContent, handlePopup, type TabsApi } from "./router";
import { Session } from "./session";
import { Frames, Saves, sessionStorageArea } from "./state";

const POPUP_KINDS = new Set([
  "state",
  "pair",
  "focus",
  "page",
  "fill",
  "copy",
  "generate",
  "fillGenerated",
  "save",
  "dismissSave",
]);

function isPopupRequest(m: unknown): m is PopupRequest {
  return typeof m === "object" && m !== null && POPUP_KINDS.has(String((m as { kind?: unknown }).kind));
}

function isContentMessage(m: unknown): m is ContentMessage {
  if (typeof m !== "object" || m === null) return false;
  const v = m as Record<string, unknown>;
  if (v.kind === "forms") {
    return typeof v.login === "boolean" && typeof v.newPassword === "boolean" && typeof v.otp === "boolean";
  }
  if (v.kind === "submitted") {
    return typeof v.password === "string" && (v.username === null || typeof v.username === "string");
  }
  return false;
}

function clientName(): string {
  const ua = navigator.userAgent;
  const nav = navigator as Navigator & { brave?: unknown };
  const browserName = /Firefox\//.test(ua)
    ? "Firefox"
    : nav.brave
      ? "Brave"
      : /Edg\//.test(ua)
        ? "Edge"
        : /Chrome\//.test(ua)
          ? "Chrome"
          : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS X|Macintosh/.test(ua) ? "macOS" : /Linux|X11/.test(ua) ? "Linux" : "";
  return os ? `${browserName} · ${os}` : browserName;
}

const session = new Session({
  connect: () => ext.runtime.connectNative(NATIVE_HOST),
  keys: indexedDbKeyStore,
  clientName: clientName(),
  notify: () => {
    const message: StateChanged = { kind: "stateChanged" };
    // No popup open: nobody receives it.
    ext.runtime.sendMessage(message).catch(() => undefined);
  },
});

const store = sessionStorageArea(ext.storage.session);
const frames = new Frames(store);
const saves = new Saves(store);

const tabs: TabsApi = {
  async url(tabId) {
    const tab = await ext.tabs.get(tabId);
    return tab.url;
  },
  async prepare(tabId) {
    // Also when access is granted: tabs opened before the content script
    // was registered do not run it yet (it runs only once per frame).
    await injectInto(tabId);
    return hasHostAccess();
  },
  send(tabId, frame, message: ToContent) {
    const options: chrome.tabs.MessageSendOptions = frame.documentId
      ? { documentId: frame.documentId }
      : { frameId: frame.frameId };
    return ext.tabs.sendMessage(tabId, message, options);
  },
  async badge(tabId, on) {
    await ext.action.setBadgeText({ tabId, text: on ? "1" : "" }).catch(() => undefined);
    if (on) await ext.action.setBadgeBackgroundColor({ tabId, color: "#4F46E5" }).catch(() => undefined);
  },
};

const deps = { session, frames, saves, tabs };

ext.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  if (sender.id !== ext.runtime.id) return false;
  // The extension's own pages (the popup, also when opened in a tab) are
  // recognised by the URL the browser reports; content scripts always
  // report the page's http/https URL.
  const fromExtensionPage = typeof sender.url === "string" && sender.url.startsWith(ext.runtime.getURL(""));
  if (fromExtensionPage) {
    if (!isPopupRequest(message)) return false;
    void handlePopup(message, deps).then(sendResponse);
    return true;
  }
  const tabId = sender.tab?.id;
  if (tabId !== undefined && sender.frameId !== undefined && typeof sender.url === "string" && isContentMessage(message)) {
    const documentId = (sender as chrome.runtime.MessageSender & { documentId?: string }).documentId;
    void handleContent(
      message,
      { tabId, frameId: sender.frameId, url: sender.url, ...(documentId ? { documentId } : {}) },
      deps,
    ).then(() => sendResponse(null));
    return true;
  }
  return false;
});

ext.tabs.onRemoved.addListener((tabId) => {
  void frames.clear(tabId);
  void saves.clear(tabId);
});

ext.tabs.onUpdated.addListener((tabId, change) => {
  // A new page: its frames will report again.
  if (change.url !== undefined) void frames.clear(tabId);
});

// Content script registration follows the optional host permission.
const sync = () => void syncContentScripts().catch(() => undefined);
sync();
ext.runtime.onStartup.addListener(sync);
ext.runtime.onInstalled.addListener(sync);
ext.permissions.onAdded.addListener(sync);
ext.permissions.onRemoved.addListener(sync);
