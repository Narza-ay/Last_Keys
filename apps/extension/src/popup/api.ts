// The popup's access to the background and to the active tab.

import type { PopupRequest, Reply } from "../shared/messages";
import { ext } from "../shared/ext";

const HOSTS = ["http://*/*", "https://*/*"];

export interface PopupApi {
  request<T>(request: PopupRequest): Promise<Reply<T>>;
  activeTabId(): Promise<number | undefined>;
  onStateChanged(callback: () => void): () => void;
  close(): void;
  language(): string;
  /** Asks the browser for access to every site (AUDIT P-9); must run in a
   * click handler. */
  requestHostAccess(): Promise<boolean>;
}

export const browserApi: PopupApi = {
  async request<T>(request: PopupRequest) {
    try {
      const reply = (await ext.runtime.sendMessage(request)) as Reply<T> | undefined;
      return reply ?? { ok: false, code: "internal" };
    } catch {
      return { ok: false, code: "internal" };
    }
  },
  async activeTabId() {
    // `?tab=<id>` when the popup page is opened in a tab (end-to-end tests):
    // only the extension can open its own pages, none is web-accessible.
    const forced = Number(new URLSearchParams(window.location.search).get("tab"));
    if (Number.isInteger(forced) && forced > 0) return forced;
    const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
    return tab?.id;
  },
  onStateChanged(callback) {
    const listener = (message: unknown, sender: chrome.runtime.MessageSender) => {
      if (sender.id === ext.runtime.id && (message as { kind?: unknown } | null)?.kind === "stateChanged") callback();
      return false;
    };
    ext.runtime.onMessage.addListener(listener);
    return () => ext.runtime.onMessage.removeListener(listener);
  },
  close() {
    window.close();
  },
  language() {
    return ext.i18n.getUILanguage();
  },
  async requestHostAccess() {
    try {
      return await ext.permissions.request({ origins: HOSTS });
    } catch {
      return false;
    }
  },
};
