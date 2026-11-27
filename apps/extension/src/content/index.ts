// Content script (every http/https frame): reports which forms the frame
// has, fills when the background asks (after the desktop checked the
// origin), and reports submitted credentials. It adds nothing to the page.

import type { ContentMessage, ToContent } from "../shared/messages";
import { ext } from "../shared/ext";
import { watchSubmissions } from "./capture";
import { detect, summarize } from "./detect";
import { fillLogin, fillNewPassword } from "./fill";

// Injected by registration and possibly again by the popup: run once.
const marker = globalThis as { __lastKeysContent?: boolean };
const alreadyRunning = marker.__lastKeysContent === true;
marker.__lastKeysContent = true;

function send(message: ContentMessage): void {
  ext.runtime.sendMessage(message).catch(() => undefined);
}

let lastReport = "";
function report(): void {
  const summary = summarize(detect(document));
  // The URL is part of the key: single-page applications navigate without
  // reloading, and the background forgets a tab's frames on navigation.
  const key = `${location.href}|${summary.login}|${summary.newPassword}|${summary.otp}`;
  if (key === lastReport) return;
  lastReport = key;
  send({ kind: "forms", ...summary });
}

let timer: ReturnType<typeof setTimeout> | undefined;
function scheduleReport(): void {
  clearTimeout(timer);
  timer = setTimeout(report, 400);
}

function isToContent(m: unknown): m is ToContent {
  if (typeof m !== "object" || m === null) return false;
  const v = m as Record<string, unknown>;
  return (v.kind === "fill" || v.kind === "fillNewPassword") && typeof v.origin === "string";
}

function onMessage(message: unknown, sender: chrome.runtime.MessageSender, sendResponse: (r: unknown) => void): boolean {
  // Only the extension itself (its background) may ask for a fill.
  if (sender.id !== ext.runtime.id || sender.tab || !isToContent(message)) return false;
  // The frame may have navigated since the desktop checked its origin.
  if (message.origin !== location.origin) {
    sendResponse({ filled: 0 });
    return false;
  }
  const fields = detect(document);
  const filled =
    message.kind === "fill"
      ? fillLogin(fields, { username: message.username, password: message.password, totp: message.totp })
      : fillNewPassword(fields, message.password);
  sendResponse({ filled });
  return false;
}

if (!alreadyRunning) {
  ext.runtime.onMessage.addListener(onMessage);
  report();
  new MutationObserver(scheduleReport).observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["type", "style", "class", "hidden", "disabled"],
  });
  window.addEventListener("popstate", scheduleReport);
  watchSubmissions(document, (submission) => send({ kind: "submitted", ...submission }));
}
