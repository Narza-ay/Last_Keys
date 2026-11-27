// Host access (AUDIT P-9): access to every site is an optional permission
// that the popup proposes. When granted, the content script is registered
// for every http/https page (form detection and saving everywhere). When
// not, the popup injects it into the page it is opened on, through the
// temporary access the browser gives when the user clicks the extension
// (`activeTab`): click-to-fill only. The popup also injects it when access
// is granted, for tabs opened before the registration.

import { ext } from "../shared/ext";

export const HOSTS = ["http://*/*", "https://*/*"];
const SCRIPT_ID = "lk-content";

export async function hasHostAccess(): Promise<boolean> {
  return ext.permissions.contains({ origins: HOSTS });
}

/** Registers or unregisters the content script to match the permission. */
export async function syncContentScripts(): Promise<boolean> {
  const granted = await hasHostAccess();
  const registered = (await ext.scripting.getRegisteredContentScripts({ ids: [SCRIPT_ID] })).length > 0;
  if (granted && !registered) {
    await ext.scripting.registerContentScripts([
      { id: SCRIPT_ID, matches: HOSTS, js: ["content.js"], allFrames: true, runAt: "document_idle" },
    ]);
  } else if (!granted && registered) {
    await ext.scripting.unregisterContentScripts({ ids: [SCRIPT_ID] });
  }
  return granted;
}

/** Injects the content script into a tab (frames the extension may access). */
export async function injectInto(tabId: number): Promise<void> {
  try {
    await ext.scripting.executeScript({ target: { tabId, allFrames: true }, files: ["content.js"] });
  } catch {
    // Some frames are out of reach: the top-level page at least.
    await ext.scripting.executeScript({ target: { tabId }, files: ["content.js"] }).catch(() => undefined);
  }
}
