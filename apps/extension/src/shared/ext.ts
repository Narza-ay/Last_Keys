// The WebExtension API: `browser` on Firefox (promise-based), `chrome` on
// Chromium browsers (promise-based in Manifest V3 when no callback is
// given). Both share the shape described by @types/chrome for what this
// extension uses.

declare const browser: typeof chrome | undefined;

export const ext: typeof chrome =
  typeof browser !== "undefined" && browser?.runtime ? browser : chrome;

/** Host of the native messaging host (apps/desktop, crates/lk-bridge). */
export const NATIVE_HOST = "app.lastkeys.bridge";
