# ADR-0011: Browser extension connected to the desktop application

* Status: Accepted
* Date: 2026-11-26

## Context
Milestone M5 delivers autofill in Chrome, Brave and Firefox (PLT-3,
AFL-1, AFL-2; criteria V-A1 to V-A3). An extension can either hold the
vault itself (unlock with the master password in the browser, keys in the
extension's JavaScript and WebAssembly memory, its own synchronization) or
ask the desktop application, which already holds the unlocked vault in
Rust. The owner chose the second mode for M5 (2026-11-26): no key, no
decryption and no vault copy in the browser. A standalone mode for
computers without the desktop application is deferred to M13, together with
the web application's WebAssembly work (ADR-0006 stays in force for both).

## Decision

### Components
```
page ⇄ content script ⇄ background ⇄ native messaging ⇄ relay ⇄ local socket ⇄ desktop (Rust, vault)
```
1. **`lk-autofill`** (Rust, portable): which stored URL may be used on which
   page. Rules in the crate documentation; summary: `http`/`https` pages
   only; hosts compared in punycode form; exact host, or same registrable
   domain by the Public Suffix List including its private section
   (`alice.github.io` ≠ `bob.github.io`); IP addresses, single-label hosts
   and public suffixes match exactly; no fuzzy or substring matching; a
   login saved for `https` is never offered on `http`; ports must agree.
   The list is compiled into the binary (`psl` crate, pinned, list data
   MPL-2.0); it is updated through dependency updates.
2. **Desktop bridge** (in `lk-desktop`): a local endpoint served while the
   application runs and browser integration is enabled — a Unix domain
   socket in a `0700` directory of the application data directory (Linux,
   macOS), a named pipe whose name is derived from the user's data
   directory, first instance only, remote clients rejected (Windows).
3. **Relay**: the desktop executable itself, started by the browser through
   native messaging (host `app.lastkeys.bridge`, provisional like the
   application identifier). It recognises the arguments browsers pass
   (Chromium: the caller's `chrome-extension://…/` origin; Firefox: the
   manifest path and the extension ID), does not initialise the window or
   open the vault, and copies frames between its standard input/output and
   the local endpoint. The first frame it sends announces the caller the
   browser reported. Using the same executable means no extra binary to
   bundle or sign; for an AppImage the registered path is the AppImage file
   (`$APPIMAGE`), not the temporary mount point.
4. **Extension** (`apps/extension`, TypeScript, Manifest V3): background
   (service worker on Chromium, event page on Firefox), content scripts
   (form detection, filling, capture of submitted credentials), popup
   (React, French and English, the desktop's design tokens).

Native host manifests are written by the desktop application when the user
enables browser integration (Settings): JSON files in each browser's
per-user directory on Linux and macOS, plus `HKCU` registry keys on Windows,
for Chrome, Chromium, Brave and Firefox. Only the extension IDs listed in the
manifest may start the relay (`allowed_origins`, `allowed_extensions`).

### Frames and messages
Every message is a JSON object in a frame prefixed by its length (32-bit
little-endian, as native messaging uses on every supported platform),
1 MiB at most, in both directions and on both hops. Requests carry an `id`
echoed by the response; the desktop also pushes events (`locked`,
`unlocked`, `revoked`).

### Pairing and authentication
* **Pairing**, started from the popup: the desktop shows a dialog naming the
  browser and the extension, with a short code that the popup shows too;
  the user compares and approves in the desktop application. The desktop
  then creates a client ID and a random 256-bit key, stored in the
  application data directory (`bridge.json`, mode `0600` on Unix) and, in
  the extension, as a non-extractable WebCrypto key in IndexedDB (not
  reachable from content scripts). One pairing request at a time; requests
  expire after two minutes; refusals add a delay before the next one.
* **Each connection** is mutually authenticated by challenge and response:
  the extension sends its client ID and a nonce, the desktop proves
  knowledge of the key (HMAC-SHA-256 over both nonces with a server label),
  the extension verifies, then proves it in turn (client label). A process
  that occupies the endpoint while the desktop is not running learns
  nothing reusable. Nothing but `pair`, `hello` and `auth` is accepted
  before authentication; one failure closes the connection.
* Pairings are listed in Settings with their browser and last use, and can
  be revoked (connected clients are disconnected at once).

### Autofill policy (AFL-2, V-A1, V-A2)
1. **The page's origin comes from the browser**, never from page content:
   the background uses `sender.url`, `sender.tab.url` and `sender.frameId`
   of content script messages, and the active tab's URL for the popup.
2. **Rust decides.** The desktop answers `list` with the logins that match
   the top-level page only, and re-checks every `fill` and `copy`: the item
   must match the top-level page and the frame that holds the form; when
   the frame's origin differs from the page's, the request must carry the
   user's explicit confirmation, which the popup asks for (V-A2).
3. **Filling happens only on a user action** (popup or its keyboard
   shortcut); never on page load. Only visible, enabled fields of the frame
   are filled; the content script checks again that its frame still has the
   expected origin before writing.
4. The extension never receives the vault list: only the matching logins
   (title, username, match type) and, for a fill, that one item's username,
   password and current TOTP code. "Copy" is done by the desktop
   (clipboard cleared after the configured delay); the value does not enter
   the extension.
5. **Saving**: the content script reports submitted credentials; the
   background keeps them in session storage (memory only, five minutes);
   the desktop says whether this is a new login, a changed password for an
   existing login of that site and username, or nothing to do; the popup
   proposes it and saves only when the user confirms. The stored URL is the
   page's origin; the title is its registrable domain.
6. Generating a password uses the desktop generator; the result can be
   filled into new-password fields and is then captured like any submitted
   password.

### Permissions (AUDIT P-9)
Required: `nativeMessaging`, `storage`, `activeTab`, `scripting` (the only
install-time warning is the native messaging one). Access to every site
(`http://*/*`, `https://*/*`) is an **optional** host permission that the
popup proposes with an explanation:
* granted: the content script is registered for every http/https page
  (form detection, capture of submitted credentials everywhere);
* declined: click-to-fill. Opening the popup gives the extension temporary
  access to the current tab (`activeTab`), and the popup injects the content
  script there; credentials submitted elsewhere are not captured.
The popup also injects the content script into its tab when access is
granted, for tabs opened before the registration (the script runs once per
frame). No `<all_urls>`, `file://`, `tabs`, `webRequest`, `cookies` or
`history`; no web-accessible resource. Strict extension CSP
(`script-src 'self'`). No remote code, no analytics, no request to any
server: the extension talks only to the desktop application.

The browser's permission prompt cannot be automated; the end-to-end test
uses a build variant (`dist/chrome-e2e`, never published) in which this
access is granted at installation, which leads to the same code paths as a
user who allowed it.

### State and locking
The extension holds no vault state: when the desktop locks, it pushes
`locked` and the popup offers to bring the application to the front for
unlocking (the master password is never typed in the browser). Explicit
actions through the extension (fill, copy, save, generate) count as user
activity for the desktop's auto-lock; listing does not.

## Consequences
* The extension's compromise exposes at most the logins of the pages the
  user fills, not the vault; the vault keys never enter a browser process.
* The desktop application must be running and unlocked for autofill;
  without it, the popup says so.
* Browsers installed as Flatpak or Snap packages cannot start native hosts
  outside their sandbox: not supported (documented).
* Same-user malware can read the pairing key from the browser profile and
  talk to the desktop like the extension: outside the threat model (T7),
  as for keyloggers.
* Extension IDs: a development key fixes the Chromium ID for unpacked
  builds; the Chrome Web Store ID and the Firefox add-on ID are owner
  decisions to take before publication (KNOWN_LIMITATIONS).

## Alternatives considered
* **Standalone extension with WebAssembly** (ADR-0006): works without the
  desktop but puts keys in the browser; deferred to M13 as the owner chose.
* **A separate relay binary**: smaller, but one more executable to bundle,
  sign and keep in sync per platform; the relay mode of the desktop
  executable runs none of the window or vault code.
* **WebSocket or HTTP server on localhost**: reachable by every web page
  (DNS rebinding, CSRF) and every local process; native messaging restricts
  who starts the relay to the listed extensions.
* **In-page save bar and inline field menus**: more convenient, but a page
  can overlay or click-jack in-page UI; M5 keeps every decision in the popup
  (toolbar badge when there is something to save). Revisit later with an
  isolated frame.
* **Host access required at installation**: simpler (content scripts
  declared in the manifest) but contrary to the least-privilege resolution
  of AUDIT P-9; rejected.
