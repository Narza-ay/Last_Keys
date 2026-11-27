# Last Keys browser extension (Chrome, Brave, Firefox)

**Status: implemented (milestone M5), connected to the desktop application.**
Tested end to end on Linux with Chromium (the real desktop application, the
real extension and native messaging; see `e2e/run.mjs`). The Firefox build
is produced and checked by unit tests but not driven end to end yet; Brave
uses the Chromium build and is not tested automatically (see
[docs/PLATFORM_COMPATIBILITY.md](../../docs/PLATFORM_COMPATIBILITY.md)).

Architecture and security model: [ADR-0011](../../docs/adr/0011-browser-extension.md).
The extension holds no vault data and no key: it asks the Last Keys desktop
application, which must be running, unlocked, with "Allow the browser
extension" turned on in its settings.

## What it does

* **Connect** to the desktop application once (a code shown in both, approved
  in the application); each connection is then mutually authenticated.
* **Fill**: the popup lists the logins of the current website (exact host
  first, then the same site; nothing for another site or a look-alike
  domain) and fills the one you choose. A form inside a frame of another
  origin is filled only after a confirmation. Nothing is filled
  automatically when a page loads.
* **Copy** a username, password or two-factor code: the desktop application
  puts it on the clipboard and clears it after its configured delay.
* **Save**: credentials you submit are proposed for saving (a new login, or
  a new password for an existing one); the toolbar button shows a badge and
  the popup asks.
* **Generate** a password (desktop generator) and fill it into the
  new-password fields of a registration or password-change form.
* French and English, light and dark (from the system).

Keyboard shortcut: Alt+Shift+L opens the popup.

## Develop

```bash
npm ci                  # install scripts are disabled (.npmrc)
npm run build           # dist/chrome (Chrome, Brave) and dist/firefox
```

Load `dist/chrome` with "Load unpacked" (chrome://extensions, developer mode)
or `dist/firefox` from about:debugging ("Load Temporary Add-on", select
`manifest.json`). The unpacked Chromium build has a fixed ID
(`bblheiicocdmmkjnhdeehaedddgcfhok`, from the development key in
`manifest.chrome.json`): the desktop application allows only that ID and the
Firefox ID `browser-extension@lastkeys.app` to start its native messaging
host. Then turn on "Allow the browser extension" in the desktop application.

## Test

```bash
npm run lint && npm run typecheck   # includes the "no hard-coded text" rule
npm test                            # Vitest: detection, filling, capture,
                                    # session and protocol, router, popup,
                                    # manifests, translations
(cd ../desktop && npx tauri build --debug --no-bundle) && npm run build
xvfb-run -a node e2e/run.mjs        # real desktop + Chromium + extension
                                    # (Linux; needs tauri-driver,
                                    # WebKitWebDriver)
```

## Not yet

Inline suggestions in form fields and an in-page save bar (decisions stay in
the popup for now), filling payment cards and identities, passkeys (M9), a
standalone mode without the desktop application (M13), store publication
(Chrome Web Store, AMO; IDs are an owner decision).
