# Last Keys desktop application (Windows, macOS, Linux)

**Status: implemented (milestone M4).** Tested end to end on Linux
(the real application, through WebDriver); built and packaged by CI on
Windows and macOS, not yet tested on physical Windows or macOS machines
(see [docs/PLATFORM_COMPATIBILITY.md](../../docs/PLATFORM_COMPATIBILITY.md)).

Stack and security model: [ADR-0010](../../docs/adr/0010-desktop-application.md).
Tauri 2 shell with a Rust back end (`src-tauri`, crate `lk-desktop`) built on
`lk-client`; React + TypeScript user interface (`src`), French and English,
light, dark and system themes.

## What it does

* First start: create a vault (master password, recovery key shown once) or
  add this device to an existing account (server, e-mail, master password).
* Unlock with the master password, or with the recovery key to reset a
  forgotten password; manual lock (Ctrl/⌘+L), automatic lock after
  inactivity (Rust timer), lock when the application exits.
* Logins (with TOTP codes and backup codes), secure notes, payment cards,
  identities with documents; custom fields; folders, tags, favorites;
  search (never over secrets); password history with restore and delete.
* Secrets are revealed one at a time and hidden again after 30 s; copies go
  from Rust to the clipboard, excluded from clipboard history where the
  system allows it, and cleared after a configurable delay.
* Password and passphrase generator.
* Registration on a server, automatic synchronization (on unlock, after
  changes, every 5 minutes), full resynchronization after a server restore.
* Devices of the account, verified with the account key; revocation.
* Settings: language, theme, auto-lock delay, clipboard delay, master
  password change, recovery key replacement, information about the vault.

## Develop

Requirements: Rust (pinned toolchain), Node.js 22, and on Linux the
WebKitGTK development packages:

```bash
sudo apt-get install libwebkit2gtk-4.1-dev librsvg2-dev libayatana-appindicator3-dev libxdo-dev
```

```bash
cd apps/desktop
npm ci                      # install scripts are disabled (.npmrc)
npx tauri dev               # the application with hot reload
VITE_LK_MOCK=1 npm run dev  # the interface alone in a browser, scripted back end
```

The scripted back end (`src/api/mock.ts`) exists for the browser preview and
the UI tests only; it is never bundled in a Tauri build (checked: the
production bundle does not contain it). URL parameters:
`?state=fresh|locked|unlocked&registered=1&lang=fr|en&theme=light|dark`;
the sample vault's master password is `correct horse battery staple`.

`LK_DESKTOP_DATA_DIR` relocates the vault and the settings (tests, portable
use); otherwise they live in the platform's application data directory
(identifier `app.lastkeys.desktop`, provisional).

## Test

```bash
npm run lint && npm run typecheck   # includes the "no hard-coded text" rule
npm test                            # Vitest: catalogues, drafts, screens
npm run test:e2e                    # Playwright: the interface in Chromium
cargo test -p lk-desktop            # Rust back end
npx tauri build --debug --no-bundle && xvfb-run -a node e2e-tauri/run.mjs
                                    # the real application (Linux, needs
                                    # tauri-driver, WebKitWebDriver, xclip)
```

## Build installers

```bash
npx tauri build   # deb, rpm, AppImage on Linux; MSI and NSIS on Windows; app and DMG on macOS
```

Installers are not signed yet (release pipeline, Phase 8).

## Not yet

Locking on system sleep or session lock, biometric unlock and hardware key
storage (M7), autofill (browser extension, M5), NordPass import (M6),
attachments (M12), single-instance enforcement, signed installers and
automatic updates.
