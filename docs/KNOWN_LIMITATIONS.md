# Known limitations

Maintained continuously (spec §19). Each entry links to its analysis in
[AUDIT.md](AUDIT.md). "Current" limitations exist in the code today;
"platform/design" limitations are permanent consequences of a platform or of
the security model.

## Current (M5)

| Limitation | Planned resolution |
|------------|--------------------|
| Desktop app: tested end to end on Linux only; Windows and macOS builds come from CI and have not been run on physical machines. | Platform test campaign before v0.1 |
| Desktop app: no lock on system sleep or session lock (inactivity timeout and exit only); no biometric unlock or hardware key storage. | System hooks before v0.1 (V-A4); M7 |
| Desktop app: the master password is typed in the web view and briefly exists as a JavaScript string; revealed secrets live in the web view until hidden (30 s) or locked. | Inherent to a web-view UI (ADR-0010); mitigated by keeping everything else in Rust |
| Desktop app: while a synchronization runs, other actions wait for it (one lock protects the vault), up to the network timeout. | Run network calls outside the vault lock (before v0.1) |
| Desktop app: no import (M6), no attachments (M12), no single-instance enforcement, installers unsigned and no automatic updates; the AppImage tooling downloaded by the Tauri CLI is not pinned. | M6, M12; release pipeline (Phase 8) |
| Desktop app: bundle identifier `app.lastkeys.desktop` is provisional (it fixes the data directory). | Owner decision (product domain) before the first release |
| Browser extension: works only with the desktop application running and unlocked on the same computer (no standalone mode). | M13 (standalone mode with WebAssembly, ADR-0011) |
| Browser extension: driven end to end automatically on Linux with Chromium only. The Firefox build is covered by unit tests and manifest checks but not loaded in Firefox by a test; Brave and Chrome on Windows/macOS are not tested; native host registration on Windows (registry, through `reg.exe`) and macOS has never run. The browser's prompt for access to every site cannot be automated (the end-to-end test grants it at installation). | Manual matrix ([TESTING.md](TESTING.md)) and platform campaign before v0.1 |
| Browser extension: browsers installed as Flatpak or Snap packages cannot start native messaging hosts outside their sandbox. | Platform limitation; documented in the settings page |
| Browser extension: no suggestions inside form fields and no in-page save bar (every decision is in the popup, with a toolbar badge); logins only (no cards or identities); one-time codes filled only into recognised one-time-code fields. | Later milestones |
| Browser extension: IDs (Chromium development key `bblheiicocdmmkjnhdeehaedddgcfhok`, Firefox `browser-extension@lastkeys.app`) and the native host name `app.lastkeys.bridge` are provisional; not published on the Chrome Web Store or AMO. | Owner decision before publication |
| Browser bridge: the pairing key is kept in the browser profile (non-extractable WebCrypto key in IndexedDB) and in the desktop data directory (`bridge.json`, mode `0600` on Unix); malware running as the user can read both (T7). The named pipe on Windows keeps the default security descriptor (mutual authentication still applies). | Out of scope (T7); platform key stores in M7 |
| A portable data directory (`LK_DESKTOP_DATA_DIR`) works with the extension only if the browser runs with the same variable. | Documented |
| Server: no e-mail verification at registration (registering reveals whether an e-mail is already taken), no WebSocket notifications (clients synchronize on demand), no account deletion, plain (non-TLS) connection to PostgreSQL (intended for the internal Docker network only). | Before v0.1 (notifications, account deletion), before the official cloud (e-mail verification) |
| Self-hosting: `linux/amd64` image only, built locally (no published or signed image); upgrade from a previous release untested (there is none yet). | arm64 and published images before v0.1; upgrade test with the first release |
| After a server restore, every device must run `lk sync --reset`; versions written after the backup come back as conflict copies and deletions made after the backup reappear (nothing is lost). | Finer resynchronization (ADR-0008, "Restore") |
| Synchronization is verified by deterministic multi-device scenarios only; the randomized simulation (≥ 5 devices, ≥ 10 000 operations, V-Y3) is not written yet. | Before v0.1 |
| Revoking a device does not rotate vault keys (a revoked device keeps the keys it held; the server refuses it). | M7 |
| The `lk` CLI is English-only, notes are entered on a single line, and every command asks for the master password (no session caching). | Use the desktop app for FR/EN and sessions |
| Store crash-safety relies on SQLite transactions; process-kill injection tests are not written yet (V-S2). | Before v0.1 |
| Argon2id default parameters measured only on a server vCPU (≈ 147 ms); not yet on mobile or in WebAssembly. | KDF campaign (V-C8): needs the physical devices and the WASM harness (M13) |
| WebAssembly build is compile-checked in CI but not executed in a browser (the M5 extension does no cryptography, ADR-0011). | M13 (`lk-wasm` for the web application and the standalone extension mode) |
| Device-identity and private-key storage use a caller-supplied wrapping key; platform key-store adapters (hardware protection) do not exist yet. | Phase 5 / M7 |
| Pairing verification between a new device and a trusted device (out-of-band code) is not designed yet. | Phase 5 / M7 |
| Windows and macOS: the Rust core is tested by the CI matrix (GitHub-hosted runners) only, not on physical user machines. | Platform test campaign before v0.1 |
| Strength estimation exists only for generated secrets (exact entropy); passwords chosen by users (including the master password) are not yet scored, only checked for length. | Security center (Phase 7) |
| Passphrases use the English EFF wordlist only. | French wordlist with a compatible license (before v0.1) |
| `opaque-ke` 4 depends on `crypto-bigint` 0.5 (RUSTSEC-2026-0387). The affected code is not linked with our cipher suite (verified in CI); the exception disappears with `opaque-ke` 5. | Migrate when `opaque-ke` 5 is stable |
| GitHub Actions in CI are pinned to major version tags, not commit SHAs. | Pin to SHAs when the release pipeline is set up (Phase 8) |

## Platform and design

* Data already decrypted by a revoked device or a share recipient cannot be erased remotely (AUDIT K-4).
* Losing the master password, the recovery key and every trusted device makes the vault unrecoverable, by design (K-5).
* An offline device keeps working with the state it last synchronized, including an old password, until it reconnects (K-6).
* Android 10–13: no system-wide third-party passkey provider (API 34+ required) (P-1).
* Windows: native passkey provider only on recent Windows 11 builds; elsewhere via the browser extension (P-2).
* Linux: no system autofill or passkey provider, no standard hardware-backed key store; local protection is software (OS keyring) (P-3).
* macOS/iOS system AutoFill requires a native Swift extension and an Apple Developer account (P-4).
* Passkey login to a self-hosted server requires a domain name and a valid TLS certificate (P-6).
* The web application trusts the server that delivers its code (P-7).
* Browser extension: automatic form detection and saving need the optional access to every site; without it, click-to-fill only, on the page where the popup is opened (P-9).
* Peer-to-peer sync works while apps are active; a relay is needed across NATs (P-10).
* The browser extension holds no vault: it follows the desktop application's lock, so locking on system sleep depends on the desktop (V-A4) (P-11).
* Breach detection only knows publicly known breaches (SEC-2).
* Memory zeroization is best effort, and impossible to guarantee in garbage-collected UI layers (Kotlin, Swift, JavaScript).
