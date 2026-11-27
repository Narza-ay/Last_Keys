# Threat model

Version 1 — 2026-11-25. Reviewed at every milestone. Status of each
mitigation: ✅ implemented and tested · 📐 designed · ⬜ planned.

## 1. Assets

| Asset | Sensitivity |
|-------|-------------|
| Vault contents (passwords, notes, cards, identities, documents, TOTP secrets, passkey private keys) | Critical |
| Master password, master key, account key, vault/item keys | Critical |
| Recovery key | Critical |
| Device private keys | High (enable device impersonation) |
| Account private keys | Critical (certify devices, receive shares) |
| Metadata (item count, sizes, timestamps, device list, IP addresses) | Moderate |
| Telemetry | Low (must stay low by construction) |

## 2. Adversaries

| ID | Adversary | Capabilities |
|----|-----------|--------------|
| T1 | Network attacker | Observes and modifies traffic. |
| T2 | Compromised or malicious server / cloud operator / self-host admin | Full access to database, object storage, logs; can send arbitrary responses, replay, reorder, withhold. |
| T3 | Database thief (backup leak) | Offline access to all server data; unlimited guessing compute. |
| T4 | Malicious Last Keys user | Valid account; attacks other accounts through the API or sharing. |
| T5 | Thief of a locked device | Physical access, offline attacks on local storage. |
| T6 | Malicious website / iframe | Tries to obtain autofilled credentials or passkey assertions for another origin. |
| T7 | Malware on an unlocked device | Same privileges as the user. |
| T8 | Supply-chain attacker | Compromised dependency, build system or update channel. |
| T9 | Revoked device holder | Holds keys that were valid before revocation. |

## 3. Trust boundaries

1. Client process ↔ operating system (key stores, clipboard, accessibility).
2. Client ↔ server (TLS; the server is **not** trusted with plaintext — T2).
3. Browser extension content scripts ↔ web pages (T6).
4. Web application code ↔ the server that delivers it (T2, see §5).
5. Device ↔ device (P2P, transfers).

## 4. Threats and mitigations

### Confidentiality of the vault
| Threat | Mitigation | Status |
|--------|------------|--------|
| T2/T3 read vault data | Client-side encryption only; server stores envelopes (XChaCha20-Poly1305, per-item keys). | ✅ core, 📐 server |
| T3 offline guessing of the master password | Argon2id (≥ 64 MiB, t ≥ 2) per-account salt; recommended strong-password policy in the UI; OPAQUE so the server holds no password-equivalent verifier usable without the KDF cost. | ✅ KDF, 📐 OPAQUE |
| T2 sends weak KDF parameters to a new device | Client-enforced parameter floor. | ✅ |
| T2 substitutes the account public keys (to intercept shares or certify a fake device) | Public keys checked against the decrypted private keys at every unlock. | ✅ |
| T2 injects a device to receive the account key | Only account-signed certificates count; transfers only to certified, non-revoked devices; out-of-band pairing check. | ✅ signatures, 📐 pairing check (Phase 5) |
| T2 swaps/moves ciphertexts between items, vaults or accounts | Context binding in the AEAD associated data. | ✅ |
| T2 rolls back an item to an older valid version | Per-item revisions, pull cursor and server history checked by clients; any step back stops synchronization until the user confirms a full resynchronization, which keeps local versions as conflict copies ([ADR-0008](adr/0008-sync-protocol.md)). Binding the revision inside the encrypted content is planned with item schema 2 (until then a server can serve an older ciphertext under a new revision number). | ✅ detection (M3) / 📐 schema 2 |
| T2 withholds updates (freeze attack) | Detectable only partially (device-to-device comparison, P2P). Documented limitation. | 📐 |
| T1 | TLS 1.2+ (1.3 preferred) in addition to E2EE; certificate validation. | 📐 |

### Authentication and account takeover
| Threat | Mitigation | Status |
|--------|------------|--------|
| Credential stuffing / brute force against the API | Rate limiting per account and IP, OPAQUE, optional passkey second factor. | 📐 M3 |
| Session theft | Short-lived sessions bound to a device key (signed requests), revocation server-side. | 📐 M3 |
| Recovery abuse (e-mail takeover) | E-mail alone never grants access to data: recovery needs the recovery key or a trusted device (cryptographic). | ✅ design, 📐 server flow |
| T9 revoked device keeps access | Server refuses revoked devices; key rotation + eager re-encryption after revocation; data already decrypted cannot be recalled. | ✅ revocation statements, 📐 rotation (Phase 5) |

### Local device
| Threat | Mitigation | Status |
|--------|------------|--------|
| T5 reads local storage | Local store holds only envelopes; device-local key in hardware-backed store where available; protection level shown truthfully. | 📐 M2/Phase 5 |
| Secrets left in memory | Zeroization on drop, no `Debug` leakage, panic=abort in release, auto-lock. Best effort: GC languages (Kotlin/Swift/JS) cannot guarantee erasure. The desktop keeps keys and decrypted items in Rust; the web view only holds a secret the user revealed (hidden again after 30 s) and the master password while it is typed (ADR-0010). | ✅ core and desktop, 📐 mobile/web |
| Clipboard exposure | Copies made by Rust, cleared after a configurable delay (default 30 s) and on lock and exit if still present; exclude-from-history flags on Windows, macOS and KDE. | ✅ desktop (clearing tested on the real app), ⬜ mobile/extension |
| T7 malware on unlocked device | Out of scope for prevention (same privileges as user); reduce window with auto-lock and re-authentication for sensitive fields. | ✅ desktop: auto-lock after inactivity, current password required to change it or to replace the recovery key; system-lock hooks pending |
| Script injection in the desktop web view (a malicious item title, a crafted server answer) | React escapes all text; lint forbids `innerHTML`; strict CSP (`script-src 'self'`, no remote content); no plugin, file-system or shell access for the web view; the server is reached by Rust only. | ✅ desktop |

### Autofill and passkeys
| Threat | Mitigation | Status |
|--------|------------|--------|
| T6 phishing / lookalike domains | Exact origin matching with the Public Suffix List (private suffixes included), punycode comparison, no fuzzy matching; the page's origin comes from the browser, never from page content; Rust re-checks every fill, copy and update (ADR-0011). | ✅ extension (desktop-connected) |
| T6 invisible or cross-origin iframes | Frames of another origin filled only after the user's confirmation (enforced in Rust), frames of another site never; hidden, off-screen, disabled and read-only fields never filled; the content script re-checks its origin before writing; no fill on page load. | ✅ extension |
| Local process impersonating the extension or the desktop (browser bridge) | Native messaging host started only for the listed extension IDs; endpoint in a `0700` directory (named pipe, first instance, remote clients refused on Windows); pairing approved in the desktop with a code; mutual HMAC challenge-response on every connection (no reusable secret on the wire); the extension never sends its proof to an endpoint that failed to prove the key. Same-user malware reading the key on disk stays out of scope (T7). | ✅ desktop + extension |
| Malicious page abusing the extension | No in-page UI (nothing to click-jack), no web-accessible resource, page messages never accepted (only the extension's own content scripts and pages, identified by the browser); submitted credentials saved only after the user confirms in the popup. | ✅ extension |
| Passkey assertion for wrong RP | RP ID validated against the calling origin by the browser/OS and re-checked by Last Keys. | ⬜ Phase 5 |

### Supply chain and releases
| Threat | Mitigation | Status |
|--------|------------|--------|
| T8 malicious or vulnerable dependency | Minimal, reviewed dependencies; pinned `Cargo.lock` and `package-lock.json`; `cargo deny` (advisories, licenses, sources) in CI; npm install scripts disabled, exact versions at least two weeks old; Dependabot (npm with a two-week cooldown). | ✅ |
| T8 compromised CI / update channel | Signed releases, signature verification before update, reproducible builds as a goal. | ⬜ Phase 8 |

## 5. Accepted residual risks and limitations

* **Web application code delivery (T2):** a malicious server can serve
  JavaScript that captures the master password. Mitigated (CSP, SRI, no
  third-party scripts, can be disabled), not eliminated. Native apps and the
  extension are the high-assurance clients.
* **Metadata:** the server sees account e-mail, number and size of items,
  timestamps, device list, IP addresses. Item titles, URLs and all fields are
  encrypted.
* **Already-decrypted data** cannot be revoked (devices, share recipients).
* **Total credential loss** (password + recovery key + all trusted devices)
  means permanent data loss, by design.
* **Compromised unlocked device** (T7) can read everything the user can.

## 6. Out of scope

Physical attacks on hardware security modules, side channels on shared
hardware beyond what the primitives' constant-time implementations provide,
coercion of the user.
