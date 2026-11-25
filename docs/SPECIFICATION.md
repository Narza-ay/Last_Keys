# Last Keys — Product specification

Version: **1.0 (locked)** — 2026-11-25.
Source: *Last Keys — Master Development Prompt v1.0* and the 14 product
decisions of the owner (§2). This document is the normative reference; the
roadmap, architecture and tests trace back to the requirement IDs below.
Open questions and conflicts are tracked in [AUDIT.md](AUDIT.md).

**Tagline:** Your passwords. Your keys. Your control.

Requirement keywords: **MUST** (mandatory), **SHOULD** (expected unless a
documented reason prevents it), **MAY** (optional).

---

## 1. Product

Last Keys is a premium, cross-platform password manager and digital identity
vault. It is a real product, not a prototype: working cryptography, real
authentication, persistent storage, real synchronization, native integrations.

| ID | Requirement |
|----|-------------|
| PRD-1 | Security features MUST NOT be simulated; compatibility MUST NOT be claimed without a test on that platform. |
| PRD-2 | Unavailable platform features MUST NOT be silently replaced by fakes; the limitation MUST be documented and the best secure alternative implemented. |
| PRD-3 | Source code is private and proprietary. Code and technical documentation in English; user interface in French and English with an internationalization architecture from the start. |
| PRD-4 | The interface MUST be minimal, elegant, accessible, responsive, with light, dark and system themes. Competitor branding and interfaces MUST NOT be copied. |
| PRD-5 | A disabled or unsupported feature MUST be clearly identified in the UI. |

## 2. Locked product decisions

| # | Topic | Decision |
|---|-------|----------|
| 1 | Passkeys | A genuine cross-platform passkey manager and WebAuthn authenticator. |
| 2 | Recovery | Two independent methods: personal recovery key **or** trusted secondary device. |
| 3 | Account | E-mail address + master password + device-specific passkeys. |
| 4 | Region | European Union, ideally France. |
| 5 | Cloud model | Free cloud to start, with a possible premium offer later. |
| 6 | Self-hosting | Docker Compose; simple installation on a NAS, VPS or personal server. |
| 7 | Sharing | Both: sharing with Last Keys users and encrypted temporary links. |
| 8 | Devices | Unlimited number of devices, individually revocable. |
| 9 | Offline | Full access to already-synchronized data, offline editing, automatic sync on reconnection. |
| 10 | OS versions | Windows 11+, macOS 14+, Android 10+, iOS 17+, maintained Linux distributions. |
| 11 | Languages | French and English from the first version; multilingual architecture. |
| 12 | Import | NordPass import from a locally exported file, never transmitted to the server. |
| 13 | Backups | Automatic encrypted cloud backup + manual encrypted local export. |
| 14 | Telemetry | Enabled by default, can be disabled at any time, strictly technical and anonymized data. |

Absolute priority: **security and reliability**.

## 3. Platforms

| ID | Requirement |
|----|-------------|
| PLT-1 | Desktop: Windows, macOS, Linux (Tauri 2, Rust backend, TypeScript UI). |
| PLT-2 | Mobile: Android (Kotlin, Keystore, Autofill Framework, Credential Manager, BiometricPrompt) and iOS (Swift, Keychain, Secure Enclave, LocalAuthentication, AuthenticationServices, Credential Provider extension). |
| PLT-3 | Browser extensions: Chrome, Firefox, Brave (TypeScript, WebExtensions, Manifest V3 where supported). |
| PLT-4 | Web application (React, TypeScript, strict CSP): authentication, vault browsing, credential management, sharing, account, devices, sync status, security settings. It MUST NOT have unrestricted access to local private keys and MUST NOT store decrypted vault contents in persistent browser storage. |
| PLT-5 | Business logic SHOULD be shared (Rust core); platform integrations go through native adapters. |

## 4. Cryptography

| ID | Requirement |
|----|-------------|
| CRY-1 | All vault encryption and decryption happens on the client. The backend MUST NOT receive plaintext vault data or the keys to decrypt it. |
| CRY-2 | Master password: chosen by the user, never transmitted, stretched with Argon2id (parameters chosen by measurement), never recoverable by the server. Password change MUST NOT require the server to decrypt anything. Server authentication MUST be separate from vault encryption. |
| CRY-3 | Versioned key hierarchy: account identity, vault keys, per-item keys, device key pairs, sharing keys, recovery material, rotation. |
| CRY-4 | Standard, audited primitives only (XChaCha20-Poly1305 or AES-256-GCM, X25519, Ed25519, Argon2id, OS CSPRNG). No invented algorithms, no custom primitives. Domain separation; nonces never reused under one key. |
| CRY-5 | Every encrypted object carries a versioned envelope with algorithm identifiers and integrity data. |
| CRY-6 | Each physical device has an independent identity: unique ID, its own key pair, registered public key, protected private key, name, OS, creation date, last sync, trust and revocation status. Hardware protection used where available and never claimed where absent. |
| CRY-7 | Device revocation prevents future authentication and sync, invalidates authorization and sessions, rotates affected secrets, keeps other devices working, and a revoked device cannot rejoin with old credentials. Data already copied cannot be erased remotely (documented). |

## 5. Authentication and unlocking

| ID | Requirement |
|----|-------------|
| AUT-1 | Support master password, device passkeys for Last Keys authentication, biometrics, Windows Hello, Face ID, local PIN, recovery key, trusted secondary device. |
| AUT-2 | Biometrics and PIN authorize access to protected local key material; they MUST NOT replace the key hierarchy. |
| AUT-3 | Automatic lock, configurable inactivity timeout, lock on exit, lock on sleep where possible, failed-attempt protection, session expiry, secure logout. |
| AUT-4 | No hidden master recovery mechanism. |

## 6. Recovery

| ID | Requirement |
|----|-------------|
| REC-1 | Personal recovery key, generated securely and shown only through a secure process. |
| REC-2 | Trusted secondary device providing *cryptographic* authorization, not a notification approval. |
| REC-3 | Documented procedures: recovery, device replacement, device loss, account recovery, recovery-key rotation, failure scenarios. |
| REC-4 | The cloud administrator MUST NEVER be able to recover plaintext vault contents. |

## 7. Vault

| ID | Requirement |
|----|-------------|
| VLT-1 | Credentials: website, application, username, password, URLs, notes, custom fields, tags, favorites, folders, creation/modification dates. |
| VLT-2 | Password generator: length, character classes, excluded characters, minimum counts, passphrases (word count, separator), strength evaluation, CSPRNG. |
| VLT-3 | Passkeys: standards-based WebAuthn/FIDO2, real authenticator where permitted, clear distinction between Last Keys login credentials and third-party website passkeys; no claim that non-exportable platform credentials can be exported. |
| VLT-4 | Payment cards (holder, number, expiry, security code where permitted, billing address, notes) with re-authentication before revealing sensitive fields. |
| VLT-5 | Secure notes with structured content and custom fields. |
| VLT-6 | Identities and documents: personal data, addresses, identity documents, attachments, expiry dates; files encrypted before upload. |
| VLT-7 | TOTP: standard TOTP, QR import, manual entry, time-sync checks, backup codes; secrets never in logs or telemetry. |
| VLT-8 | Encrypted password history with restore and delete. |

## 8. Autofill

| ID | Requirement |
|----|-------------|
| AFL-1 | Browser extensions detect login, registration and password-change forms; match the exact domain; support multiple accounts per domain; fill, generate, save. |
| AFL-2 | Never fill on an untrusted domain; validate origin; resist lookalike domains; never expose credentials to unrelated frames; minimal host permissions; confirmation when risk is elevated. |
| AFL-3 | Android Autofill Framework and Credential Manager; iOS Password AutoFill credential provider extension; desktop platform mechanisms with the browser extension as fallback. |

## 9. Security center

| ID | Requirement |
|----|-------------|
| SEC-1 | Weak, reused, compromised, old and duplicate credentials; recommendations; device overview; suspicious-session alerts. |
| SEC-2 | Breach checking MUST be privacy-preserving (k-anonymity or equivalent); plaintext passwords MUST NOT be sent to a third party; limitations explained. |

## 10. Synchronization

| ID | Requirement |
|----|-------------|
| SYN-1 | Official cloud storing only encrypted data and sync metadata, without vault keys. |
| SYN-2 | Peer-to-peer encrypted sync between authorized devices with an authenticated protocol and relay fallback, without unnecessary exposure of private network information. |
| SYN-3 | Self-hosted server: Docker Compose, environment variables, migrations, storage, TLS, backup/restore, upgrades, health checks; protocol compatible with the official cloud. |
| SYN-4 | Offline: usable after an authorized first unlock (access, editing, generator, TOTP, local encrypted storage, deferred sync); unlocking a provisioned device MUST NOT require Internet access. |
| SYN-5 | Conflicts: versioned change log, unique change IDs, idempotent sync, conflict detection, safe merge, tombstones, recovery of conflicting versions. Concurrent changes MUST NEVER be silently overwritten. |

## 11. Sharing

| ID | Requirement |
|----|-------------|
| SHR-1 | With Last Keys users: selected items, permissions, expiry, revocation, access history, key rotation. |
| SHR-2 | Encrypted temporary links: decryption secret delivered separately from the server-visible link, expiry, optional password, access limits, revocation and download restrictions where technically possible. No claim that a recipient cannot copy what they decrypted. |

## 12. Import, backup, telemetry

| ID | Requirement |
|----|-------------|
| IMP-1 | NordPass first: official exports, parsing, validation, preview, duplicate detection, categories preserved, failures reported, immediate encryption, no persistent plaintext temporary files. Then Bitwarden, 1Password, CSV. |
| BAK-1 | Automatic encrypted backup to the cloud and manual encrypted local export (decision 13; destination policy in AUDIT A-3). |
| TEL-1 | Telemetry on by default, can be disabled anytime, technical data only (version, OS, crash reports, performance, feature counters, sync error codes, compatibility diagnostics). MUST NEVER collect passwords, vault contents, TOTP secrets, keys, recovery keys, decrypted documents, form contents or sensitive URLs. Data minimization, retention limits, transparent documentation (legal basis: AUDIT A-1). |

## 13. Backend

| ID | Requirement |
|----|-------------|
| BCK-1 | Rust, REST API, WebSocket sync, PostgreSQL, encrypted object storage, background jobs. |
| BCK-2 | Strong authentication, rate limiting, request validation, session management, device authorization, audit logging, TLS, database access control, secret management, secure upload, abuse protection. |
| BCK-3 | All clients are untrusted: authorization and envelope validation server-side; the server never decrypts vault records. |

## 14. Quality

| ID | Requirement |
|----|-------------|
| QA-1 | Unit, integration, platform and security tests at every layer; property-based testing and fuzzing for security-critical parsers and protocols. |
| QA-2 | Independent security reviews before production. |
| QA-3 | Definition of Done (spec §20): implemented, connected to the real engine, security properties tested, unit/integration/platform tests passing, documentation and limitations updated, UI reflects real state, no placeholder presented as production functionality. |

## 15. Navigation

Overview · Logins · Passkeys · Payment cards · Secure notes · Identities ·
Documents · Authenticator · Password generator · Security center · Devices ·
History · Sharing · Settings. Mobile uses mobile-native navigation.
