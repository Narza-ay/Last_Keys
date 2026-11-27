# API (version 1)

**Status: implemented in `apps/server` (milestone M3).** Request
and response types are defined in `crates/lk-protocol`; this page is the
human-readable index. WebSocket notifications are not implemented yet.

## Conventions

* Base path `/v1`; breaking changes only in a new version.
* JSON over HTTPS (TLS terminated by the reverse proxy).
* Binary values (OPAQUE messages, envelopes, keys, signatures) are unpadded
  Base64url strings.
* Errors: HTTP status + `{"error": "<code>", "message": "…"}` with stable
  codes (`bad_request`, `unauthorized`, `invalid_credentials`, `forbidden`,
  `device_revoked`, `not_found`, `email_taken`, `registration_closed`,
  `rate_limited`, `payload_too_large`, `expired`, `internal`). Messages never
  contain secrets.
* Authentication: `Authorization: Bearer <session token>`. The token is
  derived by the client from the OPAQUE session key (ADR-0005); the server
  stores only its SHA-256.
* Body limits: 256 KiB, except pushes (32 MiB). Pushes carry at most 500
  changes; pulls return at most 500 states.
* Rate limits (per IP and per e-mail hash) on pre-login, registration and
  login.

## Session scopes

| Scope | Obtained by | Allowed |
|-------|-------------|---------|
| `full` | password login from a registered, non-revoked device | everything below |
| `enrollment` | password login from an unknown device | read the bundle, register **its own** certificate (then upgraded to `full`) |
| `recovery` | recovery-key login | read the bundle, replace the password credential (then every session of the account ends) |

Every authenticated request re-checks that the device is not revoked.

## Endpoints

| Method and path | Scope | Purpose |
|-----------------|-------|---------|
| `GET /v1/health` | — | Liveness and database check |
| `POST /v1/accounts/prelogin` | — | KDF configuration for an e-mail (deterministic fake for unknown e-mails) |
| `POST /v1/accounts/register/start` | — | OPAQUE registration responses (password and recovery credentials) |
| `POST /v1/accounts/register/finish` | — | Create the account: OPAQUE uploads, encrypted bundle, first device certificate |
| `POST /v1/auth/login/start` | — | OPAQUE login (password or recovery credential), bound to a device id |
| `POST /v1/auth/login/finish` | — | Complete the login; single-use attempt, expires after 120 s |
| `GET /v1/auth/session` | any | Current session (account, device, scope) |
| `POST /v1/auth/logout` | any | End the session |
| `GET /v1/account/bundle` | any | Encrypted account bundle |
| `POST /v1/account/credentials/start` | full; recovery (password only) | OPAQUE registration response for a replaced credential |
| `POST /v1/account/credentials/finish` | full; recovery (password only) | Replace the credential and the bundle atomically (account identity must not change) |
| `GET /v1/devices` | full | Certificates, revocations, last activity |
| `POST /v1/devices` | full; enrollment (own device) | Register an account-signed device certificate |
| `POST /v1/devices/{device_id}/revoke` | full | Record an account-signed revocation; ends the device's sessions |
| `GET /v1/vaults` | full | Wrapped vault keys |
| `PUT /v1/vaults/{vault_id}/key` | full | Store a wrapped vault key |
| `POST /v1/vaults/{vault_id}/changes` | full | Push changes (idempotent, conflict-detecting, ADR-0008) |
| `GET /v1/vaults/{vault_id}/changes?since=&limit=` | full | Pull states after a sequence number, with the account's latest sequence number (`head`) and the server history identifier (`history`) |

## Server history and restores

Every pull returns `head` (the account's latest sequence number) and
`history` (an identifier that `infra/restore.sh` replaces after restoring a
backup). A client whose cursor is ahead of `head`, or that sees another
`history`, stops synchronizing with an explicit error; the user then runs a
full resynchronization (`lk sync --reset`), which uploads every local item
again and keeps differing versions as conflict copies (ADR-0008, "Restore").

## Browser bridge (local, ADR-0011)

**Status: implemented in `apps/desktop` (milestone M5).** Not an HTTP API:
the protocol between the browser extension and the desktop application,
through native messaging and the desktop's local endpoint (Unix socket or
named pipe). Request types are defined in `crates/lk-bridge/src/proto.rs`;
answers are built in `apps/desktop/src-tauri/src/bridge/session.rs`.

* Frames: 32-bit little-endian length, then a UTF-8 JSON object; 1 MiB at
  most. Every message has `id` (chosen by the sender, echoed by the answer;
  `0` for events) and `type`.
* Errors: `{"id", "type": "error", "code", "message"}` with the desktop's
  error codes (`locked`, `not_found`, `ineligible_page`, `origin_mismatch`,
  `confirmation_required`, `invalid_input`, `rate_limited`, …) and the
  bridge's own: `malformed`, `not_authenticated`, `unknown_client`,
  `auth_failed`, `pairing_busy`, `pairing_refused`, `pairing_timeout`, and
  `desktop_unavailable` (sent by the relay when the application cannot be
  reached).
* The first frame of a connection is the relay's
  `{"type": "relay", "caller", "browser", "version"}`; any other first frame
  closes the connection.

| Request | Before authentication | Answer |
|---------|-----------------------|--------|
| `pair {clientName}` | yes | `pairing {code}`, then `paired {clientId, key}` once approved in the desktop (or an error) |
| `hello {clientId, nonce}` | yes | `challenge {nonce, proof}` (desktop proof, see `lk-bridge` `auth`) or `unknown_client` |
| `auth {proof}` | after `hello` | `ready {locked, vaultExists, version}`; a wrong proof closes the connection |
| `status` | no | `status {locked, vaultExists, version}` |
| `focus` | no | `ok` (the desktop window comes to the front) |
| `list {pageUrl}` | no | `logins {logins: [{id, title, username, matched, hasPassword, hasTotp, favorite}]}` — the logins of that page only |
| `fill {itemId, pageUrl, frameUrl, crossOriginConfirmed?}` | no | `credentials {username, password, totp}` after the origin checks |
| `copy {itemId, pageUrl, field}` | no | `copied {clearsInSeconds}` (`field`: `username`, `password`, `totp`) |
| `generate` | no | `generated {password}` |
| `save_check {pageUrl, username?, password}` | no | `proposal {proposal: {action: "new", title, url} \| {action: "update_password", id, title} \| {action: "unchanged", id}}` |
| `save {pageUrl, username?, password, updateId?}` | no | `saved {itemId}` |

Events (id 0): `{"type": "event", "event": "locked" | "unlocked" | "revoked"}`;
after `revoked` the connection closes.

## Planned

WebSocket change notifications (`/v1/events`), e-mail verification at
registration, account deletion, sharing and temporary links.
