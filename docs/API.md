# API (version 1)

**Status: implemented in `apps/server` (milestone M3, in progress).** Request
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
| `GET /v1/vaults/{vault_id}/changes?since=&limit=` | full | Pull states after a sequence number |

## Planned

WebSocket change notifications (`/v1/events`), e-mail verification at
registration, account deletion, sharing and temporary links.
