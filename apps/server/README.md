# Last Keys server (`lk-server`)

**Status: implemented (milestone M3).** One codebase for the official cloud
(EU, not deployed yet) and self-hosted deployments (spec §11.3).

* Rust, axum, PostgreSQL 16 (sqlx), REST under `/v1` ([docs/API.md](../../docs/API.md)).
* OPAQUE authentication ([ADR-0005](../../docs/adr/0005-server-authentication-opaque.md)):
  the server never receives a password or a password-equivalent; session
  tokens are derived by both sides, stored as SHA-256.
* Device registry with account-signed certificates and revocations; every
  authenticated request re-checks revocation.
* Synchronization ([ADR-0008](../../docs/adr/0008-sync-protocol.md)): server
  revisions, per-account sequence numbers, idempotent change identifiers,
  conflicts instead of overwrites, tombstones, server history identifier for
  restores. The server validates envelope structure but never decrypts.
* Rate limits on authentication endpoints, body limits (256 KiB / 32 MiB).

## Commands

```bash
lk-server generate-secret <path>   # create the OPAQUE server secret (mode 0600, never overwrites)
lk-server migrate                  # apply database migrations and exit
lk-server serve                    # run the API (migrations applied at start-up)
lk-server healthcheck              # exit 0 if the local API answers /v1/health with 200
```

Configuration (environment): `LK_DATABASE_URL` or `LK_DATABASE_URL_FILE`,
`LK_SERVER_SECRET_FILE`, `LK_BIND` (default `0.0.0.0:8080`), and the
variables listed in [docs/SELF_HOSTING.md](../../docs/SELF_HOSTING.md).

## Running it

Use the Docker Compose stack in [`infra/`](../../infra), documented in
[docs/SELF_HOSTING.md](../../docs/SELF_HOSTING.md).

## Tests

```bash
export LK_TEST_DATABASE_URL=postgres://lastkeys:lastkeys-dev@127.0.0.1/postgres   # role with CREATEDB
cargo test -p lk-server
```

Each test creates and drops its own database.

## Not yet

WebSocket notifications, e-mail verification, account deletion, object
storage for attachments (M12), audit log, published multi-architecture images.
