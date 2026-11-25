# Self-hosting

**Status: available (milestone M3).** The stack below is exercised end to end
by `scripts/compose-smoke-test.sh` (locally and in CI): setup, TLS through
Caddy, registration and synchronization with the real `lk` client, backup,
destruction of every volume, restore of an older backup, refusal to
synchronize until `lk sync --reset`, the resynchronization itself, and
enrollment of a new device that receives every item.

The self-hosted server is the same code and protocol as the official cloud
(decision 6, spec §11.3). It never holds a key able to decrypt vaults.

## What runs

| Service | Image | Role |
|---------|-------|------|
| `proxy` | `caddy:2.11.9-alpine` | HTTPS with automatic certificates, the only published service (ports 80/443) |
| `server` | `lastkeys/server` (built from `infra/Dockerfile`) | API; unprivileged user (uid 10001), read-only filesystem, no capabilities |
| `db` | `postgres:16-trixie` | Ciphertext and metadata; on an internal network, not published |

## Requirements

* Docker Engine with Compose v2, on amd64 (arm64 images: not yet verified).
* About 1 GB of RAM and 2 GB of disk to start (measured needs will be
  documented with the first release).
* **A domain name pointing to the machine, with ports 80 and 443 reachable**,
  so that Caddy can obtain a publicly trusted certificate. Passkey login
  (later milestone) requires a domain name: WebAuthn does not accept IP
  addresses. The `lk` client refuses plain HTTP except to the local machine,
  so a LAN-only setup also needs TLS (for example `LK_DOMAIN=nas.home.arpa`
  with a certificate your devices trust).

## Install

```bash
git clone <repository> lastkeys && cd lastkeys/infra
./setup.sh            # creates .env, secrets/ (private), builds the image, generates the server secret
nano .env             # set LK_DOMAIN (and ports if 80/443 are taken)
docker compose up -d
docker compose ps     # every service should become "healthy"
curl https://<your-domain>/v1/health
```

Then, from a client:

```bash
lk init
lk register --server https://<your-domain> --email you@example.com
```

and on every other device:

```bash
lk login --server https://<your-domain> --email you@example.com
```

Once your accounts exist, set `LK_ALLOW_REGISTRATION=false` in `.env` and run
`docker compose up -d` again to close registration.

## Secrets

`setup.sh` creates `infra/secrets/` (mode 0700) with:

| File | Content | If lost |
|------|---------|---------|
| `server_secret` | OPAQUE server secret (ADR-0005) | **Nobody can log in any more.** Vault data stays intact but every user must re-register. Back it up separately from the database. |
| `db_password`, `database_url` | PostgreSQL password and connection URL | Recreate them and reset the database password |

The files are world-readable *inside* the directory so that the containers
(running as other users) can read them; the 0700 directory keeps them private
on the host. Never commit them (they are git-ignored).

## Configuration (`infra/.env` and server environment)

| Variable | Default | Meaning |
|----------|---------|---------|
| `LK_DOMAIN` | — (required) | Public domain name served by Caddy |
| `LK_ALLOW_REGISTRATION` | `true` | Accept new accounts |
| `LK_HTTP_PORT` / `LK_HTTPS_PORT` | `80` / `443` | Published ports |
| `LK_SERVER_IMAGE` | `lastkeys/server:local` | Server image |
| `LK_SESSION_TTL_SECS` | `43200` | Session lifetime |
| `LK_LOGIN_ATTEMPT_TTL_SECS` | `120` | Lifetime of a pending login |
| `LK_AUTH_RATE_LIMIT_PER_MINUTE` | `30` | Per-IP and per-e-mail limit on authentication endpoints |
| `LK_LOG` / `LK_LOG_FORMAT` | `info` / `json` (in Compose) | Log filter and format |

The server reads `LK_DATABASE_URL_FILE` and `LK_SERVER_SECRET_FILE` (Docker
secrets) and trusts `X-Forwarded-For` only because Caddy is its sole client.

## Backup and restore

```bash
./backup.sh                                # writes backups/lastkeys-<UTC time>.dump (mode 0600)
./restore.sh backups/lastkeys-<time>.dump  # stops the server, restores, starts a new history, restarts
```

* A dump contains only ciphertext and metadata (e-mails, device list, item
  identifiers and sizes); it still deserves protection.
* Restore with the **same `server_secret`** that was in use when the dump was
  made.
* Always restore with `restore.sh`: besides `pg_restore`, it applies pending
  migrations and replaces the server history identifier.
* **After a restore, every device must run a full resynchronization.** The
  restored data is older than what devices already synchronized; they detect
  it and refuse to synchronize (a server going back in time is also what an
  attack would look like) until their user runs:

  ```bash
  lk sync --reset
  ```

  Every item of the device is uploaded again: items the backup does not
  contain are re-created, identical items are adopted, and a version that
  differs from the backup's is kept as a "(conflict copy)" item — nothing is
  deleted. Expect conflict copies for items edited after the backup (the
  original item shows the backup's version) and deletions made after the
  backup to reappear. Devices enrolled after the restore need nothing.
* Test your restore procedure; the smoke test restores an older backup and
  runs the resynchronization on every CI run.

## Upgrades

```bash
git pull
docker compose build server
docker compose up -d
```

Database migrations are forward-only and run automatically at start-up.
Downgrades are not supported: back up before upgrading.

## Health and monitoring

* `GET /v1/health` returns 200 when the server and its database are reachable.
* The `server` container's health check runs `lk-server healthcheck`.
* Logs: `docker compose logs -f server` (JSON lines; never contain secrets,
  request bodies or e-mails).

## Known limitations

No e-mail verification yet, no WebSocket notifications (clients synchronize
on demand), arm64 images not yet verified. See
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).
