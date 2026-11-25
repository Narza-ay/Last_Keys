# Self-hosting

**Status: not available yet** (server arrives in milestone M3).

Target (decision 6): a Docker Compose deployment that installs simply on a
NAS, a VPS or a personal server, using the same protocol as the official
cloud.

## Planned contents of this guide

* Requirements: Docker Engine with Compose v2; amd64 or arm64; minimum RAM and
  disk (to be measured); PostgreSQL (bundled in the Compose file).
* **A domain name and a valid TLS certificate** are required for passkey
  login (WebAuthn does not accept IP addresses) and strongly recommended in
  all cases. A reverse proxy with automatic certificates will be provided.
* Environment variables reference.
* Storage configuration (local volume or S3-compatible object storage).
* Backup and restore (database + object storage), verified by an automated
  round-trip test.
* Upgrades: migrations run automatically; downgrades are not supported.
* Health checks and monitoring endpoints.
* Option to disable the web application (see the threat model).
