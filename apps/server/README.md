# Last Keys server

**Status: not started — milestone M3.** Nothing in this directory is functional yet.

One codebase for the official cloud (EU) and self-hosted deployments (spec §11.3).

Planned:
* Rust, async HTTP (REST under `/v1`) and WebSocket notifications; framework and
  database driver chosen by ADR at M3 start (dependency review per ADR-0003).
* PostgreSQL (metadata and ciphertext), S3-compatible or local object storage
  for attachments.
* OPAQUE authentication (ADR-0005, proposed), device-bound sessions, device
  registry with account-signed certificates and revocations, change-log sync
  with conflict handling, rate limiting, audit log, health checks.
* Shares `lk-protocol` types with clients; validates envelope structure but
  never decrypts.
* Docker images (amd64, arm64) and a Compose stack (`infra/`).
