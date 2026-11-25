# ADR-0009: Server technology stack

* Status: Accepted
* Date: 2026-11-25

## Context
The server (official EU cloud and self-hosted, same code, spec §11.3) must
be written in Rust (spec §4), expose REST and WebSocket APIs, use PostgreSQL,
treat every client as untrusted, and be simple to run with Docker Compose on
a VPS or a NAS (amd64 and arm64).

## Decision
Dependencies reviewed on 2026-11-25 per ADR-0003 (maintenance, licence,
security history):

| Concern | Choice | Notes |
|---------|--------|-------|
| Async runtime | `tokio` 1.54 | Industry standard |
| HTTP framework | `axum` 0.8.9 (+ `tower` 0.5, `tower-http` 0.7) | Maintained by the Tokio project; request size limits, timeouts and tracing through tower layers |
| Database | PostgreSQL 16+ via `sqlx` 0.9 (runtime queries, embedded forward-only migrations) | No compile-time database requirement; parameters always bound (no string-built SQL) |
| Authentication | `lk-auth` (OPAQUE, ADR-0005) | Session tokens stored as SHA-256 hashes |
| Logging | `tracing` / `tracing-subscriber` | Never logs request bodies, tokens, e-mails or envelopes |
| TLS | Terminated by the reverse proxy (Caddy in the Compose stack, automatic certificates) | The server listens on the internal network only |

Server rules:
* Every request body has a size limit; every list endpoint is paginated.
* Authorization is checked on every endpoint from the session (account and
  device), never from identifiers supplied by the client alone.
* Rate limits per IP and per account on pre-login, login, registration and
  recovery endpoints.
* Errors use stable machine-readable codes and never echo secrets.
* The OPAQUE server secret lives in a file outside the database (ADR-0005).

## Consequences
* One binary, one database; the same image serves the cloud and self-hosted
  deployments.
* Integration tests run against a real PostgreSQL (local and CI service
  container), never a mock.

## Alternatives considered
* `actix-web`: comparable, but `axum` integrates directly with the `tower`
  middleware ecosystem used for limits and tracing.
* `tokio-postgres` without a migration framework: lighter, but migrations
  would be hand-rolled.
* SQLite for small self-hosted installs: rejected to keep one schema for
  cloud and self-hosting (AUDIT D-3).
