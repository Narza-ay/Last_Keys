# Deployment

**Status: the synchronization server is deployable by self-hosters (M3).**
There is no official cloud deployment and no client installer yet.

* Self-hosting with Docker Compose: [SELF_HOSTING.md](SELF_HOSTING.md).
* Server image: built from `infra/Dockerfile` (multi-stage, Rust 1.97.0 on
  Debian trixie, runtime `debian:trixie-slim`, unprivileged uid 10001,
  `lk-server healthcheck` as the container health check). Only `linux/amd64`
  is built and tested; no image is published to a registry yet.
* Database migrations are embedded in the binary, forward-only, and run at
  start-up (`lk-server serve`) or explicitly (`lk-server migrate`).

## Continuous integration (in place)

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | What it checks |
|-----|----------------|
| `lint` | `cargo fmt --check`, `cargo clippy -D warnings` (all targets, all features) |
| `test` | `cargo test --workspace` (dev and release profiles, server excluded) on Linux, Windows and macOS; `cargo check` of the server |
| `server-tests` | Server, synchronization and CLI end-to-end tests against a PostgreSQL 16 service |
| `compose-smoke` | Builds the server image and the `lk` binary, then runs `scripts/compose-smoke-test.sh`: the real Compose stack with TLS, registration, synchronization, backup, volume destruction, restore and enrollment of a new device |
| `wasm` | `cargo check` of the portable crates for `wasm32-unknown-unknown` |
| `deny` | `cargo deny check` (advisories, licenses, bans, sources) |
| `advisory-guard` | Proves the code behind the one ignored advisory (RUSTSEC-2026-0387) is not linked |
| `docs` | `cargo doc` with warnings denied |

`.github/workflows/fuzz.yml` runs every fuzz target nightly (and on demand).
Dependabot watches Cargo dependencies, GitHub Actions and the Docker base
images of `infra/`.

## Planned

* Official cloud: staging then production in the EU, behind the same image;
  operational runbook, monitoring and alerting (before any public beta).
* Multi-architecture images (`linux/arm64`) and signed images published to a
  registry with an SBOM.
* M4–M5: desktop installers (signed MSI/MSIX, notarized DMG, AppImage/deb/rpm),
  extension packages for the Chrome Web Store, AMO and Brave.
* Phase 8: signed releases, update mechanism with signature verification,
  reproducible builds as a goal.
