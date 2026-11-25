# Deployment

**Status: no deployable component yet.** This document describes the
continuous integration in place and the deployment process to come.

## Continuous integration (in place)

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | What it checks |
|-----|----------------|
| `lint` | `cargo fmt --check`, `cargo clippy -D warnings` (all targets) |
| `test` | `cargo test --workspace --locked` on Linux, Windows and macOS |
| `wasm` | `cargo check` of `lk-core` for `wasm32-unknown-unknown` |
| `deny` | `cargo deny check` (advisories, licenses, bans, sources) |
| `advisory-guard` | Proves the code behind the one ignored advisory (RUSTSEC-2026-0387) is not linked |
| `docs` | `cargo doc` with warnings denied |

`.github/workflows/fuzz.yml` runs every fuzz target nightly (and on demand).

## Planned

* M3: server container images (amd64, arm64), Docker Compose stack,
  migrations at startup, health checks, staging environment in the EU.
* M4–M5: desktop installers (signed MSI/MSIX, notarized DMG, AppImage/deb/rpm),
  extension packages for the Chrome Web Store, AMO and Brave.
* Phase 8: signed releases, SBOM, update mechanism with signature
  verification, reproducible builds as a goal.
