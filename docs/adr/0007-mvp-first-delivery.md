# ADR-0007: MVP-first delivery order

* Status: **Proposed** — awaiting owner confirmation of the MVP scope (AUDIT decision 10)
* Date: 2026-11-25

## Context
The owner asked for step-by-step delivery starting from an MVP, with code
structured for the later steps. The spec's phases (§18) group work by theme
and forbid skipping validation.

## Decision
Deliver milestones M0–M6 as a vertical slice (CLI → server/sync → desktop →
extension → NordPass import) forming v0.1, then continue with mobile,
passkeys, sharing, security center, documents, web app, P2P and telemetry
(see `ROADMAP.md`). Each milestone meets the validation criteria of the
phases it touches. Extension points for later phases are built in from the
start (format versions, reserved envelope purposes and suites, platform
adapter interfaces, crate boundaries).

## Consequences
* A usable product earlier; real-world feedback on the core before mobile.
* Some phase-5 work (biometric unlock, hardware key stores) comes after the
  first desktop release; until then the desktop app reports software-only
  local protection.

## Alternatives considered
Strict phase order (all crypto, then all backend, then all vault features,
then all apps): later first usable build, no early validation by real use.
