# Contributing

Last Keys is proprietary; contributions come from the project team only.

## Workflow

1. Work on a branch; never push directly to `main`.
2. Keep changes focused: one milestone task per pull request.
3. Before opening a pull request, run the full verification
   ([docs/TESTING.md](docs/TESTING.md#how-to-run)); CI must be green.
4. Update documentation in the same pull request: `CHANGELOG.md`, the
   relevant docs, `docs/KNOWN_LIMITATIONS.md`, and `ROADMAP.md` when a
   milestone completes.
5. Significant technical decisions require an ADR (`docs/adr/`). Decisions
   that are hard to reverse (formats, protocols, key hierarchy) require owner
   approval before merge.

## Rules

* **No custom cryptographic primitives.** All cryptography lives in
  `lk-crypto` and uses reviewed crates (ADR-0003).
* No `unsafe` in workspace crates. No `unwrap`, `expect` or `panic!` in
  production code (enforced by Clippy).
* Secrets: zeroize on drop, never in `Debug`, logs, errors, telemetry or
  command-line arguments.
* Every persisted or transmitted structure has a format version; changing a
  format means a new version, never a silent change.
* Every security property has a negative test. Every parser of untrusted
  input has property tests and a fuzz target.
* Never skip, disable or weaken a test to make CI pass.
* Never claim a platform works without a test on that platform.
* New dependency: follow the review in ADR-0003 and record it in the PR.

## Definition of Done (spec §20)

Implemented; connected to the real engine; security properties tested; unit,
integration and platform tests pass; documentation and limitations updated;
the UI reflects the real state; no placeholder presented as production
functionality.

## Commit messages

Imperative mood, short summary line (≤ 72 characters), body explaining *why*.
