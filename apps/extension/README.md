# Browser extension (Chrome, Brave, Firefox)

**Status: not started — milestone M5.** Nothing in this directory is functional yet.

Planned: TypeScript, Manifest V3 (Firefox event-page differences handled by a
compatibility adapter), cryptography through `lk-wasm` (ADR-0006).

Security rules (spec §9): exact origin matching with the Public Suffix List,
IDN homograph checks, never fill cross-origin frames without confirmation,
host access requested as an optional permission with a click-to-fill fallback
(AUDIT P-9), lock on idle/locked state (AUDIT P-11). Passkey support arrives
in M9.
