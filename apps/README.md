# Applications

One directory per application; each README states its current status.
The shared Rust core is in [`crates/`](../crates). Order of delivery:
[ROADMAP.md](../ROADMAP.md).

| Application | Status |
|-------------|--------|
| [`cli`](cli) — `lk` command-line client | ✅ implemented (M2, M3) |
| [`server`](server) — synchronization server | ✅ implemented (M3) |
| [`desktop`](desktop) — desktop application (Tauri 2) | ✅ implemented (M4, M5); Linux tested end to end, Windows/macOS built by CI |
| [`extension`](extension) — browser extension connected to the desktop | ✅ implemented (M5); Chromium on Linux tested end to end |
| [`android`](android), [`ios`](ios) — mobile applications | ⬜ not started (M8) |
| [`web`](web) — web application | ⬜ not started (M13) |
