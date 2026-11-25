# `lk` — command-line client

**Status: not started — milestone M2 (next).** Nothing in this directory is functional yet.

Purpose: exercise the complete local stack end to end before any graphical
client exists (create account, unlock, add/list/show/edit items, generate
passwords, TOTP codes, change password, show recovery procedure), and serve
power users afterwards.

Stack: Rust binary linking `lk-core`, `lk-vault`, `lk-store`,
`lk-generator`, `lk-totp`. Secrets read from the terminal without echo; no
secret ever accepted as a command-line argument (visible in process lists and
shell history).
