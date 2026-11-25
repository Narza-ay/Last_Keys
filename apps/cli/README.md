# `lk` — command-line client

**Status: implemented (milestones M2 and M3): local vault and
synchronization.** English-only developer and power-user tool; the
graphical applications provide the French/English interface.

`lk` exercises the complete stack end to end: key hierarchy (`lk-core`),
vault model (`lk-vault`), local encrypted store (`lk-store`), generator
(`lk-generator`), TOTP (`lk-totp`) and synchronization with a Last Keys
server (`lk-sync`).

## Build

```bash
cargo build --release -p lk-cli
./target/release/lk --help
```

## Usage

```bash
lk init                                   # create account + vault, shows the recovery key once
lk add login --title Bank --username alice --url bank.example.com --generate
lk add login --title GitHub --totp        # prompts for password and TOTP secret/otpauth URI
lk add note --title Wifi
lk add card --title Visa --expiry 12/2030 # prompts for number and security code
lk list [query]
lk show <id> [--reveal]
lk edit <id> --password | --generate | --restore-password N | --add-url URL | --title T
lk history <id> [--reveal]
lk totp <id>
lk delete <id>
lk generate [--length N --no-symbols ...] | --passphrase [--words N --separator S]
lk passwd                                 # change the master password
lk --recovery-key passwd                  # reset a forgotten master password with the recovery key
lk recovery rotate                        # replace the recovery key
lk info
```

Synchronization (server: [docs/SELF_HOSTING.md](../../docs/SELF_HOSTING.md)):

```bash
lk register --server https://sync.example --email you@example.com  # first device: asks for the recovery key too
lk login --server https://sync.example --email you@example.com     # any other device: creates its local vault
lk sync                                   # pull, push, merge (conflict copies, never overwrites)
lk sync --reset                           # only after the server was restored from a backup
lk devices                                # list devices, verified with the account key
lk revoke <device-id>                     # the device loses access at its next request
```

Plain `http://` is refused except to the local machine. Changing the master
password or rotating the recovery key also updates the server credential.

`<id>` is the item ID or a prefix of at least 4 characters (as shown by
`lk list`). The vault file defaults to `$LK_VAULT`, then
`~/.lastkeys/vault.lkvault`; override with `--vault`.

## Security rules

* Secrets are never accepted as arguments (process lists, shell history).
  They are read from hidden prompts, or one per line from standard input with
  `--password-stdin` (for scripts and tests).
* Secrets are masked in output unless `--reveal` is given; the recovery key
  is printed only by `init` and `recovery rotate`.
* Master passwords shorter than 12 characters are refused by this client.
* Local protection is software-only until platform key stores (M7): the
  vault is unlocked by the master password (Argon2id) every time.
