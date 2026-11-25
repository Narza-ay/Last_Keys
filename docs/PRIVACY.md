# Privacy

Last Keys is designed so that the service operator cannot read user data.
This document lists exactly what is visible to whom. It is updated whenever a
data flow changes. (Status: design; no server or telemetry exists yet.)

## What the server can see (official cloud or self-hosted)

| Data | Visibility |
|------|-----------|
| Vault contents: titles, usernames, passwords, URLs, notes, cards, identities, documents, TOTP secrets, passkeys, tags, folders | **Encrypted** end to end; never readable by the server |
| Master password, recovery key, any decryption key | **Never sent** |
| Account e-mail address | Visible (needed for login and account e-mails) |
| Number of items, their sizes, creation/modification times | Visible |
| Device list (names, platforms, public keys, last sync) | Visible |
| IP addresses, request times | Visible to the server and its logs; retention limited (to be defined, see below) |

## Hosting

Official cloud: European Union, preferably France (decision 4). Third-party
processors (e-mail, push notifications, breach data) are listed here once
chosen; open questions in [AUDIT.md](AUDIT.md) A-2.

## Telemetry

Not implemented. Decision 14 sets it on by default, technical and anonymized,
switchable off at any time. The legal basis under EU rules (consent vs CNIL
exemption) must be confirmed before implementation (AUDIT A-1). Whatever the
decision, telemetry will **never** include passwords, vault contents, TOTP
secrets, keys, recovery keys, decrypted documents, form contents or URLs, and
its schema will be published here field by field.

## Breach monitoring

Planned with k-anonymity: only the first characters of a hash of a password
leave the device; the full password or hash never does (SEC-2).

## Retention and deletion

To be specified with the server (M3): account deletion removes all server
data, including backups after their rotation period; log retention bounded.
