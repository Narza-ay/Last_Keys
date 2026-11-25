# API

**Status: not implemented.** The server API is designed and built in
milestone M3. This document fixes the principles the API must follow; the
endpoint reference will be generated from the implementation.

## Principles

* Base path `/v1`; breaking changes only in a new version.
* JSON over HTTPS for REST; WebSocket for change notifications.
* Binary values (envelopes, public keys, signatures) as unpadded Base64url
  strings (`lk_core::Bytes`).
* All request bodies are validated (types, sizes, format versions);
  envelopes are structurally validated by the server (header, purpose, size)
  although it cannot decrypt them.
* Authentication: OPAQUE registration and login (ADR-0005, proposed), then
  short-lived sessions bound to the device signing key.
* Authorization checked server-side on every endpoint; clients are untrusted.
* Rate limits on authentication, enrollment, recovery and upload endpoints.
* Errors: stable machine-readable codes; never echo secrets.

## Planned resources

Accounts (prelogin KDF config, OPAQUE register/login, account bundle),
devices (register, certificate upload, revocation), vaults and items (change
batches, tombstones), recovery, sharing (later), temporary links (later),
health.
