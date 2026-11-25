# ADR-0008: Synchronization protocol v1

* Status: Accepted
* Date: 2026-11-25

## Context
Requirements (spec §11.5, decision 9): offline editing on any number of
devices, automatic sync on reconnection, unique change identifiers,
idempotent sync, conflict detection, safe merge, tombstones, recovery of
conflicting versions, and **never** silently overwriting a concurrent change.
The server cannot read items (ADR-0002), so it cannot merge contents: it can
only order, compare revisions and store ciphertext.

## Decision

### Data model (server)
For each vault, the server keeps the **current state** of every item:
`(item_id, revision, deleted, encrypted_item?, seq, updated_by_device)`.
* `revision` is assigned by the server: 1 at creation, +1 for every accepted
  change of that item.
* `seq` is a per-account monotonic sequence number assigned to every accepted
  change; it is the pull cursor.
* Deletions keep a tombstone (`deleted = true`, no ciphertext).
* Every accepted change records its client-generated `change_id`
  (`lk_core::ChangeId`), which makes replays idempotent.

### Push
`POST /v1/vaults/{vault}/changes` with a batch of changes, each carrying
`change_id`, `item_id`, `base_revision` (the server revision the client last
saw; 0 for a new item), and either the new `encrypted_item` or a deletion.
For each change, in one transaction:
1. `change_id` already applied → return the recorded outcome (idempotent).
2. `base_revision` equals the current server revision → **accepted**:
   revision + 1, new `seq`, store.
3. Otherwise → **conflict**: nothing is written; the response carries the
   current server state of the item.
The server validates the envelope structure (sizes, versions, purposes,
item/vault identifiers matching the URL and the body) but never decrypts.

### Pull
`GET /v1/vaults/{vault}/changes?since={seq}` returns the current state of
every item whose `seq` is greater than `since` (tombstones included), in
`seq` order, paginated, with the new cursor.

### Client merge rules (never lose data)
The client applies pulls, then pushes its queue (`lk-store` pending changes).
On conflict it decrypts both versions:
* identical contents → adopt the server revision, drop the local change;
* local edit vs remote edit → keep the server version under the original
  item, and save the local version as a **new item** ("… (conflict copy)"),
  with a fresh identifier and item key;
* local delete vs remote edit → keep the remote edit (the user can delete
  again);
* local edit vs remote delete → re-create the local version as a new item.
No branch discards a version the user wrote.

### Rollback and freeze
* The client remembers the highest `revision` it has seen per item and the
  last `seq`; a server answer going backwards is rejected as an integrity
  error.
* A malicious server can still withhold updates (freeze) or serve an older
  ciphertext under a new revision number. Detection of the latter requires
  binding revisions inside the encrypted content (planned with item schema
  2); device-to-device comparison (P2P, M14) narrows the freeze window. Both
  are recorded in the threat model.

### Real time
A WebSocket (`/v1/events`) only notifies "changes available" (no content);
clients then pull. Polling is the fallback. (Delivered after the HTTP
endpoints.)

## Consequences
* The server stays content-blind; all merging happens on clients, where the
  plaintext is.
* Conflict copies are visible to the user, who resolves them by deleting the
  version they do not want (UI in M4).
* Per-account `seq` makes pulls cheap and resumable; idempotency makes retries
  after network failures safe.

## Alternatives considered
* CRDTs per field: automatic merges, but either the server must see field
  structure (privacy loss) or every client must implement a complex CRDT over
  encrypted blobs; deferred.
* Last-writer-wins: simple but violates "never silently overwrite".
