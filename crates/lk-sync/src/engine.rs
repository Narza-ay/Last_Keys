//! Synchronization engine (ADR-0008).
//!
//! One pass of [`sync_vault`]:
//! 1. upload the wrapped vault key (idempotent);
//! 2. pull every server state after the local cursor and apply it to items
//!    that have no unsynchronized local change;
//! 3. push the latest local state of every changed item (one change per
//!    item, idempotent change id, base revision = last known server
//!    revision), resolving conflicts with rules that never discard a version
//!    written by the user;
//! 4. pull again to settle the cursor.
//!
//! Any sign that the server went back in time (other history identifier,
//! cursor ahead of the server, older revision) stops the pass with
//! [`SyncError::ServerRollback`]; [`resync_vault`] is the explicit recovery.

use std::collections::{BTreeMap, HashMap};

use lk_core::{EncryptedItem, ItemId, VaultKey, WrappedVaultKey};
use lk_crypto::Zeroizing;
use lk_protocol::{ItemState, PushChange, PushOutcome};
use lk_store::{LocalItem, PendingChange, RemoteState, Store};
use lk_vault::codec;
use lk_vault::item::limits;
use sha2::{Digest, Sha256};

use crate::api::{Api, Session};
use crate::error::{Result, SyncError};
use crate::transport::Transport;

/// Maximum push rounds in one pass (conflict copies are pushed in the next
/// round).
const MAX_ROUNDS: usize = 4;
/// Maximum changes per push request.
const MAX_BATCH: usize = 100;
/// Maximum cumulative content bytes per push request.
const MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;
/// Suffix of the title of a conflict copy.
pub const CONFLICT_SUFFIX: &str = " (conflict copy)";

/// What a synchronization pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Remote states applied locally.
    pub pulled: usize,
    /// Local changes accepted by the server.
    pub pushed: usize,
    /// Real conflicts: a local change met a different server version (the
    /// same edit made on two devices is not counted).
    pub conflicts: usize,
    /// Conflict copies created (new items holding a local version).
    pub conflict_copies: Vec<ItemId>,
}

/// Synchronizes one vault.
///
/// # Errors
/// Transport, server, store or integrity errors. A pass interrupted by an
/// error can simply be retried: pushes are idempotent and nothing is lost.
pub fn sync_vault<T: Transport>(
    api: &Api<T>,
    session: &Session,
    store: &mut Store,
    vault: &VaultKey,
    wrapped: &WrappedVaultKey,
    now: u64,
) -> Result<SyncReport> {
    if wrapped.vault_id != vault.vault_id() {
        return Err(SyncError::Integrity("vault key mismatch"));
    }
    api.put_vault_key(session, wrapped)?;
    let mut report = SyncReport::default();
    pull_all(api, session, store, vault, now, &mut report)?;
    let mut index = ContentIndex::default();
    for _ in 0..MAX_ROUNDS {
        let pending = latest_pending(store, vault)?;
        if pending.is_empty() {
            break;
        }
        let mut ctx = Push {
            api,
            session,
            vault,
            now,
            index: &mut index,
            report: &mut report,
        };
        push_round(&mut ctx, store, pending)?;
    }
    pull_all(api, session, store, vault, now, &mut report)?;
    Ok(report)
}

/// Full resynchronization of one vault, for after [`SyncError::ServerRollback`]
/// when the user confirms that the server was restored from a backup.
///
/// Forgets the cursor, the server history and the known server revisions,
/// queues every local item, then runs [`sync_vault`]: items the server lost
/// are uploaded again, identical ones are adopted, and a local version that
/// differs from the server's is kept as a conflict copy. Nothing local is
/// deleted. Deletions made after the backup may reappear (they can be
/// repeated).
///
/// # Errors
/// As [`sync_vault`].
pub fn resync_vault<T: Transport>(
    api: &Api<T>,
    session: &Session,
    store: &mut Store,
    vault: &VaultKey,
    wrapped: &WrappedVaultKey,
    now: u64,
) -> Result<SyncReport> {
    if wrapped.vault_id != vault.vault_id() {
        return Err(SyncError::Integrity("vault key mismatch"));
    }
    store.reset_sync(&vault.vault_id(), now)?;
    sync_vault(api, session, store, vault, wrapped, now)
}

fn pull_all<T: Transport>(
    api: &Api<T>,
    session: &Session,
    store: &mut Store,
    vault: &VaultKey,
    now: u64,
    report: &mut SyncReport,
) -> Result<()> {
    let vault_id = vault.vault_id();
    let mut since = store.sync_cursor(&vault_id)?;
    let mut known_history = store.sync_history(&vault_id)?;
    loop {
        let page = api.pull(session, &vault_id, since)?;
        let history = page.history.to_string();
        match &known_history {
            Some(known) if *known != history => {
                return Err(SyncError::ServerRollback(
                    "the server history changed, a backup was probably restored",
                ));
            }
            _ => {}
        }
        if since > page.head {
            return Err(SyncError::ServerRollback(
                "the server has fewer changes than this device already received",
            ));
        }
        if page.next_since < since
            || page.next_since > page.head
            || page
                .items
                .iter()
                .any(|s| s.seq <= since || s.seq > page.head)
        {
            return Err(SyncError::Integrity("inconsistent pull cursor"));
        }
        if known_history.is_none() {
            store.set_sync_history(&vault_id, &history)?;
            known_history = Some(history);
        }
        let pending_items: Vec<ItemId> = latest_pending(store, vault)?.into_keys().collect();
        for state in &page.items {
            if let Some(item) = &state.item
                && (item.item_id != state.item_id || item.vault_id != vault_id)
            {
                return Err(SyncError::Integrity("pulled item does not match its vault"));
            }
            if pending_items.contains(&state.item_id) {
                // A local change is waiting: the push will detect the
                // conflict and merge without losing either version.
                continue;
            }
            let known = store
                .local_item(&state.item_id)?
                .map_or(0, |l| l.server_revision);
            if state.revision < known {
                return Err(SyncError::ServerRollback(
                    "the server returned an older revision of an item",
                ));
            }
            store.apply_remote(&vault_id, &remote(state), None, now)?;
            if state.revision > known {
                report.pulled = report.pulled.saturating_add(1);
            }
        }
        store.set_sync_cursor(&vault_id, page.next_since)?;
        since = page.next_since;
        if !page.more {
            return Ok(());
        }
    }
}

fn remote(state: &ItemState) -> RemoteState {
    RemoteState {
        item_id: state.item_id,
        revision: state.revision,
        item: state.item.clone(),
    }
}

/// Latest queued change per item of this vault (older entries are folded:
/// only the current local state is pushed).
fn latest_pending(store: &Store, vault: &VaultKey) -> Result<BTreeMap<ItemId, PendingChange>> {
    let mut latest: BTreeMap<ItemId, PendingChange> = BTreeMap::new();
    for change in store.pending_changes()? {
        if change.vault_id != vault.vault_id() {
            continue;
        }
        match latest.get(&change.item_id) {
            Some(existing) if existing.seq >= change.seq => {}
            _ => {
                latest.insert(change.item_id, change);
            }
        }
    }
    Ok(latest)
}

fn content_len(item: Option<&EncryptedItem>) -> usize {
    item.map_or(0, |i| {
        i.content
            .as_slice()
            .len()
            .saturating_add(i.wrapped_item_key.as_slice().len())
    })
}

/// Digest of the contents of an item plaintext, ignoring the modification
/// time (the equality of [`same_content`]).
fn content_digest(plaintext: &[u8]) -> [u8; 32] {
    // Serialized directly: `codec::encode` would validate the item, and a
    // zero modification time is not a valid item.
    let normalized = codec::decode(plaintext).ok().and_then(|mut data| {
        data.updated_at = 0;
        serde_json::to_vec(&data).ok().map(Zeroizing::new)
    });
    let digest = match &normalized {
        Some(bytes) => Sha256::new()
            .chain_update(b"lk-sync item v1\0")
            .chain_update(bytes.as_slice())
            .finalize(),
        None => Sha256::new()
            .chain_update(b"lk-sync raw\0")
            .chain_update(plaintext)
            .finalize(),
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// Number of live items per content digest, built on the first conflict of a
/// pass and kept up to date, so that a conflict copy identical to an existing
/// item (for instance one that another device already created while
/// resynchronizing after a restore) is not created a second time.
#[derive(Default)]
struct ContentIndex(Option<HashMap<[u8; 32], usize>>);

impl ContentIndex {
    fn counts(&mut self, store: &Store, vault: &VaultKey) -> Result<&mut HashMap<[u8; 32], usize>> {
        if self.0.is_none() {
            let mut counts = HashMap::new();
            for stored in store.items(&vault.vault_id())? {
                let plaintext = vault.open_item(&stored.item)?;
                let n: &mut usize = counts.entry(content_digest(&plaintext)).or_default();
                *n = n.saturating_add(1);
            }
            self.0 = Some(counts);
        }
        Ok(self.0.get_or_insert_with(HashMap::new))
    }

    fn is_built(&self) -> bool {
        self.0.is_some()
    }

    fn contains(&mut self, store: &Store, vault: &VaultKey, digest: &[u8; 32]) -> Result<bool> {
        Ok(self
            .counts(store, vault)?
            .get(digest)
            .is_some_and(|n| *n > 0))
    }

    /// Records that a live item's content changed from `old` to `new`
    /// (`None`: no item before, or none after).
    fn replace(
        &mut self,
        store: &Store,
        vault: &VaultKey,
        old: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> Result<()> {
        let counts = self.counts(store, vault)?;
        if let Some(old) = old
            && let Some(n) = counts.get_mut(&content_digest(old))
        {
            *n = n.saturating_sub(1);
        }
        if let Some(new) = new {
            let n: &mut usize = counts.entry(content_digest(new)).or_default();
            *n = n.saturating_add(1);
        }
        Ok(())
    }
}

/// What a push round needs besides the store.
struct Push<'a, T> {
    api: &'a Api<T>,
    session: &'a Session,
    vault: &'a VaultKey,
    now: u64,
    index: &'a mut ContentIndex,
    report: &'a mut SyncReport,
}

fn push_round<T: Transport>(
    ctx: &mut Push<'_, T>,
    store: &mut Store,
    pending: BTreeMap<ItemId, PendingChange>,
) -> Result<()> {
    let mut batch: Vec<(PushChange, LocalItem, u64)> = Vec::new();
    let mut batch_bytes = 0usize;
    for (item_id, change) in pending {
        let local = store
            .local_item(&item_id)?
            .ok_or(SyncError::Integrity("queued change for a missing item"))?;
        if local.item.is_none() && local.server_revision == 0 {
            // Created and deleted before ever reaching the server.
            store.mark_pushed(&item_id, 0, change.seq)?;
            continue;
        }
        let size = content_len(local.item.as_ref());
        if !batch.is_empty()
            && (batch.len() >= MAX_BATCH || batch_bytes.saturating_add(size) > MAX_BATCH_BYTES)
        {
            send_batch(ctx, store, std::mem::take(&mut batch))?;
            batch_bytes = 0;
        }
        batch_bytes = batch_bytes.saturating_add(size);
        batch.push((
            PushChange {
                change_id: change.change_id,
                item_id,
                base_revision: local.server_revision,
                item: local.item.clone(),
            },
            local,
            change.seq,
        ));
    }
    if !batch.is_empty() {
        send_batch(ctx, store, batch)?;
    }
    Ok(())
}

fn send_batch<T: Transport>(
    ctx: &mut Push<'_, T>,
    store: &mut Store,
    batch: Vec<(PushChange, LocalItem, u64)>,
) -> Result<()> {
    let changes: Vec<PushChange> = batch.iter().map(|(c, _, _)| c.clone()).collect();
    let response = ctx.api.push(ctx.session, &ctx.vault.vault_id(), changes)?;
    for ((change, local, seq), outcome) in batch.into_iter().zip(response.results) {
        match outcome {
            PushOutcome::Accepted { state } => {
                if state.item_id != change.item_id {
                    return Err(SyncError::Integrity("push outcome for another item"));
                }
                store.mark_pushed(&change.item_id, state.revision, seq)?;
                ctx.report.pushed = ctx.report.pushed.saturating_add(1);
            }
            PushOutcome::Conflict { current } => {
                if current.item_id != change.item_id {
                    return Err(SyncError::Integrity("push outcome for another item"));
                }
                resolve_conflict(ctx, store, &local, &current, seq)?;
            }
        }
    }
    Ok(())
}

/// Merge rules of ADR-0008. No branch discards a version the user wrote.
fn resolve_conflict<T: Transport>(
    ctx: &mut Push<'_, T>,
    store: &mut Store,
    local: &LocalItem,
    current: &ItemState,
    seq: u64,
) -> Result<()> {
    let vault = ctx.vault;
    let vault_id = vault.vault_id();
    if current.revision < local.server_revision {
        // Includes an item the server no longer knows (revision 0).
        return Err(SyncError::ServerRollback(
            "the server holds an older revision of an item",
        ));
    }
    let server_state = remote(current);
    match (&local.item, &current.item) {
        (Some(mine), theirs) => {
            let mine_plain = vault.open_item(mine)?;
            let theirs_plain = theirs.as_ref().map(|t| vault.open_item(t)).transpose()?;
            let identical = theirs_plain
                .as_ref()
                .is_some_and(|t| same_content(&mine_plain, t));
            // The original item takes the server state (an edit, or a
            // deletion: then the local edit is re-created as a new item).
            ctx.index.replace(
                store,
                vault,
                Some(&mine_plain),
                theirs_plain.as_ref().map(|t| t.as_slice()),
            )?;
            if !identical {
                ctx.report.conflicts = ctx.report.conflicts.saturating_add(1);
                keep_as_copy(ctx, store, &mine_plain)?;
            }
            store.apply_remote(&vault_id, &server_state, Some(seq), ctx.now)?;
        }
        // Deleted here, edited (or deleted) on the server: the server state
        // wins; a deletion can be repeated, an edit could not be recovered.
        (None, theirs) => {
            if theirs.is_some() {
                // The local deletion gives way to the server's version.
                ctx.report.conflicts = ctx.report.conflicts.saturating_add(1);
            }
            if ctx.index.is_built()
                && let Some(t) = theirs
            {
                let theirs_plain = vault.open_item(t)?;
                ctx.index.replace(store, vault, None, Some(&theirs_plain))?;
            }
            store.apply_remote(&vault_id, &server_state, Some(seq), ctx.now)?;
        }
    }
    Ok(())
}

/// Saves `plaintext` as a conflict copy, unless a live item with the same
/// contents already exists (nothing would be lost by skipping it).
fn keep_as_copy<T: Transport>(
    ctx: &mut Push<'_, T>,
    store: &mut Store,
    plaintext: &[u8],
) -> Result<()> {
    let copy = conflict_copy(ctx.vault, plaintext, ctx.now)?;
    let copy_plain = ctx.vault.open_item(&copy)?;
    if ctx
        .index
        .contains(store, ctx.vault, &content_digest(&copy_plain))?
    {
        return Ok(());
    }
    store.upsert_item(&copy, ctx.now)?;
    ctx.index
        .replace(store, ctx.vault, None, Some(&copy_plain))?;
    ctx.report.conflict_copies.push(copy.item_id);
    Ok(())
}

/// Equality of two item plaintexts, ignoring the modification time (the
/// same edit made on two devices is not a conflict).
fn same_content(a: &[u8], b: &[u8]) -> bool {
    match (codec::decode(a), codec::decode(b)) {
        (Ok(mut x), Ok(mut y)) => {
            x.updated_at = 0;
            y.updated_at = 0;
            x == y
        }
        _ => a == b,
    }
}

/// A new item holding `plaintext`. Items this client understands get a
/// marked title; others (newer schema) are copied byte for byte so that no
/// data is lost even when it cannot be interpreted.
fn conflict_copy(vault: &VaultKey, plaintext: &[u8], now: u64) -> Result<EncryptedItem> {
    match codec::decode(plaintext) {
        Ok(mut data) => {
            let mut title = data.title.clone();
            let room = limits::TITLE.saturating_sub(CONFLICT_SUFFIX.len());
            while title.len() > room {
                title.pop();
            }
            title.push_str(CONFLICT_SUFFIX);
            data.title = title;
            data.updated_at = data.updated_at.max(now);
            Ok(codec::seal_new(vault, &data)?)
        }
        Err(_) => Ok(vault.create_item(plaintext)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lk_vault::{ItemContent, ItemData, SecureNote};

    fn note(title: &str, body: &str, t: u64) -> Vec<u8> {
        let mut item = ItemData::new(title, ItemContent::SecureNote(SecureNote {}), t).unwrap();
        item.notes = Some(body.into());
        codec::encode(&item).unwrap().to_vec()
    }

    #[test]
    fn same_content_ignores_modification_time_only() {
        assert!(same_content(&note("a", "x", 10), &note("a", "x", 10)));
        let mut later = codec::decode(&note("a", "x", 10)).unwrap();
        later.updated_at = 99;
        assert!(same_content(
            &note("a", "x", 10),
            &codec::encode(&later).unwrap()
        ));
        assert!(!same_content(&note("a", "x", 10), &note("a", "y", 10)));
        assert!(!same_content(b"raw-1", b"raw-2"));
        assert!(same_content(b"raw", b"raw"));
    }

    #[test]
    fn content_digest_matches_same_content() {
        let mut later = codec::decode(&note("a", "x", 10)).unwrap();
        later.updated_at = 99;
        let later = codec::encode(&later).unwrap();
        assert_eq!(
            content_digest(&note("a", "x", 10)),
            content_digest(&later),
            "the modification time is ignored"
        );
        assert_ne!(
            content_digest(&note("a", "x", 10)),
            content_digest(&note("a", "y", 10))
        );
        assert_ne!(
            content_digest(&note("a", "x", 10)),
            content_digest(&note("b", "x", 10))
        );
        // Items this client cannot decode are compared byte for byte.
        assert_eq!(content_digest(b"raw"), content_digest(b"raw"));
        assert_ne!(content_digest(b"raw-1"), content_digest(b"raw-2"));
    }

    #[test]
    fn conflict_copies_are_marked_and_bounded() {
        let account = lk_core::create_account(
            &lk_crypto::MasterPassword::new("pw").unwrap(),
            lk_crypto::KdfParams::recommended(),
        )
        .unwrap();
        let (vault, _) = account.keys.create_vault().unwrap();
        let copy = conflict_copy(&vault, &note("Bank", "secret", 5), 7).unwrap();
        let data = codec::open(&vault, &copy).unwrap();
        assert_eq!(data.title, "Bank (conflict copy)");
        assert_eq!(data.updated_at, 7);
        let long = note(&"x".repeat(limits::TITLE), "s", 5);
        let data = codec::open(&vault, &conflict_copy(&vault, &long, 7).unwrap()).unwrap();
        assert!(data.title.len() <= limits::TITLE && data.title.ends_with(CONFLICT_SUFFIX));
        // Unknown plaintext is preserved byte for byte.
        let raw = conflict_copy(&vault, b"{\"schema\":9}", 7).unwrap();
        assert_eq!(vault.open_item(&raw).unwrap().as_slice(), b"{\"schema\":9}");
    }
}
