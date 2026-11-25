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

use std::collections::BTreeMap;

use lk_core::{EncryptedItem, ItemId, VaultKey, WrappedVaultKey};
use lk_protocol::{ItemState, PushChange, PushOutcome};
use lk_store::{LocalItem, PendingChange, RemoteState, Store};
use lk_vault::codec;
use lk_vault::item::limits;

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
    /// Conflicts encountered.
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
    for _ in 0..MAX_ROUNDS {
        let pending = latest_pending(store, vault)?;
        if pending.is_empty() {
            break;
        }
        push_round(api, session, store, vault, pending, now, &mut report)?;
    }
    pull_all(api, session, store, vault, now, &mut report)?;
    Ok(report)
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
    loop {
        let page = api.pull(session, &vault_id, since)?;
        if page.next_since < since || page.items.iter().any(|s| s.seq <= since) {
            return Err(SyncError::Integrity("pull cursor moved backwards"));
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

fn push_round<T: Transport>(
    api: &Api<T>,
    session: &Session,
    store: &mut Store,
    vault: &VaultKey,
    pending: BTreeMap<ItemId, PendingChange>,
    now: u64,
    report: &mut SyncReport,
) -> Result<()> {
    let vault_id = vault.vault_id();
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
            send_batch(
                api,
                session,
                store,
                vault,
                std::mem::take(&mut batch),
                now,
                report,
            )?;
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
        send_batch(api, session, store, vault, batch, now, report)?;
    }
    let _ = vault_id;
    Ok(())
}

fn send_batch<T: Transport>(
    api: &Api<T>,
    session: &Session,
    store: &mut Store,
    vault: &VaultKey,
    batch: Vec<(PushChange, LocalItem, u64)>,
    now: u64,
    report: &mut SyncReport,
) -> Result<()> {
    let changes: Vec<PushChange> = batch.iter().map(|(c, _, _)| c.clone()).collect();
    let response = api.push(session, &vault.vault_id(), changes)?;
    for ((change, local, seq), outcome) in batch.into_iter().zip(response.results) {
        match outcome {
            PushOutcome::Accepted { state } => {
                if state.item_id != change.item_id {
                    return Err(SyncError::Integrity("push outcome for another item"));
                }
                store.mark_pushed(&change.item_id, state.revision, seq)?;
                report.pushed = report.pushed.saturating_add(1);
            }
            PushOutcome::Conflict { current } => {
                if current.item_id != change.item_id {
                    return Err(SyncError::Integrity("push outcome for another item"));
                }
                report.conflicts = report.conflicts.saturating_add(1);
                resolve_conflict(store, vault, &local, &current, seq, now, report)?;
            }
        }
    }
    Ok(())
}

/// Merge rules of ADR-0008. No branch discards a version the user wrote.
fn resolve_conflict(
    store: &mut Store,
    vault: &VaultKey,
    local: &LocalItem,
    current: &ItemState,
    seq: u64,
    now: u64,
    report: &mut SyncReport,
) -> Result<()> {
    let vault_id = vault.vault_id();
    if current.revision == 0 && current.item.is_none() {
        // The server does not know the item (e.g. restored from an older
        // backup): forget the stale revision; the next round re-creates it.
        store.reset_server_revision(&local.item_id)?;
        return Ok(());
    }
    let server_state = remote(current);
    match (&local.item, &current.item) {
        (Some(mine), Some(theirs)) => {
            let mine_plain = vault.open_item(mine)?;
            let theirs_plain = vault.open_item(theirs)?;
            if !same_content(&mine_plain, &theirs_plain) {
                let copy = conflict_copy(vault, &mine_plain, now)?;
                store.upsert_item(&copy, now)?;
                report.conflict_copies.push(copy.item_id);
            }
            store.apply_remote(&vault_id, &server_state, Some(seq), now)?;
        }
        (Some(mine), None) => {
            // Deleted on the server, edited here: keep the edit as a new item.
            let mine_plain = vault.open_item(mine)?;
            let copy = conflict_copy(vault, &mine_plain, now)?;
            store.upsert_item(&copy, now)?;
            report.conflict_copies.push(copy.item_id);
            store.apply_remote(&vault_id, &server_state, Some(seq), now)?;
        }
        // Deleted here, edited (or deleted) on the server: the server state
        // wins; a deletion can be repeated, an edit could not be recovered.
        (None, _) => store.apply_remote(&vault_id, &server_state, Some(seq), now)?,
    }
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
