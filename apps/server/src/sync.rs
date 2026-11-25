//! Vault keys and change-log synchronization (ADR-0008).
//!
//! The server validates the structure of every encrypted item (identifiers,
//! versions, envelope headers and purposes, sizes) but never decrypts it.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use lk_core::{EncryptedItem, ItemId, WrappedVaultKey};
use lk_crypto::{Envelope, Purpose};
use lk_protocol::{ItemState, PullResponse, PushOutcome, PushRequest, PushResponse, VaultKeyList};
use serde::Deserialize;
use sqlx::types::Json as DbJson;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::session::Session;
use crate::{AppState, now};

/// Maximum number of changes in one push.
pub(crate) const MAX_PUSH_CHANGES: usize = 500;
/// Maximum number of states returned by one pull.
pub(crate) const MAX_PULL_LIMIT: i64 = 500;
/// Maximum size of one item's content envelope (1 MiB plaintext + overhead).
const MAX_CONTENT_BYTES: usize = 1024 * 1024 + 1024;

/// `GET /v1/vaults`.
pub(crate) async fn list_vault_keys(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<VaultKeyList>> {
    session.require_full()?;
    let rows =
        sqlx::query("SELECT wrapped FROM vault_keys WHERE account_id = $1 ORDER BY vault_id")
            .bind(session.account_id.as_uuid())
            .fetch_all(state.db())
            .await?;
    let mut vaults = Vec::with_capacity(rows.len());
    for row in rows {
        let DbJson(w): DbJson<WrappedVaultKey> = row.try_get("wrapped")?;
        vaults.push(w);
    }
    Ok(Json(VaultKeyList { vaults }))
}

/// `PUT /v1/vaults/{vault_id}/key`.
pub(crate) async fn put_vault_key(
    State(state): State<AppState>,
    session: Session,
    Path(vault_id): Path<Uuid>,
    Json(wrapped): Json<WrappedVaultKey>,
) -> ApiResult<StatusCode> {
    session.require_full()?;
    if wrapped.account_id != session.account_id || *wrapped.vault_id.as_uuid() != vault_id {
        return Err(ApiError::bad_request(
            "wrapped key does not match the account or vault",
        ));
    }
    if wrapped.format_version != lk_core::vault::VAULT_FORMAT_VERSION {
        return Err(ApiError::bad_request("unsupported vault key version"));
    }
    let envelope = Envelope::from_bytes(wrapped.wrapped_key.as_slice())
        .map_err(|_| ApiError::bad_request("malformed vault key envelope"))?;
    if envelope.purpose() != Purpose::VaultKey {
        return Err(ApiError::bad_request("envelope is not a vault key"));
    }
    sqlx::query(
        "INSERT INTO vault_keys (account_id, vault_id, wrapped) VALUES ($1, $2, $3)
         ON CONFLICT (account_id, vault_id) DO UPDATE SET wrapped = excluded.wrapped",
    )
    .bind(session.account_id.as_uuid())
    .bind(vault_id)
    .bind(DbJson(&wrapped))
    .execute(state.db())
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_item(item: &EncryptedItem, vault_id: &Uuid, item_id: &ItemId) -> ApiResult<()> {
    if item.vault_id.as_uuid() != vault_id || item.item_id != *item_id {
        return Err(ApiError::bad_request(
            "item does not match the vault or change",
        ));
    }
    if item.format_version != lk_core::vault::VAULT_FORMAT_VERSION {
        return Err(ApiError::bad_request("unsupported item version"));
    }
    if item.content.as_slice().len() > MAX_CONTENT_BYTES {
        return Err(ApiError::bad_request("item too large"));
    }
    let key = Envelope::from_bytes(item.wrapped_item_key.as_slice())
        .map_err(|_| ApiError::bad_request("malformed item key envelope"))?;
    let content = Envelope::from_bytes(item.content.as_slice())
        .map_err(|_| ApiError::bad_request("malformed item content envelope"))?;
    if key.purpose() != Purpose::ItemKey || content.purpose() != Purpose::ItemContent {
        return Err(ApiError::bad_request("unexpected envelope purpose"));
    }
    Ok(())
}

fn to_u64(v: i64) -> ApiResult<u64> {
    u64::try_from(v).map_err(|_| ApiError::internal())
}

fn to_i64(v: u64) -> ApiResult<i64> {
    i64::try_from(v).map_err(|_| ApiError::bad_request("value out of range"))
}

struct CurrentItem {
    vault_id: Uuid,
    revision: i64,
    seq: i64,
    item: Option<EncryptedItem>,
}

async fn current_item(
    tx: &mut Transaction<'_, Postgres>,
    account: &Uuid,
    item_id: &Uuid,
) -> ApiResult<Option<CurrentItem>> {
    let row = sqlx::query(
        "SELECT vault_id, revision, seq, encrypted FROM items
         WHERE account_id = $1 AND item_id = $2 FOR UPDATE",
    )
    .bind(account)
    .bind(item_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        let encrypted: Option<DbJson<EncryptedItem>> = row.try_get("encrypted")?;
        Ok(CurrentItem {
            vault_id: row.try_get("vault_id")?,
            revision: row.try_get("revision")?,
            seq: row.try_get("seq")?,
            item: encrypted.map(|DbJson(i)| i),
        })
    })
    .transpose()
}

/// `POST /v1/vaults/{vault_id}/changes`.
pub(crate) async fn push(
    State(state): State<AppState>,
    session: Session,
    Path(vault_id): Path<Uuid>,
    Json(req): Json<PushRequest>,
) -> ApiResult<Json<PushResponse>> {
    session.require_full()?;
    if req.changes.len() > MAX_PUSH_CHANGES {
        return Err(ApiError::bad_request("too many changes in one push"));
    }
    let account = *session.account_id.as_uuid();
    for change in &req.changes {
        if let Some(item) = &change.item {
            validate_item(item, &vault_id, &change.item_id)?;
        }
    }

    let mut tx = state.db().begin().await?;
    // Serializes pushes of one account and checks the vault exists.
    let vault_known: Option<Uuid> = sqlx::query_scalar(
        "SELECT vault_id FROM vault_keys WHERE account_id = $1 AND vault_id = $2",
    )
    .bind(account)
    .bind(vault_id)
    .fetch_optional(&mut *tx)
    .await?;
    if vault_known.is_none() {
        return Err(ApiError::not_found("unknown vault"));
    }
    sqlx::query("SELECT last_seq FROM account_seq WHERE account_id = $1 FOR UPDATE")
        .bind(account)
        .fetch_one(&mut *tx)
        .await?;

    let mut results = Vec::with_capacity(req.changes.len());
    for change in req.changes {
        let item_uuid = *change.item_id.as_uuid();
        // 1. Replay of an already applied change: same outcome.
        let applied = sqlx::query(
            "SELECT item_id, outcome FROM applied_changes WHERE account_id = $1 AND change_id = $2",
        )
        .bind(account)
        .bind(change.change_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = applied {
            let recorded_item: Uuid = row.try_get("item_id")?;
            if recorded_item != item_uuid {
                return Err(ApiError::bad_request(
                    "change identifier reused for another item",
                ));
            }
            let DbJson(outcome): DbJson<PushOutcome> = row.try_get("outcome")?;
            results.push(outcome);
            continue;
        }
        // 2. Compare with the current revision.
        let current = current_item(&mut tx, &account, &item_uuid).await?;
        if let Some(c) = &current
            && c.vault_id != vault_id
        {
            return Err(ApiError::bad_request("item belongs to another vault"));
        }
        let current_revision = current.as_ref().map_or(0, |c| c.revision);
        if to_i64(change.base_revision)? != current_revision {
            let state = match current {
                Some(c) => ItemState {
                    item_id: change.item_id,
                    revision: to_u64(c.revision)?,
                    seq: to_u64(c.seq)?,
                    item: c.item,
                },
                None => ItemState {
                    item_id: change.item_id,
                    revision: 0,
                    seq: 0,
                    item: None,
                },
            };
            results.push(PushOutcome::Conflict { current: state });
            continue;
        }
        if current.is_none() && change.item.is_none() {
            return Err(ApiError::bad_request("cannot delete an unknown item"));
        }
        // 3. Accept.
        let seq: i64 = sqlx::query_scalar("UPDATE account_seq SET last_seq = last_seq + 1 WHERE account_id = $1 RETURNING last_seq")
            .bind(account)
            .fetch_one(&mut *tx)
            .await?;
        let revision = current_revision
            .checked_add(1)
            .ok_or_else(ApiError::internal)?;
        sqlx::query(
            "INSERT INTO items (account_id, vault_id, item_id, revision, deleted, encrypted, seq, updated_by, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (account_id, item_id) DO UPDATE SET
                revision = excluded.revision, deleted = excluded.deleted, encrypted = excluded.encrypted,
                seq = excluded.seq, updated_by = excluded.updated_by, updated_at = excluded.updated_at",
        )
        .bind(account)
        .bind(vault_id)
        .bind(item_uuid)
        .bind(revision)
        .bind(change.item.is_none())
        .bind(change.item.as_ref().map(DbJson))
        .bind(seq)
        .bind(session.device_id.as_uuid())
        .bind(now())
        .execute(&mut *tx)
        .await?;
        let outcome = PushOutcome::Accepted {
            state: ItemState {
                item_id: change.item_id,
                revision: to_u64(revision)?,
                seq: to_u64(seq)?,
                item: change.item,
            },
        };
        sqlx::query(
            "INSERT INTO applied_changes (account_id, change_id, item_id, outcome, applied_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(account)
        .bind(change.change_id.as_uuid())
        .bind(item_uuid)
        .bind(DbJson(&outcome))
        .bind(now())
        .execute(&mut *tx)
        .await?;
        results.push(outcome);
    }
    tx.commit().await?;
    Ok(Json(PushResponse { results }))
}

#[derive(Deserialize)]
pub(crate) struct PullQuery {
    #[serde(default)]
    since: u64,
    limit: Option<i64>,
}

/// `GET /v1/vaults/{vault_id}/changes?since=…&limit=…`.
pub(crate) async fn pull(
    State(state): State<AppState>,
    session: Session,
    Path(vault_id): Path<Uuid>,
    Query(query): Query<PullQuery>,
) -> ApiResult<Json<PullResponse>> {
    session.require_full()?;
    let limit = query
        .limit
        .unwrap_or(MAX_PULL_LIMIT)
        .clamp(1, MAX_PULL_LIMIT);
    let rows = sqlx::query(
        "SELECT item_id, revision, seq, encrypted FROM items
         WHERE account_id = $1 AND vault_id = $2 AND seq > $3
         ORDER BY seq LIMIT $4",
    )
    .bind(session.account_id.as_uuid())
    .bind(vault_id)
    .bind(to_i64(query.since)?)
    .bind(limit.saturating_add(1))
    .fetch_all(state.db())
    .await?;
    let more = i64::try_from(rows.len()).unwrap_or(i64::MAX) > limit;
    let mut items = Vec::new();
    for row in rows.into_iter().take(usize::try_from(limit).unwrap_or(0)) {
        let encrypted: Option<DbJson<EncryptedItem>> = row.try_get("encrypted")?;
        let item_id: Uuid = row.try_get("item_id")?;
        items.push(ItemState {
            item_id: ItemId::from_uuid(item_id),
            revision: to_u64(row.try_get("revision")?)?,
            seq: to_u64(row.try_get("seq")?)?,
            item: encrypted.map(|DbJson(i)| i),
        });
    }
    let next_since = items.last().map_or(query.since, |s| s.seq);
    // Read after the items: every committed push visible above is also
    // counted here, so `head` is never lower than a returned `seq`.
    let meta = sqlx::query(
        "SELECT (SELECT history_id FROM server_meta) AS history,
                COALESCE((SELECT last_seq FROM account_seq WHERE account_id = $1), 0) AS head",
    )
    .bind(session.account_id.as_uuid())
    .fetch_one(state.db())
    .await?;
    let history: Option<Uuid> = meta.try_get("history")?;
    Ok(Json(PullResponse {
        items,
        next_since,
        more,
        head: to_u64(meta.try_get("head")?)?,
        history: history.ok_or_else(|| {
            tracing::error!("server_meta holds no history identifier");
            ApiError::internal()
        })?,
    }))
}
