//! One extension connection: the relay's announcement, then pairing or
//! mutual authentication, then requests. A connection that breaks the
//! protocol is closed.

use std::sync::Arc;
use std::time::Instant;

use lk_bridge::{Caller, ClientId, CopyField, Nonce, Request, auth, parse_request};
use lk_client::{Field, FillTarget, ItemId, Zeroizing};
use serde::Serialize;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc};

use super::io::{read_frame, send, send_error};
use super::pairing::{Outcome, PAIRING_TIMEOUT};
use super::{BridgeContext, BridgeEvent};
use crate::core::{DesktopCore, VaultEvent, unix_now};
use crate::error::{UiError, UiResult};

enum State {
    /// Waiting for the relay's announcement.
    Fresh,
    /// Announced, not authenticated.
    Connected { caller: Caller },
    /// The desktop sent its challenge.
    Challenged {
        caller: Caller,
        client: ClientId,
        client_nonce: Nonce,
        server_nonce: Nonce,
    },
    /// Authenticated.
    Ready { client: ClientId },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Close,
}

type Frames = mpsc::Receiver<Zeroizing<Vec<u8>>>;

/// Serves one connection until it ends.
pub(super) async fn serve<S>(stream: S, ctx: Arc<BridgeContext>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    // A dedicated reader task keeps frame reading cancel-safe.
    let (tx, mut frames) = mpsc::channel(8);
    let reader_task = tokio::spawn(async move {
        while let Ok(Some(body)) = read_frame(&mut reader).await {
            if tx.send(body).await.is_err() {
                break;
            }
        }
    });
    let mut events = ctx.events.subscribe();
    let mut state = State::Fresh;
    loop {
        let flow = tokio::select! {
            frame = frames.recv() => match frame {
                Some(body) => handle_frame(&ctx, &mut state, &body, &mut writer, &mut frames)
                    .await
                    .unwrap_or(Flow::Close),
                None => Flow::Close,
            },
            event = events.recv() => handle_event(&state, event, &mut writer)
                .await
                .unwrap_or(Flow::Close),
        };
        if flow == Flow::Close {
            break;
        }
    }
    reader_task.abort();
    let _ = writer.shutdown().await;
}

async fn handle_event<W: AsyncWrite + Unpin>(
    state: &State,
    event: Result<BridgeEvent, broadcast::error::RecvError>,
    w: &mut W,
) -> std::io::Result<Flow> {
    let event = match event {
        Ok(event) => event,
        Err(broadcast::error::RecvError::Lagged(_)) => return Ok(Flow::Continue),
        Err(broadcast::error::RecvError::Closed) => return Ok(Flow::Close),
    };
    let client = match state {
        State::Ready { client } | State::Challenged { client, .. } => Some(client),
        _ => None,
    };
    match (event, client) {
        (BridgeEvent::Disabled, _) => Ok(Flow::Close),
        (BridgeEvent::Revoked(id), Some(client)) if id == *client => {
            send(w, 0, "event", &json!({"event": "revoked"})).await?;
            Ok(Flow::Close)
        }
        (BridgeEvent::Vault(event), Some(_)) if matches!(state, State::Ready { .. }) => {
            let name = match event {
                VaultEvent::Locked => "locked",
                VaultEvent::Unlocked => "unlocked",
                VaultEvent::Changed => return Ok(Flow::Continue),
            };
            send(w, 0, "event", &json!({ "event": name })).await?;
            Ok(Flow::Continue)
        }
        _ => Ok(Flow::Continue),
    }
}

async fn handle_frame<W: AsyncWrite + Unpin>(
    ctx: &Arc<BridgeContext>,
    state: &mut State,
    body: &[u8],
    w: &mut W,
    frames: &mut Frames,
) -> std::io::Result<Flow> {
    let incoming = match parse_request(body) {
        Ok(incoming) => incoming,
        Err(e) => {
            send_error(w, 0, "malformed", &e.to_string()).await?;
            return Ok(Flow::Close);
        }
    };
    let id = incoming.id;
    match (&*state, incoming.request) {
        (
            State::Fresh,
            Request::Relay {
                caller, browser, ..
            },
        ) => {
            *state = State::Connected {
                caller: Caller {
                    family: browser,
                    extension: caller,
                },
            };
            Ok(Flow::Continue)
        }
        // Nothing before the relay's announcement, and only once.
        (State::Fresh, _) => Ok(Flow::Close),
        (_, Request::Relay { .. }) => {
            send_error(w, id, "malformed", "unexpected relay announcement").await?;
            Ok(Flow::Close)
        }
        (
            State::Connected { caller } | State::Challenged { caller, .. },
            Request::Pair { client_name },
        ) => {
            let caller = caller.clone();
            pair(ctx, id, &client_name, &caller, w, frames).await
        }
        (
            State::Connected { caller } | State::Challenged { caller, .. },
            Request::Hello { client_id, nonce },
        ) => {
            let caller = caller.clone();
            hello(ctx, state, id, caller, &client_id, &nonce, w).await
        }
        (
            State::Challenged {
                client,
                client_nonce,
                server_nonce,
                ..
            },
            Request::Auth { proof },
        ) => {
            let key = ctx.pairings.lock().ok().and_then(|p| p.key(client));
            let valid = key.is_some_and(|key| {
                auth::verify_client_proof(&key, client, client_nonce, server_nonce, &proof)
            });
            if !valid {
                send_error(w, id, "auth_failed", "authentication failed").await?;
                return Ok(Flow::Close);
            }
            let client = client.clone();
            if let Ok(mut pairings) = ctx.pairings.lock() {
                pairings.touch(&client, unix_now());
            }
            *state = State::Ready { client };
            match with_core(ctx, |c| Ok(status(c))).await {
                Ok(body) => send(w, id, "ready", &body).await?,
                Err(e) => send_error(w, id, &e.kind, &e.message).await?,
            }
            Ok(Flow::Continue)
        }
        (
            State::Ready { .. },
            Request::Pair { .. } | Request::Hello { .. } | Request::Auth { .. },
        ) => {
            send_error(w, id, "malformed", "already authenticated").await?;
            Ok(Flow::Continue)
        }
        (State::Ready { .. }, request) => {
            operation(ctx, id, request, w).await?;
            Ok(Flow::Continue)
        }
        _ => {
            send_error(w, id, "not_authenticated", "pair or authenticate first").await?;
            Ok(Flow::Close)
        }
    }
}

async fn pair<W: AsyncWrite + Unpin>(
    ctx: &Arc<BridgeContext>,
    id: u32,
    client_name: &str,
    caller: &Caller,
    w: &mut W,
    frames: &mut Frames,
) -> std::io::Result<Flow> {
    let (view, mut answer) = match ctx.broker.start(client_name, caller, Instant::now()) {
        Ok(started) => started,
        Err(e) => {
            send_error(w, id, &e.kind, &e.message).await?;
            return Ok(Flow::Continue);
        }
    };
    ctx.notifier.pairing_requested(&view);
    send(w, id, "pairing", &json!({ "code": view.code })).await?;
    let deadline = tokio::time::sleep(PAIRING_TIMEOUT);
    tokio::pin!(deadline);
    let (outcome, expired) = loop {
        tokio::select! {
            decided = &mut answer => break (match decided {
                Ok(true) => Outcome::Approved,
                _ => Outcome::Refused,
            }, false),
            () = &mut deadline => break (Outcome::Refused, true),
            frame = frames.recv() => match frame {
                None => break (Outcome::Cancelled, false),
                Some(body) => {
                    let other = parse_request(&body).map(|i| i.id).unwrap_or(0);
                    send_error(w, other, "pairing_busy", "a pairing is waiting for approval").await?;
                }
            },
        }
    };
    ctx.broker.finish(view.id, outcome, Instant::now());
    ctx.notifier.pairing_closed(view.id);
    match outcome {
        Outcome::Approved => {
            let added = ctx
                .pairings
                .lock()
                .map_err(|_| UiError::internal())
                .and_then(|mut p| p.add(&view.client_name, caller, unix_now()));
            match added {
                Ok((client, key)) => {
                    #[derive(Serialize)]
                    #[serde(rename_all = "camelCase")]
                    struct Paired<'a> {
                        client_id: &'a str,
                        key: &'a str,
                    }
                    let key = key.to_base64();
                    send(
                        w,
                        id,
                        "paired",
                        &Paired {
                            client_id: client.as_str(),
                            key: &key,
                        },
                    )
                    .await?;
                }
                Err(e) => send_error(w, id, &e.kind, &e.message).await?,
            }
            Ok(Flow::Continue)
        }
        Outcome::Refused if expired => {
            send_error(
                w,
                id,
                "pairing_timeout",
                "the request was not answered in time",
            )
            .await?;
            Ok(Flow::Continue)
        }
        Outcome::Refused => {
            send_error(w, id, "pairing_refused", "the request was refused").await?;
            Ok(Flow::Continue)
        }
        Outcome::Cancelled => Ok(Flow::Close),
    }
}

async fn hello<W: AsyncWrite + Unpin>(
    ctx: &Arc<BridgeContext>,
    state: &mut State,
    id: u32,
    caller: Caller,
    client_id: &str,
    nonce: &str,
    w: &mut W,
) -> std::io::Result<Flow> {
    let Ok(client_nonce) = Nonce::from_base64(nonce) else {
        send_error(w, id, "malformed", "invalid nonce").await?;
        return Ok(Flow::Close);
    };
    let client = ClientId::parse(client_id).ok();
    let key = client
        .as_ref()
        .and_then(|c| ctx.pairings.lock().ok().and_then(|p| p.key(c)));
    let (Some(client), Some(key)) = (client, key) else {
        send_error(w, id, "unknown_client", "this browser is not paired").await?;
        return Ok(Flow::Continue);
    };
    let Ok(server_nonce) = Nonce::generate() else {
        send_error(w, id, "internal", "internal error").await?;
        return Ok(Flow::Close);
    };
    let Ok(proof) = auth::server_proof(&key, &client, &client_nonce, &server_nonce) else {
        send_error(w, id, "internal", "internal error").await?;
        return Ok(Flow::Close);
    };
    send(
        w,
        id,
        "challenge",
        &json!({ "nonce": server_nonce.to_base64(), "proof": proof }),
    )
    .await?;
    *state = State::Challenged {
        caller,
        client,
        client_nonce,
        server_nonce,
    };
    Ok(Flow::Continue)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusBody {
    locked: bool,
    vault_exists: bool,
    version: &'static str,
}

fn status(core: &DesktopCore) -> StatusBody {
    let status = core.status();
    StatusBody {
        locked: !status.unlocked,
        vault_exists: status.vault_exists,
        version: status.version,
    }
}

async fn with_core<T, F>(ctx: &Arc<BridgeContext>, work: F) -> UiResult<T>
where
    T: Send + 'static,
    F: FnOnce(&mut DesktopCore) -> UiResult<T> + Send + 'static,
{
    let core = Arc::clone(&ctx.core);
    tokio::task::spawn_blocking(move || {
        let mut core = core.lock().map_err(|_| UiError::internal())?;
        work(&mut core)
    })
    .await
    .map_err(|_| UiError::internal())?
}

fn item_id(text: &str) -> UiResult<ItemId> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|_| UiError::new("not_found", "no such item"))
}

async fn reply<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    id: u32,
    kind: &str,
    result: UiResult<T>,
) -> std::io::Result<()> {
    match result {
        Ok(body) => send(w, id, kind, &body).await,
        Err(e) => send_error(w, id, &e.kind, &e.message).await,
    }
}

async fn operation<W: AsyncWrite + Unpin>(
    ctx: &Arc<BridgeContext>,
    id: u32,
    request: Request,
    w: &mut W,
) -> std::io::Result<()> {
    match request {
        Request::Status => reply(w, id, "status", with_core(ctx, |c| Ok(status(c))).await).await,
        Request::Focus => {
            ctx.notifier.focus();
            send(w, id, "ok", &json!({})).await
        }
        Request::List { page_url } => {
            let result = with_core(ctx, move |c| c.autofill_candidates(&page_url))
                .await
                .map(|logins| json!({ "logins": logins }));
            reply(w, id, "logins", result).await
        }
        Request::Fill {
            item_id: item,
            page_url,
            frame_url,
            cross_origin_confirmed,
        } => {
            let result = match item_id(&item) {
                Ok(item) => {
                    with_core(ctx, move |c| {
                        let target = FillTarget {
                            page_url: &page_url,
                            frame_url: &frame_url,
                            cross_origin_confirmed,
                        };
                        c.autofill_fill(&item, &target, Instant::now())
                    })
                    .await
                }
                Err(e) => Err(e),
            };
            reply(w, id, "credentials", result).await
        }
        Request::Copy {
            item_id: item,
            page_url,
            field,
        } => {
            let field = match field {
                CopyField::Username => Field::Username,
                CopyField::Password => Field::Password,
                CopyField::Totp => Field::TotpCode,
            };
            let result = match item_id(&item) {
                Ok(item) => {
                    with_core(ctx, move |c| {
                        c.autofill_copy(&item, &page_url, field, Instant::now())
                    })
                    .await
                }
                Err(e) => Err(e),
            };
            reply(w, id, "copied", result).await
        }
        Request::Generate => {
            #[derive(Serialize)]
            struct Generated<'a> {
                password: &'a str,
            }
            match with_core(ctx, |c| c.generate_for_autofill(Instant::now())).await {
                Ok(password) => {
                    send(
                        w,
                        id,
                        "generated",
                        &Generated {
                            password: &password,
                        },
                    )
                    .await
                }
                Err(e) => send_error(w, id, &e.kind, &e.message).await,
            }
        }
        Request::SaveCheck {
            page_url,
            username,
            password,
        } => {
            let result = with_core(ctx, move |c| {
                c.save_proposal(&page_url, username.as_deref(), password.expose())
            })
            .await
            .map(|proposal| json!({ "proposal": proposal }));
            reply(w, id, "proposal", result).await
        }
        Request::Save {
            page_url,
            username,
            password,
            update_id,
        } => {
            let update = match update_id.as_deref().map(item_id).transpose() {
                Ok(update) => update,
                Err(e) => return send_error(w, id, &e.kind, &e.message).await,
            };
            let result = with_core(ctx, move |c| {
                c.save_login(
                    &page_url,
                    username.as_deref(),
                    password.expose(),
                    update.as_ref(),
                    Instant::now(),
                )
            })
            .await
            .map(|item| json!({ "itemId": item }));
            reply(w, id, "saved", result).await
        }
        _ => send_error(w, id, "malformed", "unexpected request").await,
    }
}
