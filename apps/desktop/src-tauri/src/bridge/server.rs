//! The local endpoint: a Unix domain socket in a private directory (Linux,
//! macOS) or a named pipe (Windows), served while browser integration is
//! on.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lk_bridge::Endpoint;
use tokio::task::JoinHandle;

use super::{BridgeContext, BridgeEvent, session};

/// Most simultaneous connections (one per browser profile is typical).
pub const MAX_CONNECTIONS: usize = 8;

/// A running endpoint.
pub struct ServerHandle {
    task: JoinHandle<()>,
    endpoint: Endpoint,
}

impl ServerHandle {
    /// The endpoint served.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Stops accepting connections, ends the open ones and removes the
    /// socket file.
    pub fn stop(self, ctx: &BridgeContext) {
        self.task.abort();
        let _ = ctx.events.send(BridgeEvent::Disabled);
        if let Endpoint::Unix(path) = &self.endpoint {
            let _ = std::fs::remove_file(path);
        }
    }
}

struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(active: &Arc<AtomicUsize>) -> Option<Self> {
        let previous = active.fetch_add(1, Ordering::SeqCst);
        if previous >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Self(Arc::clone(active)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn serve_with_slot<S>(stream: S, ctx: &Arc<BridgeContext>, active: &Arc<AtomicUsize>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    let Some(slot) = Slot::take(active) else {
        return; // dropping the stream closes it
    };
    let ctx = Arc::clone(ctx);
    tokio::spawn(async move {
        session::serve(stream, ctx).await;
        drop(slot);
    });
}

/// Starts serving `endpoint`. Must be called within a Tokio runtime.
///
/// # Errors
/// `AddrInUse` when another running instance serves it; other I/O errors.
pub async fn start(ctx: Arc<BridgeContext>, endpoint: Endpoint) -> io::Result<ServerHandle> {
    let task = match &endpoint {
        #[cfg(unix)]
        Endpoint::Unix(path) => {
            let listener = bind_unix(path)?;
            let active = Arc::new(AtomicUsize::new(0));
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => serve_with_slot(stream, &ctx, &active),
                        Err(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                    }
                }
            })
        }
        #[cfg(windows)]
        Endpoint::Pipe(name) => {
            use tokio::net::windows::named_pipe::ServerOptions;
            let name = name.clone();
            // Windows answers "access denied" when another process already
            // serves this pipe: report it as the address being in use.
            let mut server = ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create(&name)
                .map_err(|e| {
                    if e.kind() == io::ErrorKind::PermissionDenied {
                        io::Error::new(
                            io::ErrorKind::AddrInUse,
                            "another instance of Last Keys serves the browser bridge",
                        )
                    } else {
                        e
                    }
                })?;
            let active = Arc::new(AtomicUsize::new(0));
            tokio::spawn(async move {
                loop {
                    if server.connect().await.is_err() {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    let next = match ServerOptions::new()
                        .reject_remote_clients(true)
                        .create(&name)
                    {
                        Ok(next) => next,
                        Err(_) => break,
                    };
                    let connected = std::mem::replace(&mut server, next);
                    serve_with_slot(connected, &ctx, &active);
                }
            })
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "endpoint not supported on this platform",
            ));
        }
    };
    Ok(ServerHandle { task, endpoint })
}

/// Binds the socket in a directory readable by the user only; a socket
/// left by a crashed instance is replaced, a live one is not.
#[cfg(unix)]
fn bind_unix(path: &std::path::Path) -> io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "another instance of Last Keys serves the browser bridge",
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
