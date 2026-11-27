//! Asynchronous frame I/O and connection to the local endpoint.

use std::io;
use std::pin::Pin;

use lk_bridge::{Endpoint, frame};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use lk_client::Zeroizing;

/// Reads one frame; `None` when the stream ends cleanly before a header.
///
/// # Errors
/// I/O errors; `InvalidData` for an unacceptable length.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut head = [0_u8; 4];
    match reader.read_exact(&mut head).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = frame::body_len(head)?;
    let mut body = Zeroizing::new(vec![0_u8; len]);
    reader.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Writes one frame and flushes.
///
/// # Errors
/// I/O errors; `InvalidData` for an unacceptable length.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    writer.write_all(&frame::encode(body)?).await?;
    writer.flush().await
}

#[derive(Serialize)]
struct Out<'a, T: Serialize> {
    id: u32,
    #[serde(rename = "type")]
    kind: &'a str,
    #[serde(flatten)]
    body: &'a T,
}

/// Writes a message `{"id": id, "type": kind, ...body}`; the serialized
/// bytes are wiped after sending.
///
/// # Errors
/// I/O errors.
pub async fn send<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    id: u32,
    kind: &str,
    body: &T,
) -> io::Result<()> {
    let mut buf = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *buf, &Out { id, kind, body })
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_frame(writer, &buf).await
}

/// Writes an error message `{"id", "type": "error", "code", "message"}`.
///
/// # Errors
/// I/O errors.
pub async fn send_error<W: AsyncWrite + Unpin>(
    writer: &mut W,
    id: u32,
    code: &str,
    message: &str,
) -> io::Result<()> {
    #[derive(Serialize)]
    struct ErrorBody<'a> {
        code: &'a str,
        message: &'a str,
    }
    send(writer, id, "error", &ErrorBody { code, message }).await
}

/// A connected local stream.
pub trait Stream: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> Stream for T {}

/// Connects to the desktop's endpoint.
///
/// # Errors
/// I/O errors (typically: the application is not running, or browser
/// integration is off).
pub async fn connect(endpoint: &Endpoint) -> io::Result<Pin<Box<dyn Stream>>> {
    match endpoint {
        #[cfg(unix)]
        Endpoint::Unix(path) => Ok(Box::pin(tokio::net::UnixStream::connect(path).await?)),
        #[cfg(windows)]
        Endpoint::Pipe(name) => {
            use tokio::net::windows::named_pipe::ClientOptions;
            // All instances may be busy for a moment: retry briefly.
            let mut attempts = 0_u8;
            loop {
                match ClientOptions::new().open(name) {
                    Ok(client) => return Ok(Box::pin(client)),
                    Err(e) if e.raw_os_error() == Some(231) && attempts < 20 => {
                        attempts = attempts.saturating_add(1);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        #[allow(unreachable_patterns)]
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "endpoint not supported on this platform",
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[tokio::test]
    async fn frames_and_messages() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        send(&mut a, 7, "status", &serde_json::json!({"locked": true}))
            .await
            .unwrap();
        send_error(&mut a, 8, "locked", "the vault is locked")
            .await
            .unwrap();
        drop(a);
        let first: serde_json::Value =
            serde_json::from_slice(&read_frame(&mut b).await.unwrap().unwrap()).unwrap();
        assert_eq!(
            first,
            serde_json::json!({"id": 7, "type": "status", "locked": true})
        );
        let second: serde_json::Value =
            serde_json::from_slice(&read_frame(&mut b).await.unwrap().unwrap()).unwrap();
        assert_eq!(
            second,
            serde_json::json!({"id": 8, "type": "error", "code": "locked", "message": "the vault is locked"})
        );
        assert!(read_frame(&mut b).await.unwrap().is_none());
    }
}
