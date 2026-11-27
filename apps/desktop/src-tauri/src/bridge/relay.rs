//! Relay mode: when a browser starts the executable as its native
//! messaging host, frames are copied between standard input/output and the
//! running application's endpoint. No window, no vault: only this module
//! and the frame helpers run.

use std::io;
use std::process::ExitCode;

use lk_bridge::{Caller, Endpoint, endpoint};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};

use super::data_dir;
use super::io::{connect, read_frame, send, send_error, write_frame};

/// Runs the relay for `caller` with the process's standard streams.
#[must_use]
pub fn run(caller: &Caller) -> ExitCode {
    let Some(dir) = data_dir() else {
        return ExitCode::FAILURE;
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    let result = runtime.block_on(relay(
        caller,
        &endpoint(&dir),
        tokio::io::stdin(),
        tokio::io::stdout(),
    ));
    // A read of standard input may still be blocked: do not wait for it.
    runtime.shutdown_background();
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Copies frames in both directions until either side closes. The first
/// frame sent to the application announces the caller; when the
/// application cannot be reached, the extension receives a
/// `desktop_unavailable` error.
///
/// # Errors
/// I/O errors on either side.
pub async fn relay<R, W>(
    caller: &Caller,
    endpoint: &Endpoint,
    mut input: R,
    mut output: W,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Ok(stream) = connect(endpoint).await else {
        return send_error(
            &mut output,
            0,
            "desktop_unavailable",
            "Last Keys is not running or browser integration is off",
        )
        .await;
    };
    let (mut from_app, mut to_app) = tokio::io::split(stream);
    send(
        &mut to_app,
        0,
        "relay",
        &json!({
            "caller": caller.extension,
            "browser": caller.family,
            "version": env!("CARGO_PKG_VERSION"),
        }),
    )
    .await?;
    let up = async {
        while let Some(frame) = read_frame(&mut input).await? {
            write_frame(&mut to_app, &frame).await?;
        }
        io::Result::Ok(())
    };
    let down = async {
        while let Some(frame) = read_frame(&mut from_app).await? {
            write_frame(&mut output, &frame).await?;
        }
        io::Result::Ok(())
    };
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}
