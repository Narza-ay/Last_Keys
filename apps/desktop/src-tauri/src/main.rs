//! Last Keys desktop application entry point.

// No console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    // Started by a browser as its native messaging host: relay only, no
    // window (ADR-0011).
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if let Some(caller) = lk_bridge::caller_from_args(&args) {
        return lk_desktop::bridge::relay::run(&caller);
    }
    match lk_desktop::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("Last Keys could not start: {e}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}
