//! Last Keys desktop application entry point.

// No console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
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
