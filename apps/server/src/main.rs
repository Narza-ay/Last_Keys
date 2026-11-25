//! `lk-server` — Last Keys synchronization server.
//!
//! ```text
//! lk-server generate-secret <path>   create the OPAQUE server secret file
//! lk-server migrate                  apply database migrations and exit
//! lk-server serve                    run the server
//! ```
//!
//! Configuration: `LK_DATABASE_URL`, `LK_SERVER_SECRET_FILE`, `LK_BIND`
//! (default `0.0.0.0:8080`) and the optional variables of `Config::from_env`.

#![forbid(unsafe_code)]
#![allow(clippy::print_stderr, clippy::print_stdout)]

use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;

use lk_auth::ServerSecret;
use lk_server::{AppState, Config, connect_and_migrate, router};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("generate-secret") => match args.get(2) {
            Some(path) => generate_secret(Path::new(path)),
            None => Err("usage: lk-server generate-secret <path>".to_owned()),
        },
        Some("migrate") => run_async(migrate()),
        Some("serve") => run_async(serve()),
        _ => Err("usage: lk-server <generate-secret PATH | migrate | serve>".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lk-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_async(fut: impl Future<Output = Result<(), String>>) -> Result<(), String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?
        .block_on(fut)
}

fn generate_secret(path: &Path) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        format!(
            "cannot create {} (refusing to overwrite): {e}",
            path.display()
        )
    })?;
    let secret = ServerSecret::generate();
    let text = data_encoding::BASE64URL_NOPAD.encode(&secret.to_bytes());
    file.write_all(text.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|e| format!("write failed: {e}"))?;
    println!(
        "Server secret written to {}. Back it up securely; never commit it.",
        path.display()
    );
    Ok(())
}

fn load_secret() -> Result<ServerSecret, String> {
    let path = std::env::var("LK_SERVER_SECRET_FILE")
        .map_err(|_| "LK_SERVER_SECRET_FILE is not set".to_owned())?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read server secret file: {e}"))?;
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(text.trim().as_bytes())
        .map_err(|_| "server secret file is not valid".to_owned())?;
    ServerSecret::from_bytes(&bytes).map_err(|_| "server secret file is not valid".to_owned())
}

fn database_url() -> Result<String, String> {
    std::env::var("LK_DATABASE_URL").map_err(|_| "LK_DATABASE_URL is not set".to_owned())
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("LK_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if std::env::var("LK_LOG_FORMAT").is_ok_and(|v| v == "json") {
        builder.json().init();
    } else {
        builder.init();
    }
}

async fn migrate() -> Result<(), String> {
    init_logging();
    connect_and_migrate(&database_url()?)
        .await
        .map_err(|e| format!("database: {e}"))?;
    println!("Migrations applied.");
    Ok(())
}

async fn serve() -> Result<(), String> {
    init_logging();
    let config = Config::from_env()?;
    let secret = load_secret()?;
    let pool = connect_and_migrate(&database_url()?)
        .await
        .map_err(|e| format!("database: {e}"))?;
    let state = AppState::new(pool, secret, config)?;
    let bind: SocketAddr = std::env::var("LK_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
        .parse()
        .map_err(|_| "LK_BIND is not a valid socket address".to_owned())?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("cannot listen on {bind}: {e}"))?;
    tracing::info!(%bind, version = env!("CARGO_PKG_VERSION"), "lk-server listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| format!("server: {e}"))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutting down");
}
