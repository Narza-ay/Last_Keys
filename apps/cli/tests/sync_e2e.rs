//! End to end: two devices running the real `lk` binary synchronize through
//! a real `lk-server` (in-process, real HTTP) backed by PostgreSQL.
//! Requires `LK_TEST_DATABASE_URL` and `--features server-e2e`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const MASTER: &str = "correct horse battery staple";
const EMAIL: &str = "e2e@example.com";

struct Server {
    url: String,
    runtime: tokio::runtime::Runtime,
    admin_url: String,
    db_name: String,
}

impl Server {
    fn start() -> Self {
        let admin_url =
            std::env::var("LK_TEST_DATABASE_URL").expect("LK_TEST_DATABASE_URL must be set");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let db_name = format!(
            "lk_e2e_{}",
            data_encoding::HEXLOWER.encode(&lk_crypto::rng::random_array::<8>().unwrap())
        );
        let url = runtime.block_on(async {
            let admin = sqlx::PgPool::connect(&admin_url).await.unwrap();
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db_name}")))
                .execute(&admin)
                .await
                .unwrap();
            admin.close().await;
            let (prefix, _) = admin_url.rsplit_once('/').unwrap();
            let pool = lk_server::connect_and_migrate(&format!("{prefix}/{db_name}"))
                .await
                .unwrap();
            let state = lk_server::AppState::new(
                pool,
                lk_auth::ServerSecret::generate(),
                lk_server::Config::default(),
            )
            .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum_serve(listener, lk_server::router(state)).await;
            });
            format!("http://{addr}")
        });
        Self {
            url,
            runtime,
            admin_url,
            db_name,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let db = self.db_name.clone();
        self.runtime.block_on(async move {
            if let Ok(admin) = sqlx::PgPool::connect(&admin_url).await {
                let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                    "DROP DATABASE {db} WITH (FORCE)"
                )))
                .execute(&admin)
                .await;
            }
        });
    }
}

async fn axum_serve(listener: tokio::net::TcpListener, router: axum::Router) {
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();
}

fn lk(vault: &Path, args: &[&str], stdin_lines: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lk"))
        .arg("--vault")
        .arg(vault)
        .arg("--password-stdin")
        .args(args)
        .env_remove("LK_VAULT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for line in stdin_lines {
            if writeln!(stdin, "{line}").is_err() {
                break;
            }
        }
    }
    child.wait_with_output().unwrap()
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn err(out: &Output) -> String {
    assert!(
        !out.status.success(),
        "command unexpectedly succeeded: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn password_of(stdout: &str) -> String {
    stdout
        .lines()
        .find(|l| l.starts_with("Password:"))
        .unwrap()
        .trim_start_matches("Password:")
        .trim()
        .to_owned()
}

#[test]
fn two_cli_devices_synchronize_through_the_server() {
    let server = Server::start();
    let dir = tempfile::tempdir().unwrap();
    let a: PathBuf = dir.path().join("a.lkvault");
    let b: PathBuf = dir.path().join("b.lkvault");

    // Device A: create, register (master password + recovery key), add, sync.
    let init = ok(&lk(
        &a,
        &["init", "--device-name", "laptop"],
        &[MASTER, MASTER],
    ));
    let recovery = init
        .lines()
        .find(|l| l.starts_with("Recovery key: "))
        .unwrap()
        .trim_start_matches("Recovery key: ")
        .to_owned();
    // A wrong recovery key is refused at registration.
    let wrong_rk = "LK1-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0005-B7J7";
    err(&lk(
        &a,
        &["register", "--server", &server.url, "--email", EMAIL],
        &[MASTER, wrong_rk],
    ));
    let out = ok(&lk(
        &a,
        &["register", "--server", &server.url, "--email", EMAIL],
        &[MASTER, &recovery],
    ));
    assert!(out.contains("Registered"));
    let added = ok(&lk(
        &a,
        &[
            "add",
            "login",
            "--title",
            "Bank",
            "--username",
            "alice",
            "--generate",
        ],
        &[MASTER],
    ));
    let id = added.split_whitespace().nth(1).unwrap().to_owned();
    assert!(ok(&lk(&a, &["sync"], &[MASTER])).contains("1 sent"));
    let password_a = password_of(&ok(&lk(&a, &["show", &id, "--reveal"], &[MASTER])));

    // Device B: enroll with e-mail + master password only; items arrive.
    let out = ok(&lk(
        &b,
        &[
            "login",
            "--server",
            &server.url,
            "--email",
            EMAIL,
            "--device-name",
            "phone",
        ],
        &[MASTER],
    ));
    assert!(out.contains("1 item(s) received"), "{out}");
    let password_b = password_of(&ok(&lk(&b, &["show", &id, "--reveal"], &[MASTER])));
    assert_eq!(password_a, password_b);

    // B changes the password; A receives it, with the old one in history.
    ok(&lk(&b, &["edit", &id, "--generate"], &[MASTER]));
    ok(&lk(&b, &["sync"], &[MASTER]));
    ok(&lk(&a, &["sync"], &[MASTER]));
    let shown = ok(&lk(&a, &["show", &id, "--reveal"], &[MASTER]));
    assert_ne!(password_of(&shown), password_a);
    assert!(ok(&lk(&a, &["history", &id, "--reveal"], &[MASTER])).contains(&password_a));

    // Devices are listed and verified; A revokes B; B is locked out.
    let devices = ok(&lk(&a, &["devices"], &[MASTER]));
    assert!(
        devices.contains("this device") && devices.contains("phone") && devices.contains("active"),
        "{devices}"
    );
    let b_line = devices.lines().find(|l| l.contains("phone")).unwrap();
    let b_prefix = b_line.split_whitespace().next().unwrap();
    ok(&lk(&a, &["revoke", b_prefix], &[MASTER]));
    assert!(err(&lk(&b, &["sync"], &[MASTER])).contains("revoked"));
    assert!(ok(&lk(&a, &["devices"], &[MASTER])).contains("revoked"));

    // Password change on A updates the server credential too.
    let new_master = "a brand new master password";
    ok(&lk(&a, &["passwd"], &[MASTER, new_master, new_master]));
    ok(&lk(&a, &["sync"], &[new_master]));
    assert!(err(&lk(&a, &["sync"], &[MASTER])).contains("wrong master password"));

    // Forgotten password: reset with the recovery key, server included.
    let reset = "reset with the recovery key";
    ok(&lk(
        &a,
        &["--recovery-key", "passwd"],
        &[&recovery, reset, reset],
    ));
    assert!(ok(&lk(&a, &["sync"], &[reset])).contains("Synchronized"));

    // A full resynchronization against a healthy server changes nothing:
    // every item is identical on both sides, nothing is sent or copied.
    let before = ok(&lk(&a, &["list"], &[reset]));
    let resync = ok(&lk(&a, &["sync", "--reset"], &[reset]));
    assert!(
        resync.contains("0 sent, 0 conflict(s)") && !resync.contains("conflict copy"),
        "{resync}"
    );
    assert_eq!(ok(&lk(&a, &["list"], &[reset])), before);

    // A third device can enroll with the reset password.
    let c = dir.path().join("c.lkvault");
    assert!(
        ok(&lk(
            &c,
            &["login", "--server", &server.url, "--email", EMAIL],
            &[reset]
        ))
        .contains("item(s) received")
    );
    drop(server);
}

#[test]
fn plain_http_to_remote_hosts_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let v = dir.path().join("v.lkvault");
    let m = err(&lk(
        &v,
        &[
            "login",
            "--server",
            "http://sync.example.com",
            "--email",
            EMAIL,
        ],
        &[MASTER],
    ));
    assert!(m.contains("plain HTTP"), "{m}");
}
