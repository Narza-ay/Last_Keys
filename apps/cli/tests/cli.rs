//! End-to-end tests of the `lk` binary: real key derivation, real store,
//! real encryption. Secrets are passed through standard input.

// Test helpers outside `#[test]` functions: panicking is the intended outcome.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const MASTER: &str = "correct horse battery staple";

struct Env {
    _dir: tempfile::TempDir,
    vault: PathBuf,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("data").join("vault.lkvault");
    Env { _dir: dir, vault }
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
            // The program may legitimately exit before reading its input
            // (e.g. rejected arguments): a closed pipe is not a test failure.
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
        "command failed: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn err(out: &Output) -> String {
    assert!(!out.status.success(), "command unexpectedly succeeded");
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn init(e: &Env) -> String {
    let out = ok(&lk(&e.vault, &["init"], &[MASTER, MASTER]));
    let line = out
        .lines()
        .find(|l| l.starts_with("Recovery key: "))
        .expect("recovery key printed");
    line.trim_start_matches("Recovery key: ").to_owned()
}

fn added_id(stdout: &str) -> String {
    stdout.split_whitespace().nth(1).unwrap().to_owned()
}

#[test]
fn full_vault_workflow() {
    let e = env();
    let recovery = init(&e);
    assert!(recovery.starts_with("LK1-"));

    // Add a login with a password and a TOTP secret (RFC 6238 seed).
    let out = ok(&lk(
        &e.vault,
        &[
            "add",
            "login",
            "--title",
            "Bank",
            "--username",
            "alice",
            "--url",
            "bank.example.com",
            "--totp",
        ],
        &[MASTER, "s3cret-pw", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"],
    ));
    let id = added_id(&out);
    assert_eq!(id.len(), 8);
    ok(&lk(
        &e.vault,
        &["add", "note", "--title", "Wifi"],
        &[MASTER, "router code 1234"],
    ));
    ok(&lk(
        &e.vault,
        &[
            "add",
            "card",
            "--title",
            "Visa",
            "--cardholder",
            "Alice",
            "--expiry",
            "12/2030",
        ],
        &[MASTER, "4111 1111 1111 1111", "123"],
    ));

    // Listing and searching.
    let list = ok(&lk(&e.vault, &["list"], &[MASTER]));
    assert!(list.contains("Bank") && list.contains("Wifi") && list.contains("Visa"));
    let search = ok(&lk(&e.vault, &["list", "bank.example"], &[MASTER]));
    assert!(search.contains("Bank") && !search.contains("Wifi"));

    // Secrets are masked unless --reveal.
    let shown = ok(&lk(&e.vault, &["show", &id], &[MASTER]));
    assert!(shown.contains("alice") && shown.contains("https://bank.example.com/"));
    assert!(!shown.contains("s3cret-pw"));
    let revealed = ok(&lk(&e.vault, &["show", &id, "--reveal"], &[MASTER]));
    assert!(revealed.contains("s3cret-pw"));

    // TOTP: a 6-digit code.
    let code = ok(&lk(&e.vault, &["totp", &id], &[MASTER]));
    let code = code.trim();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));

    // Change the password: the old one goes to the history.
    ok(&lk(
        &e.vault,
        &["edit", &id, "--password"],
        &[MASTER, "n3w-pw", "n3w-pw"],
    ));
    let history = ok(&lk(&e.vault, &["history", &id, "--reveal"], &[MASTER]));
    assert!(history.contains("s3cret-pw"));
    ok(&lk(
        &e.vault,
        &["edit", &id, "--restore-password", "1"],
        &[MASTER],
    ));
    let revealed = ok(&lk(&e.vault, &["show", &id, "--reveal"], &[MASTER]));
    assert!(revealed.contains("s3cret-pw"));

    // Delete.
    ok(&lk(&e.vault, &["delete", &id], &[MASTER]));
    let list = ok(&lk(&e.vault, &["list"], &[MASTER]));
    assert!(!list.contains("Bank"));
    let info = ok(&lk(&e.vault, &["info"], &[MASTER]));
    assert!(info.contains("Items:          2"));
    assert!(info.contains("software"));
}

#[test]
fn wrong_password_and_recovery_flows() {
    let e = env();
    let recovery = init(&e);
    let message = err(&lk(&e.vault, &["list"], &["not the password"]));
    assert!(message.contains("wrong master password or recovery key"));

    // Forgotten password: reset it with the recovery key.
    ok(&lk(
        &e.vault,
        &["--recovery-key", "passwd"],
        &[&recovery, "a brand new master pw", "a brand new master pw"],
    ));
    err(&lk(&e.vault, &["list"], &[MASTER]));
    ok(&lk(&e.vault, &["list"], &["a brand new master pw"]));

    // Rotate the recovery key: the old one stops working.
    let out = ok(&lk(
        &e.vault,
        &["recovery", "rotate"],
        &["a brand new master pw"],
    ));
    let new_recovery = out
        .lines()
        .find(|l| l.starts_with("Recovery key: "))
        .unwrap()
        .trim_start_matches("Recovery key: ")
        .to_owned();
    assert_ne!(new_recovery, recovery);
    err(&lk(&e.vault, &["--recovery-key", "list"], &[&recovery]));
    ok(&lk(&e.vault, &["--recovery-key", "list"], &[&new_recovery]));
    // Typing mistakes in the recovery key are caught by its checksum.
    let typo = new_recovery.replacen('0', "8", 1).replacen('A', "B", 1);
    if typo != new_recovery {
        err(&lk(&e.vault, &["--recovery-key", "list"], &[&typo]));
    }
}

#[test]
fn init_guards() {
    let e = env();
    // Mismatched confirmation.
    let m = err(&lk(
        &e.vault,
        &["init"],
        &[MASTER, "something else entirely"],
    ));
    assert!(m.contains("do not match"));
    // Too short.
    let m = err(&lk(&e.vault, &["init"], &["short", "short"]));
    assert!(m.contains("at least 12"));
    assert!(!e.vault.exists());
    // No overwrite of an existing vault.
    init(&e);
    let m = err(&lk(&e.vault, &["init"], &[MASTER, MASTER]));
    assert!(m.contains("already exists"));
}

#[test]
fn secrets_are_never_accepted_as_arguments() {
    let e = env();
    init(&e);
    for args in [
        vec!["add", "login", "--title", "x", "--password", "hunter2"],
        vec!["list", "--master-password", "hunter2"],
    ] {
        let out = lk(&e.vault, &args, &[MASTER]);
        assert!(!out.status.success(), "{args:?} must be rejected");
    }
}

#[test]
fn generator_commands() {
    let e = env();
    let out = ok(&lk(
        &e.vault,
        &["generate", "--length", "32", "--no-symbols"],
        &[],
    ));
    let pw = out.trim();
    assert_eq!(pw.len(), 32);
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    let out = ok(&lk(
        &e.vault,
        &[
            "generate",
            "--passphrase",
            "--words",
            "5",
            "--separator",
            " ",
        ],
        &[],
    ));
    assert_eq!(out.trim().split(' ').count(), 5);
    err(&lk(&e.vault, &["generate", "--length", "2"], &[]));
}

#[test]
fn ambiguous_and_unknown_references() {
    let e = env();
    init(&e);
    let m = err(&lk(&e.vault, &["show", "abc"], &[MASTER]));
    assert!(m.contains("at least 4"));
    let m = err(&lk(&e.vault, &["show", "ffffffff"], &[MASTER]));
    assert!(m.contains("no item matches"));
}
