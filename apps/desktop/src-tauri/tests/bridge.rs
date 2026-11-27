//! The browser bridge end to end (ADR-0011), over the real local endpoint:
//! relay announcement, pairing approved and refused, mutual
//! authentication, origin-checked requests, events, revocation, and the
//! real executable in relay mode (as a browser starts it).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lk_bridge::{ClientId, Nonce, PairingKey, auth, endpoint};
use lk_client::{ItemDraft, Platform, Zeroizing};
use lk_desktop::bridge::io::{Stream, connect, read_frame, write_frame};
use lk_desktop::bridge::server::{self, ServerHandle};
use lk_desktop::bridge::{BridgeContext, Notifier, PairingRequestView, PairingStore};
use lk_desktop::clipboard::ClipboardBackend;
use lk_desktop::commands::Shared;
use lk_desktop::core::{DesktopCore, Paths};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSWORD: &str = "correct horse battery staple";
const EXTENSION: &str = "bblheiicocdmmkjnhdeehaedddgcfhok";
const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Default)]
struct FakeClipboard(Arc<Mutex<Option<String>>>);

impl ClipboardBackend for FakeClipboard {
    fn set_secret(&mut self, text: &str) -> Result<(), String> {
        *self.0.lock().unwrap() = Some(text.to_owned());
        Ok(())
    }
    fn text(&mut self) -> Option<Zeroizing<String>> {
        self.0.lock().unwrap().clone().map(Zeroizing::new)
    }
    fn clear(&mut self) -> Result<(), String> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

#[derive(Default)]
struct Ui {
    requests: Mutex<Vec<PairingRequestView>>,
    closed: Mutex<Vec<u64>>,
    focus: AtomicUsize,
}

impl Notifier for Ui {
    fn pairing_requested(&self, request: &PairingRequestView) {
        self.requests.lock().unwrap().push(request.clone());
    }
    fn pairing_closed(&self, id: u64) {
        self.closed.lock().unwrap().push(id);
    }
    fn focus(&self) {
        self.focus.fetch_add(1, Ordering::SeqCst);
    }
}

struct Setup {
    dir: tempfile::TempDir,
    core: Shared,
    ctx: Arc<BridgeContext>,
    ui: Arc<Ui>,
    clipboard: FakeClipboard,
    server: Option<ServerHandle>,
}

fn login(core: &mut DesktopCore, title: &str, username: &str, password: &str, url: &str) {
    let draft: ItemDraft = serde_json::from_value(json!({
        "title": title,
        "content": {
            "type": "login",
            "username": username,
            "password": {"op": "set", "value": password},
            "urls": [url],
            "totp": {"op": "set", "value": "JBSWY3DPEHPK3PXP"}
        }
    }))
    .unwrap();
    core.create_item(draft).unwrap();
}

async fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let clipboard = FakeClipboard::default();
    let mut core = DesktopCore::new(
        Paths::in_dir(dir.path()),
        Platform::Linux,
        Box::new(clipboard.clone()),
        Instant::now(),
    );
    core.create_vault(PASSWORD, PASSWORD, "Laptop", Instant::now())
        .unwrap();
    login(
        &mut core,
        "Example",
        "alice",
        "s3cret-1",
        "https://example.com",
    );
    login(&mut core, "Other", "bob", "s3cret-2", "https://other.org");
    let core: Shared = Arc::new(Mutex::new(core));
    let ui = Arc::new(Ui::default());
    let ctx = Arc::new(BridgeContext::new(
        Arc::clone(&core),
        PairingStore::load(&dir.path().join("bridge.json")),
        Arc::clone(&ui) as Arc<dyn Notifier>,
    ));
    let weak = Arc::downgrade(&ctx);
    core.lock().unwrap().set_observer(Box::new(move |event| {
        if let Some(ctx) = weak.upgrade() {
            ctx.vault_event(event);
        }
    }));
    let server = server::start(Arc::clone(&ctx), endpoint(dir.path()))
        .await
        .unwrap();
    Setup {
        dir,
        core,
        ctx,
        ui,
        clipboard,
        server: Some(server),
    }
}

struct Client {
    stream: Pin<Box<dyn Stream>>,
    next: u32,
}

impl Client {
    async fn raw(dir: &std::path::Path) -> Self {
        Self {
            stream: connect(&endpoint(dir)).await.unwrap(),
            next: 0,
        }
    }

    async fn connect(dir: &std::path::Path) -> Self {
        let mut c = Self::raw(dir).await;
        c.write(&json!({"id": 0, "type": "relay", "caller": EXTENSION, "browser": "chromium", "version": "test"}))
            .await;
        c
    }

    async fn write(&mut self, v: &Value) {
        write_frame(&mut self.stream, &serde_json::to_vec(v).unwrap())
            .await
            .unwrap();
    }

    /// Next message, or `None` when the desktop closed the connection.
    async fn recv(&mut self) -> Option<Value> {
        let frame = tokio::time::timeout(TIMEOUT, read_frame(&mut self.stream))
            .await
            .expect("no answer in time")
            .ok()??;
        Some(serde_json::from_slice(&frame).unwrap())
    }

    async fn send(&mut self, mut v: Value) -> u32 {
        self.next += 1;
        v["id"] = json!(self.next);
        self.write(&v).await;
        self.next
    }

    async fn reply(&mut self, id: u32) -> Value {
        loop {
            let v = self.recv().await.expect("connection closed");
            if v["id"] == json!(id) {
                return v;
            }
        }
    }

    async fn call(&mut self, v: Value) -> Value {
        let id = self.send(v).await;
        self.reply(id).await
    }

    async fn closed(&mut self) -> bool {
        self.recv().await.is_none()
    }
}

async fn wait_for_request(ui: &Ui, count: usize) -> PairingRequestView {
    let start = Instant::now();
    loop {
        if let Some(r) = ui.requests.lock().unwrap().get(count - 1) {
            return r.clone();
        }
        assert!(start.elapsed() < TIMEOUT, "no pairing request");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn pair(s: &Setup) -> (String, String) {
    let mut c = Client::connect(s.dir.path()).await;
    let count = s.ui.requests.lock().unwrap().len() + 1;
    let id = c
        .send(json!({"type": "pair", "clientName": "Test browser"}))
        .await;
    let pairing = c.reply(id).await;
    assert_eq!(pairing["type"], "pairing");
    let request = wait_for_request(&s.ui, count).await;
    // The popup and the dialog show the same code.
    assert_eq!(pairing["code"], json!(request.code));
    assert_eq!(request.client_name, "Test browser");
    assert_eq!(request.extension, EXTENSION);
    assert!(s.ctx.broker.decide(request.id, true));
    let paired = c.reply(id).await;
    assert_eq!(paired["type"], "paired", "{paired}");
    (
        paired["clientId"].as_str().unwrap().to_owned(),
        paired["key"].as_str().unwrap().to_owned(),
    )
}

/// Runs hello/challenge/auth like the extension; returns the `ready` reply.
async fn authenticate(c: &mut Client, client_id: &str, key: &str) -> Value {
    let key = PairingKey::from_base64(key).unwrap();
    let client = ClientId::parse(client_id).unwrap();
    let nc = Nonce::generate().unwrap();
    let challenge = c
        .call(json!({"type": "hello", "clientId": client_id, "nonce": nc.to_base64()}))
        .await;
    assert_eq!(challenge["type"], "challenge", "{challenge}");
    let ns = Nonce::from_base64(challenge["nonce"].as_str().unwrap()).unwrap();
    assert!(auth::verify_server_proof(
        &key,
        &client,
        &nc,
        &ns,
        challenge["proof"].as_str().unwrap()
    ));
    let proof = auth::client_proof(&key, &client, &nc, &ns).unwrap();
    c.call(json!({"type": "auth", "proof": proof})).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pairing_authentication_and_requests() {
    let s = setup().await;
    let (client_id, key) = pair(&s).await;
    assert_eq!(s.ctx.clients().len(), 1);

    let mut c = Client::connect(s.dir.path()).await;
    let ready = authenticate(&mut c, &client_id, &key).await;
    assert_eq!(ready["type"], "ready");
    assert_eq!(ready["locked"], false);
    assert_eq!(ready["vaultExists"], true);

    // Only the logins of the page.
    let logins = c
        .call(json!({"type": "list", "pageUrl": "https://login.example.com/signin"}))
        .await;
    assert_eq!(logins["type"], "logins", "{logins}");
    let rows = logins["logins"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["title"], "Example");
    assert_eq!(rows[0]["matched"], "same_site");
    assert!(!logins.to_string().contains("s3cret"));
    let item = rows[0]["id"].as_str().unwrap().to_owned();

    let page = "https://example.com/login";
    let creds = c
        .call(json!({"type": "fill", "itemId": item, "pageUrl": page, "frameUrl": page}))
        .await;
    assert_eq!(creds["type"], "credentials", "{creds}");
    assert_eq!(creds["username"], "alice");
    assert_eq!(creds["password"], "s3cret-1");
    assert_eq!(creds["totp"].as_str().unwrap().len(), 6);

    // Rust re-checks every fill.
    let refused = c
        .call(json!({"type": "fill", "itemId": item, "pageUrl": "https://evil.com/", "frameUrl": "https://evil.com/"}))
        .await;
    assert_eq!(refused["type"], "error");
    assert_eq!(refused["code"], "origin_mismatch");
    let frame = "https://accounts.example.com/embedded";
    let confirm = c
        .call(json!({"type": "fill", "itemId": item, "pageUrl": page, "frameUrl": frame}))
        .await;
    assert_eq!(confirm["code"], "confirmation_required");
    let confirmed = c
        .call(json!({"type": "fill", "itemId": item, "pageUrl": page, "frameUrl": frame, "crossOriginConfirmed": true}))
        .await;
    assert_eq!(confirmed["type"], "credentials");
    let unknown = c
        .call(json!({"type": "fill", "itemId": "not-an-id", "pageUrl": page, "frameUrl": page}))
        .await;
    assert_eq!(unknown["code"], "not_found");

    // Copy goes from Rust to the clipboard, not to the extension.
    let copied = c
        .call(json!({"type": "copy", "itemId": item, "pageUrl": page, "field": "password"}))
        .await;
    assert_eq!(copied["type"], "copied", "{copied}");
    assert!(copied.get("password").is_none());
    assert_eq!(s.clipboard.0.lock().unwrap().as_deref(), Some("s3cret-1"));

    let generated = c.call(json!({"type": "generate"})).await;
    assert_eq!(generated["password"].as_str().unwrap().chars().count(), 20);

    // Save flow.
    let signup = "https://shop.example.net/register";
    let proposal = c
        .call(json!({"type": "save_check", "pageUrl": signup, "username": "carol", "password": "new-pw"}))
        .await;
    assert_eq!(
        proposal["proposal"],
        json!({"action": "new", "title": "example.net", "url": "https://shop.example.net/"})
    );
    let saved = c
        .call(json!({"type": "save", "pageUrl": signup, "username": "carol", "password": "new-pw"}))
        .await;
    assert_eq!(saved["type"], "saved", "{saved}");
    let unchanged = c
        .call(json!({"type": "save_check", "pageUrl": signup, "username": "carol", "password": "new-pw"}))
        .await;
    assert_eq!(unchanged["proposal"]["action"], "unchanged");
    let new_id = saved["itemId"].as_str().unwrap();
    let update = c
        .call(json!({"type": "save_check", "pageUrl": signup, "username": "carol", "password": "newer"}))
        .await;
    assert_eq!(update["proposal"]["action"], "update_password");
    assert_eq!(update["proposal"]["id"], new_id);
    let updated = c
        .call(json!({"type": "save", "pageUrl": signup, "username": "carol", "password": "newer", "updateId": new_id}))
        .await;
    assert_eq!(updated["type"], "saved");
    let hijack = c
        .call(json!({"type": "save", "pageUrl": "https://evil.com/", "username": "carol", "password": "x", "updateId": new_id}))
        .await;
    assert_eq!(hijack["code"], "origin_mismatch");

    let focus = c.call(json!({"type": "focus"})).await;
    assert_eq!(focus["type"], "ok");
    assert_eq!(s.ui.focus.load(Ordering::SeqCst), 1);

    // Locking reaches the extension; requests then fail with `locked`.
    s.core.lock().unwrap().lock();
    let event = c.recv().await.unwrap();
    assert_eq!(event, json!({"id": 0, "type": "event", "event": "locked"}));
    let locked = c.call(json!({"type": "list", "pageUrl": page})).await;
    assert_eq!(locked["code"], "locked");
    let status = c.call(json!({"type": "status"})).await;
    assert_eq!(status["locked"], true);
    s.core
        .lock()
        .unwrap()
        .unlock(PASSWORD, Instant::now())
        .unwrap();
    let event = c.recv().await.unwrap();
    assert_eq!(event["event"], "unlocked");

    // A second session of the same extension works too; revocation ends both.
    let mut c2 = Client::connect(s.dir.path()).await;
    assert_eq!(
        authenticate(&mut c2, &client_id, &key).await["type"],
        "ready"
    );
    s.ctx.revoke(&client_id).unwrap();
    for client in [&mut c, &mut c2] {
        assert_eq!(client.recv().await.unwrap()["event"], "revoked");
        assert!(client.closed().await);
    }
    let mut c3 = Client::connect(s.dir.path()).await;
    let nc = Nonce::generate().unwrap();
    let unknown = c3
        .call(json!({"type": "hello", "clientId": client_id, "nonce": nc.to_base64()}))
        .await;
    assert_eq!(unknown["code"], "unknown_client");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_violations_close_the_connection() {
    let s = setup().await;
    let (client_id, key) = pair(&s).await;

    // Nothing is accepted before the relay's announcement.
    let mut c = Client::raw(s.dir.path()).await;
    c.send(json!({"type": "status"})).await;
    assert!(c.closed().await);

    // Requests before authentication.
    let mut c = Client::connect(s.dir.path()).await;
    let e = c
        .call(json!({"type": "list", "pageUrl": "https://example.com/"}))
        .await;
    assert_eq!(e["code"], "not_authenticated");
    assert!(c.closed().await);

    // A second relay announcement.
    let mut c = Client::connect(s.dir.path()).await;
    c.write(
        &json!({"id": 0, "type": "relay", "caller": "x", "browser": "firefox", "version": "1"}),
    )
    .await;
    assert_eq!(c.recv().await.unwrap()["code"], "malformed");
    assert!(c.closed().await);

    // A wrong proof: one failure closes the connection.
    let mut c = Client::connect(s.dir.path()).await;
    let nc = Nonce::generate().unwrap();
    let challenge = c
        .call(json!({"type": "hello", "clientId": client_id, "nonce": nc.to_base64()}))
        .await;
    assert_eq!(challenge["type"], "challenge");
    let wrong_key = PairingKey::generate().unwrap();
    let ns = Nonce::from_base64(challenge["nonce"].as_str().unwrap()).unwrap();
    let proof =
        auth::client_proof(&wrong_key, &ClientId::parse(&client_id).unwrap(), &nc, &ns).unwrap();
    let e = c.call(json!({"type": "auth", "proof": proof})).await;
    assert_eq!(e["code"], "auth_failed");
    assert!(c.closed().await);

    // Replaying an old proof on a new challenge fails as well.
    let mut c = Client::connect(s.dir.path()).await;
    let good = auth::client_proof(
        &PairingKey::from_base64(&key).unwrap(),
        &ClientId::parse(&client_id).unwrap(),
        &nc,
        &ns,
    )
    .unwrap();
    let _ = c
        .call(json!({"type": "hello", "clientId": client_id, "nonce": nc.to_base64()}))
        .await;
    let e = c.call(json!({"type": "auth", "proof": good})).await;
    assert_eq!(e["code"], "auth_failed");

    // Malformed JSON and oversized frames.
    let mut c = Client::connect(s.dir.path()).await;
    write_frame(&mut c.stream, b"{not json").await.unwrap();
    assert_eq!(c.recv().await.unwrap()["code"], "malformed");
    assert!(c.closed().await);
    let mut c = Client::connect(s.dir.path()).await;
    c.stream
        .write_all(&(2_u32 * 1024 * 1024).to_le_bytes())
        .await
        .unwrap();
    assert!(c.closed().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_and_cancelled_pairings() {
    let s = setup().await;
    let mut c = Client::connect(s.dir.path()).await;
    let id = c.send(json!({"type": "pair", "clientName": "Test"})).await;
    assert_eq!(c.reply(id).await["type"], "pairing");
    let request = wait_for_request(&s.ui, 1).await;
    // Other requests wait while the dialog is open.
    let busy = c.call(json!({"type": "status"})).await;
    assert_eq!(busy["code"], "pairing_busy");
    let mut other = Client::connect(s.dir.path()).await;
    let e = other
        .call(json!({"type": "pair", "clientName": "Other"}))
        .await;
    assert_eq!(e["code"], "pairing_busy");
    assert!(s.ctx.broker.decide(request.id, false));
    assert_eq!(c.reply(id).await["code"], "pairing_refused");
    assert_eq!(s.ui.closed.lock().unwrap().as_slice(), &[request.id]);
    // A refusal imposes a delay.
    let e = c.call(json!({"type": "pair", "clientName": "Test"})).await;
    assert_eq!(e["code"], "rate_limited");
    assert!(s.ctx.clients().is_empty());
    assert!(s.ctx.broker.pending().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_server_per_endpoint_and_clean_stop() {
    let mut s = setup().await;
    let e = server::start(Arc::clone(&s.ctx), endpoint(s.dir.path()))
        .await
        .err()
        .unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse);
    let (client_id, key) = pair(&s).await;
    let mut c = Client::connect(s.dir.path()).await;
    assert_eq!(
        authenticate(&mut c, &client_id, &key).await["type"],
        "ready"
    );
    s.server.take().unwrap().stop(&s.ctx);
    assert!(c.closed().await);
    assert!(connect(&endpoint(s.dir.path())).await.is_err());
    #[cfg(unix)]
    {
        assert!(!lk_bridge::endpoint::socket_path(s.dir.path()).exists());
        use std::os::unix::fs::PermissionsExt;
        let dir = lk_bridge::endpoint::socket_dir(s.dir.path());
        assert_eq!(
            std::fs::metadata(dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    // A socket left behind by a crashed instance is replaced.
    let restarted = server::start(Arc::clone(&s.ctx), endpoint(s.dir.path())).await;
    assert!(restarted.is_ok());
}

/// Native messaging frames on the relay's standard streams.
async fn native_write(stdin: &mut tokio::process::ChildStdin, v: &Value) {
    let body = serde_json::to_vec(v).unwrap();
    stdin
        .write_all(&u32::try_from(body.len()).unwrap().to_ne_bytes())
        .await
        .unwrap();
    stdin.write_all(&body).await.unwrap();
    stdin.flush().await.unwrap();
}

async fn native_read(stdout: &mut tokio::process::ChildStdout) -> Value {
    let read = async {
        let mut head = [0_u8; 4];
        stdout.read_exact(&mut head).await.unwrap();
        let mut body = vec![0_u8; u32::from_ne_bytes(head) as usize];
        stdout.read_exact(&mut body).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    };
    tokio::time::timeout(TIMEOUT, read)
        .await
        .expect("relay silent")
}

fn relay_process(dir: &std::path::Path) -> tokio::process::Child {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_last-keys"))
        .arg(format!("chrome-extension://{EXTENSION}/"))
        .env("LK_DESKTOP_DATA_DIR", dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_executable_relays_native_messages() {
    let s = setup().await;
    let (client_id, key) = pair(&s).await;
    let mut child = relay_process(s.dir.path());
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    let pairing_key = PairingKey::from_base64(&key).unwrap();
    let client = ClientId::parse(&client_id).unwrap();
    let nc = Nonce::generate().unwrap();
    native_write(
        &mut stdin,
        &json!({"id": 1, "type": "hello", "clientId": client_id, "nonce": nc.to_base64()}),
    )
    .await;
    let challenge = native_read(&mut stdout).await;
    assert_eq!(challenge["type"], "challenge", "{challenge}");
    let ns = Nonce::from_base64(challenge["nonce"].as_str().unwrap()).unwrap();
    assert!(auth::verify_server_proof(
        &pairing_key,
        &client,
        &nc,
        &ns,
        challenge["proof"].as_str().unwrap()
    ));
    let proof = auth::client_proof(&pairing_key, &client, &nc, &ns).unwrap();
    native_write(
        &mut stdin,
        &json!({"id": 2, "type": "auth", "proof": proof}),
    )
    .await;
    assert_eq!(native_read(&mut stdout).await["type"], "ready");
    native_write(
        &mut stdin,
        &json!({"id": 3, "type": "list", "pageUrl": "https://other.org/"}),
    )
    .await;
    let logins = native_read(&mut stdout).await;
    assert_eq!(logins["logins"][0]["title"], "Other");
    // The relay announced the caller the browser passed.
    assert_eq!(s.ctx.clients()[0].extension, EXTENSION);

    // The browser closes the port: the relay exits.
    drop(stdin);
    let status = tokio::time::timeout(TIMEOUT, child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_reports_a_missing_application() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = relay_process(dir.path());
    let mut stdout = child.stdout.take().unwrap();
    let e = native_read(&mut stdout).await;
    assert_eq!(e["type"], "error");
    assert_eq!(e["code"], "desktop_unavailable");
    let status = tokio::time::timeout(TIMEOUT, child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
}
