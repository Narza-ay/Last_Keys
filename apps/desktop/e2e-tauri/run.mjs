// End-to-end test of the REAL desktop application (Rust back end + UI) on
// Linux, through WebDriver (tauri-driver + WebKitWebDriver). No dependency:
// a minimal W3C WebDriver client over fetch.
//
//   npx tauri build --debug --no-bundle
//   xvfb-run -a node e2e-tauri/run.mjs
//
// Environment: LK_APP (application binary), TAURI_DRIVER (tauri-driver path),
// LK_E2E_SERVER (optional URL of a running lk-server: registration,
// synchronization and device list are then tested against it).

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const app = process.env.LK_APP ?? resolve(here, "../../../target/debug/last-keys");
const driverBin = process.env.TAURI_DRIVER ?? "tauri-driver";
const PORT = 4444;
const BASE = `http://127.0.0.1:${PORT}`;
const ELEMENT = "element-6066-11e4-a52e-4f735466cecf"; // W3C WebDriver element key
const MASTER = "a long master passphrase for e2e";
const CANARY = "e2e-canary-password-7Hq2";
const SERVER = process.env.LK_E2E_SERVER;
const EMAIL = `desktop-e2e-${Date.now()}@example.com`;
let recoveryKey = "";

if (!existsSync(app)) throw new Error(`application not found: ${app}`);
const dataDir = mkdtempSync(join(tmpdir(), "lk-desktop-e2e-"));
// Short clipboard delay so that the automatic clearing can be observed.
writeFileSync(
  join(dataDir, "settings.json"),
  JSON.stringify({ language: "en", theme: "light", clipboardClearSeconds: 10 }),
);
const screenshots = process.env.LK_E2E_SCREENSHOTS;
if (screenshots) mkdirSync(screenshots, { recursive: true });

/** Text on the X11 clipboard (xclip), or "" when it is empty. */
function clipboard() {
  const r = spawnSync("xclip", ["-o", "-selection", "clipboard"], { encoding: "utf8", timeout: 5000 });
  return r.status === 0 ? r.stdout : "";
}

const driver = spawn(driverBin, ["--port", String(PORT)], {
  env: { ...process.env, LK_DESKTOP_DATA_DIR: dataDir },
  stdio: ["ignore", "inherit", "inherit"],
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function call(method, path, body) {
  const res = await fetch(BASE + path, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(`${method} ${path}: ${JSON.stringify(json.value)}`);
  return json.value;
}

class Session {
  static async start() {
    const value = await call("POST", "/session", {
      capabilities: { alwaysMatch: { "tauri:options": { application: app } } },
    });
    const s = new Session(value.sessionId);
    await call("POST", `/session/${s.id}/timeouts`, { implicit: 0 });
    return s;
  }
  constructor(id) {
    this.id = id;
  }
  async end() {
    await call("DELETE", `/session/${this.id}`);
  }
  async find(xpath, timeout = 20_000) {
    const until = Date.now() + timeout;
    for (;;) {
      const found = await call("POST", `/session/${this.id}/elements`, { using: "xpath", value: xpath });
      if (found.length) return found[0][ELEMENT];
      if (Date.now() > until) throw new Error(`not found: ${xpath}`);
      await sleep(200);
    }
  }
  async absent(xpath) {
    const found = await call("POST", `/session/${this.id}/elements`, { using: "xpath", value: xpath });
    return found.length === 0;
  }
  async click(xpath) {
    await call("POST", `/session/${this.id}/element/${await this.find(xpath)}/click`, {});
  }
  async type(xpath, text) {
    const el = await this.find(xpath);
    await call("POST", `/session/${this.id}/element/${el}/clear`, {});
    await call("POST", `/session/${this.id}/element/${el}/value`, { text });
  }
  /** Rendered text; waits for it to be non-empty (entry animations start
   * at opacity 0, which WebDriver reports as no text). */
  async screenshot(name) {
    if (!screenshots) return;
    const png = await call("GET", `/session/${this.id}/screenshot`);
    writeFileSync(join(screenshots, `${name}.png`), Buffer.from(png, "base64"));
  }
  async text(xpath, timeout = 20_000) {
    const until = Date.now() + timeout;
    for (;;) {
      const value = await call("GET", `/session/${this.id}/element/${await this.find(xpath, timeout)}/text`);
      if (value.trim() || Date.now() > until) return value;
      await sleep(200);
    }
  }
}

const button = (label) =>
  `//button[normalize-space(.)='${label}' or @aria-label='${label}' or @title='${label}']`;
const input = (label) => `//label[normalize-space(.)='${label}']/following::input[1]`;
const heading = (text) => `//h2[normalize-space(.)='${text}']`;

let failures = 0;
async function step(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failures += 1;
    console.log(`  ✗ ${name}\n    ${e.message}`);
    throw e;
  }
}

try {
  for (let i = 0; ; i++) {
    try {
      await call("GET", "/status");
      break;
    } catch {
      if (i > 50) throw new Error("tauri-driver did not start");
      await sleep(200);
    }
  }
  console.log("Real application end-to-end test");
  let s = await Session.start();

  await step("onboarding: create a vault (Argon2id in Rust)", async () => {
    await s.click("//button[contains(., 'Create a new vault')]");
    await s.type(input("Master password"), MASTER);
    await s.type(input("Confirm the master password"), MASTER);
    await s.click(button("Create my vault"));
    const key = await s.text("//*[@data-testid='recovery-key']", 60_000);
    if (!/^LK1(-[0-9A-Z]{4}){14}$/.test(key.trim())) throw new Error(`unexpected recovery key format: ${key}`);
    recoveryKey = key.trim();
  });

  await step("recovery key acknowledged, empty vault opens", async () => {
    await s.click("//label[contains(., 'I have stored my recovery key')]/input");
    await s.click(button("Open my vault"));
    await s.find("//*[normalize-space(.)='Nothing here yet']");
  });

  await step("add a login through the editor", async () => {
    await s.click(button("New item"));
    await s.click("//main//button[starts-with(normalize-space(.), 'Login')]");
    await s.type(input("Title"), "Forum");
    await s.type(input("Username"), "alice");
    await s.type(input("Password"), CANARY);
    await s.type(input("Website"), "forum.example.org");
    await s.click(button("Save"));
    await s.find(heading("Forum"));
    await s.find("//*[normalize-space(.)='https://forum.example.org/']");
    if (!(await s.absent(`//*[contains(text(), '${CANARY}')]`))) throw new Error("password shown without a reveal");
  });

  await step("reveal fetches the secret from Rust", async () => {
    await s.click(button("Reveal"));
    await s.find(`//*[normalize-space(.)='${CANARY}']`);
  });

  await step("copy goes from Rust to the clipboard, which is cleared after the delay", async () => {
    await s.screenshot("real-app-item");
    await s.click("(//button[@aria-label='Copy'])[2]");
    await s.find("//*[contains(., 'The clipboard will be cleared in 10 s')]");
    const deadline = Date.now() + 5000;
    while (clipboard() !== CANARY) {
      if (Date.now() > deadline) throw new Error(`clipboard holds "${clipboard()}"`);
      await sleep(200);
    }
    await sleep(11_500);
    const after = clipboard();
    if (after === CANARY) throw new Error("the clipboard was not cleared");
  });

  if (SERVER) {
    await step("register on a real server and synchronize", async () => {
      await s.click(button("Settings"));
      await s.type(input("Server"), SERVER);
      await s.type(input("E-mail"), EMAIL);
      await s.type(input("Recovery key"), recoveryKey);
      await s.click(button("Register and synchronize"));
      await s.find("//*[normalize-space(.)='Registered. 1 item sent.']", 60_000);
      await s.find("//*[contains(normalize-space(.), 'Synchronized at')]", 30_000);
    });

    await step("devices come from the server, verified with the account key", async () => {
      await s.click(button("Devices"));
      await s.find("//*[contains(@class,'device-name')][contains(., 'This device')]", 30_000);
      await s.click(button("All items"));
    });
  } else {
    console.log("  - server steps skipped (LK_E2E_SERVER not set)");
  }

  await step("the vault files on disk (database, WAL) contain no plaintext", async () => {
    const files = readdirSync(dataDir).filter((f) => f.startsWith("vault.lkvault"));
    if (!files.includes("vault.lkvault")) throw new Error(`vault file missing: ${files}`);
    for (const file of files) {
      const bytes = readFileSync(join(dataDir, file));
      for (const secret of [CANARY, "alice", "forum.example.org", MASTER]) {
        if (bytes.includes(Buffer.from(secret))) throw new Error(`"${secret}" found in ${file}`);
      }
    }
  });

  await step("lock; wrong password refused; unlock", async () => {
    await s.click(button("Lock"));
    await s.type(input("Master password"), "not the master password");
    await s.click(button("Unlock"));
    await s.find("//*[normalize-space(.)='Wrong master password or recovery key.']", 30_000);
    await s.type(input("Master password"), MASTER);
    await s.click(button("Unlock"));
    await s.find("//li[@role='option'][contains(., 'Forum')]", 30_000);
  });

  await step("generator produces a password in Rust", async () => {
    await s.click(button("Generator"));
    // The value replaces "…" once Rust answers (after a running sync).
    let value = "";
    for (const until = Date.now() + 30_000; Date.now() < until; await sleep(250)) {
      value = (await s.text("//*[@data-testid='generated']")).trim();
      if (value !== "…") break;
    }
    if (value.length !== 20) throw new Error(`unexpected generated value: ${value}`);
    await s.screenshot("real-app-generator");
  });

  await s.end();
  s = await Session.start();

  await step("after a restart the vault is locked and the item persists", async () => {
    await s.find("//h1[normalize-space(.)='Welcome back']", 30_000);
    await s.type(input("Master password"), MASTER);
    await s.click(button("Unlock"));
    await s.click("//li[@role='option'][contains(., 'Forum')]", 30_000);
    await s.find(heading("Forum"));
    if (SERVER) await s.find("//*[contains(normalize-space(.), 'Synchronized at')]", 30_000);
  });

  await step("settings are persisted by Rust", async () => {
    await s.click(button("Settings"));
    await s.click(button("Dark"));
    await sleep(500);
    const saved = JSON.parse(readFileSync(join(dataDir, "settings.json"), "utf8"));
    if (saved.theme !== "dark") throw new Error(`settings.json not updated: ${JSON.stringify(saved)}`);
    await s.screenshot("real-app-settings-dark");
  });

  await s.end();
  console.log(failures ? `FAILED (${failures})` : "REAL APP E2E PASSED");
} catch (e) {
  if (!failures) console.log(`ERROR: ${e.message}`);
  process.exitCode = 1;
} finally {
  driver.kill();
  rmSync(dataDir, { recursive: true, force: true });
}
