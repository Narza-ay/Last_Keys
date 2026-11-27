// End-to-end test of autofill with REAL components (Linux): the desktop
// application driven through WebDriver (tauri-driver + WebKitWebDriver), a
// Chromium browser with the built extension (Playwright), and the native
// messaging host registered by the application itself. Nothing is mocked:
// the browser starts the relay (the desktop executable), which connects to
// the running application.
//
//   (cd ../desktop && npx tauri build --debug --no-bundle)
//   LK_EXTENSION_E2E=1 npm run build
//   xvfb-run -a node e2e/run.mjs
//
// Environment: LK_APP (application binary), TAURI_DRIVER (tauri-driver path),
// LK_E2E_SCREENSHOTS (optional directory for screenshots).

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const here = dirname(fileURLToPath(import.meta.url));
const app = resolve(process.env.LK_APP ?? join(here, "../../../target/debug/last-keys"));
// The Chromium build with access to every site granted (scripts/build.mjs).
const extension = resolve(here, "../dist/chrome-e2e");
const driverBin = process.env.TAURI_DRIVER ?? "tauri-driver";
const EXTENSION_ID = "bblheiicocdmmkjnhdeehaedddgcfhok";
// Not the desktop test's ports (4444, and 4445 for the native driver).
const DRIVER_PORT = 4446;
const NATIVE_PORT = 4447;
const BASE = `http://127.0.0.1:${DRIVER_PORT}`;
const ELEMENT = "element-6066-11e4-a52e-4f735466cecf";
const MASTER = "a long master passphrase for e2e";
const SITE_PASSWORD = "site-pass-Q8w2";
const screenshots = process.env.LK_E2E_SCREENSHOTS;

if (!existsSync(app)) throw new Error(`application not found: ${app}`);
if (!existsSync(join(extension, "manifest.json"))) throw new Error("build the extension first (LK_EXTENSION_E2E=1 npm run build)");
if (screenshots) mkdirSync(screenshots, { recursive: true });

// An isolated user: home directory (browser profiles, native host
// manifests) and application data directory.
const root = mkdtempSync(join(tmpdir(), "lk-extension-e2e-"));
const home = join(root, "home");
const dataDir = join(root, "data");
const profile = join(home, ".config", "chromium");
mkdirSync(profile, { recursive: true });
mkdirSync(dataDir, { recursive: true });
writeFileSync(join(dataDir, "settings.json"), JSON.stringify({ language: "en", theme: "light" }));
const env = { ...process.env, HOME: home, LK_DESKTOP_DATA_DIR: dataDir };
delete env.XDG_CONFIG_HOME;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------ web pages

const PAGES = {
  "/login": `<!doctype html><title>Sign in</title>
    <form action="/welcome"><label>E-mail <input type="email" name="email" id="email"></label>
    <label>Password <input type="password" name="password" id="password"></label>
    <button type="submit">Sign in</button></form>`,
  "/signup": `<!doctype html><title>Create an account</title>
    <form action="/welcome"><label>E-mail <input type="email" name="email" id="email" autocomplete="username"></label>
    <label>Password <input type="password" id="new" autocomplete="new-password"></label>
    <label>Confirm <input type="password" id="confirm" autocomplete="new-password"></label>
    <button type="submit" id="create">Create account</button></form>`,
  "/embed": `<!doctype html><title>Embedded login</title><h1>Shop</h1>
    <iframe id="frame" width="420" height="220" src="http://login.site.test:PORT/frame"></iframe>`,
  "/frame": `<!doctype html><form><input type="text" name="username" id="username">
    <input type="password" id="password"><button type="submit">Log in</button></form>`,
  "/welcome": `<!doctype html><title>Welcome</title><p>Welcome</p>`,
};

const web = createServer((req, res) => {
  const path = new URL(req.url ?? "/", "http://x").pathname;
  const body = PAGES[path];
  res.writeHead(body ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
  res.end(body ? body.replaceAll("PORT", String(web.address().port)) : "not found");
});
await new Promise((r) => web.listen(0, "127.0.0.1", r));
const PORT = web.address().port;
const url = (host, path) => `http://${host}:${PORT}${path}`;

// ------------------------------------------------- desktop via WebDriver

const driver = spawn(driverBin, ["--port", String(DRIVER_PORT), "--native-port", String(NATIVE_PORT)], {
  env,
  stdio: ["ignore", "inherit", "inherit"],
});

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

class Desktop {
  static async start() {
    const value = await call("POST", "/session", {
      capabilities: { alwaysMatch: { "tauri:options": { application: app } } },
    });
    return new Desktop(value.sessionId);
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
      if (Date.now() > until) throw new Error(`desktop: not found: ${xpath}`);
      await sleep(200);
    }
  }
  async click(xpath, timeout) {
    await call("POST", `/session/${this.id}/element/${await this.find(xpath, timeout)}/click`, {});
  }
  async type(xpath, text) {
    const el = await this.find(xpath);
    await call("POST", `/session/${this.id}/element/${el}/clear`, {});
    await call("POST", `/session/${this.id}/element/${el}/value`, { text });
  }
  async text(xpath, timeout = 20_000) {
    const until = Date.now() + timeout;
    for (;;) {
      const value = await call("GET", `/session/${this.id}/element/${await this.find(xpath, timeout)}/text`);
      if (value.trim() || Date.now() > until) return value;
      await sleep(200);
    }
  }
  async screenshot(name) {
    if (!screenshots) return;
    const png = await call("GET", `/session/${this.id}/screenshot`);
    writeFileSync(join(screenshots, `${name}.png`), Buffer.from(png, "base64"));
  }
}

const button = (label) =>
  `//button[normalize-space(.)='${label}' or @aria-label='${label}' or @title='${label}']`;
const input = (label) => `//label[normalize-space(.)='${label}']/following::input[1]`;

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

function expectEqual(actual, expected, what) {
  if (actual !== expected) throw new Error(`${what}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

let context;
let desktop;
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
  console.log("Autofill end-to-end test (desktop application + Chromium + extension)");
  desktop = await Desktop.start();

  await step("desktop: create a vault and add a login for the test site", async () => {
    await desktop.click("//button[contains(., 'Create a new vault')]");
    await desktop.type(input("Master password"), MASTER);
    await desktop.type(input("Confirm the master password"), MASTER);
    await desktop.click(button("Create my vault"));
    await desktop.text("//*[@data-testid='recovery-key']", 60_000);
    await desktop.click("//label[contains(., 'I have stored my recovery key')]/input");
    await desktop.click(button("Open my vault"));
    await desktop.click(button("New item"));
    await desktop.click("//main//button[starts-with(normalize-space(.), 'Login')]");
    await desktop.type(input("Title"), "Test site");
    await desktop.type(input("Username"), "alice@site.test");
    await desktop.type(input("Password"), SITE_PASSWORD);
    await desktop.type(input("Website"), url("site.test", "/"));
    await desktop.click(button("Save"));
    await desktop.find("//h2[normalize-space(.)='Test site']");
  });

  await step("desktop: turn on browser integration (registers the native host)", async () => {
    await desktop.click(button("Settings"));
    await desktop.click("//label[contains(@class,'toggle')][.//span[normalize-space(.)='Off']]");
    await desktop.find("//label[contains(@class,'toggle')][.//span[normalize-space(.)='On']]");
    await desktop.find("//ul[@aria-label='Browsers']/li[contains(., 'Chromium')][contains(., 'Ready')]");
    const manifest = JSON.parse(
      readFileSync(join(profile, "NativeMessagingHosts", "app.lastkeys.bridge.json"), "utf8"),
    );
    expectEqual(manifest.path, app, "host path");
    expectEqual(manifest.allowed_origins[0], `chrome-extension://${EXTENSION_ID}/`, "allowed origin");
    await desktop.screenshot("desktop-browser-settings");
  });

  context = await chromium.launchPersistentContext(profile, {
    headless: false,
    env,
    viewport: { width: 1000, height: 760 },
    args: [
      `--disable-extensions-except=${extension}`,
      `--load-extension=${extension}`,
      "--host-resolver-rules=MAP *.test 127.0.0.1",
      "--no-first-run",
    ],
  });
  let [worker] = context.serviceWorkers();
  worker ??= await context.waitForEvent("serviceworker", { timeout: 20_000 });
  if (process.env.LK_E2E_DEBUG) worker.on("console", (m) => console.log(`    [worker] ${m.text()}`));

  const tabId = async (page) => {
    const target = page.url();
    const tabs = await worker.evaluate(async () => (await chrome.tabs.query({})).map((t) => ({ id: t.id, url: t.url })));
    const tab = tabs.find((t) => t.url === target);
    if (!tab) throw new Error(`tab not found for ${target}`);
    return tab.id;
  };
  const popupFor = async (page) => {
    const popup = await context.newPage();
    popup.on("console", (m) => process.env.LK_E2E_DEBUG && console.log(`    [popup] ${m.text()}`));
    await popup.goto(`chrome-extension://${EXTENSION_ID}/popup.html?tab=${await tabId(page)}`);
    if (process.env.LK_E2E_DEBUG) {
      await sleep(1500);
      console.log(`    [popup text] ${(await popup.locator("body").innerText()).replaceAll("\n", " | ")}`);
    }
    return popup;
  };

  await step("the extension loads with the ID the native host allows", async () => {
    expectEqual(new URL(worker.url()).host, EXTENSION_ID, "extension ID");
  });

  const site = await context.newPage();
  await site.goto(url("site.test", "/login"));

  await step("pairing: the same code in the popup and in the desktop, approved there", async () => {
    const popup = await popupFor(site);
    await popup.getByRole("button", { name: "Connect" }).click();
    if (process.env.LK_E2E_DEBUG) {
      await sleep(3000);
      console.log(`    [popup after connect] ${(await popup.locator("body").innerText()).replaceAll("\n", " | ")}`);
    }
    const code = (await popup.getByTestId("pairing-code").textContent({ timeout: 20_000 })).trim();
    if (!/^[3-9A-Z]{3}-[3-9A-Z]{3}$/.test(code)) throw new Error(`unexpected code ${code}`);
    await desktop.find(`//*[@role='dialog'][contains(., 'Connect a browser extension?')][contains(., '${code}')]`);
    await desktop.screenshot("desktop-pairing");
    await desktop.click("//*[@role='dialog']//button[normalize-space(.)='Connect']");
    await popup.getByText("Test site").waitFor({ timeout: 20_000 });
    await desktop.find("//ul[@aria-label='Connected extensions']/li[contains(., 'Chrome · Linux') or contains(., 'Chromium')]");
    if (screenshots) await popup.screenshot({ path: join(screenshots, "popup-logins.png") });
    await popup.close();
  });

  await step("fill: the desktop's login goes into the page", async () => {
    const popup = await popupFor(site);
    await popup.getByRole("button", { name: "Fill" }).first().click();
    await site.waitForFunction(() => document.querySelector("#password")?.value.length > 0, null, { timeout: 10_000 });
    expectEqual(await site.inputValue("#email"), "alice@site.test", "username");
    expectEqual(await site.inputValue("#password"), SITE_PASSWORD, "password");
    if (!popup.isClosed()) await popup.close();
  });

  await step("another site gets nothing (no matching login is offered)", async () => {
    const evil = await context.newPage();
    await evil.goto(url("evil.test", "/login"));
    const popup = await popupFor(evil);
    await popup.getByText("No login saved for this site.").waitFor({ timeout: 10_000 });
    if (await popup.getByText("Test site").count()) throw new Error("the login was offered on another site");
    await popup.close();
    expectEqual(await evil.inputValue("#password"), "", "password on another site");
    await evil.close();
  });

  await step("an embedded form of another origin is filled only after confirmation", async () => {
    const embed = await context.newPage();
    await embed.goto(url("site.test", "/embed"));
    const frame = embed.frameLocator("#frame");
    await frame.locator("#password").waitFor();
    await sleep(800); // the frame's content script reports its form
    const popup = await popupFor(embed);
    await popup.getByRole("button", { name: "Fill" }).first().click();
    const dialog = popup.getByRole("alertdialog", { name: "Fill an embedded form?" });
    await dialog.waitFor({ timeout: 10_000 });
    if (!(await dialog.textContent()).includes("login.site.test")) throw new Error("the frame's host is not shown");
    expectEqual(await frame.locator("#password").inputValue(), "", "frame before confirmation");
    await dialog.getByRole("button", { name: "Fill anyway" }).click();
    const inner = embed.frames().find((f) => f.url().includes("login.site.test"));
    await inner.waitForFunction(() => document.querySelector("#password")?.value.length > 0, null, { timeout: 10_000 });
    expectEqual(await frame.locator("#username").inputValue(), "alice@site.test", "frame username");
    expectEqual(await frame.locator("#password").inputValue(), SITE_PASSWORD, "frame password");
    if (!popup.isClosed()) await popup.close();
    await embed.close();
  });

  await step("generate: a desktop-generated password fills the new-password fields", async () => {
    const signup = await context.newPage();
    await signup.goto(url("site.test", "/signup"));
    await sleep(800);
    const popup = await popupFor(signup);
    await popup.getByRole("button", { name: "Generate a password" }).click();
    const generated = (await popup.getByTestId("generated").textContent({ timeout: 10_000 })).trim();
    expectEqual(generated.length, 20, "generated length");
    await popup.locator(".generator").getByRole("button", { name: "Fill" }).click();
    await signup.waitForFunction(() => document.querySelector("#new")?.value.length > 0, null, { timeout: 10_000 });
    expectEqual(await signup.inputValue("#new"), generated, "new password");
    expectEqual(await signup.inputValue("#confirm"), generated, "confirmation");
    if (!popup.isClosed()) await popup.close();
    await signup.close();
  });

  await step("save: submitted credentials are proposed, then saved in the desktop vault", async () => {
    const page = await context.newPage();
    await page.goto(url("shop.test", "/signup"));
    await page.fill("#email", "carol@shop.test");
    await page.fill("#new", "carol-Pass-77");
    await page.fill("#confirm", "carol-Pass-77");
    await page.click("#create");
    await page.waitForURL(/\/welcome/);
    const popup = await popupFor(page);
    await popup.getByText("Save this login?").waitFor({ timeout: 10_000 });
    await popup.getByText("carol@shop.test").waitFor();
    await popup.getByRole("button", { name: "Save", exact: true }).click();
    await popup.getByText("Saved in Last Keys.").waitFor({ timeout: 10_000 });
    await popup.getByText("shop.test").first().waitFor();
    await popup.close();
    await desktop.click(button("All items"));
    await desktop.find("//li[@role='option'][contains(., 'shop.test')]", 20_000);
    await page.close();
  });

  await step("lock: the popup follows the desktop and never asks for the master password", async () => {
    await desktop.click(button("Lock"));
    const popup = await popupFor(site);
    await popup.getByText("Last Keys is locked").waitFor({ timeout: 10_000 });
    expectEqual(await popup.locator("input").count(), 0, "inputs in the popup");
    await desktop.type(input("Master password"), MASTER);
    await desktop.click(button("Unlock"));
    await popup.getByText("Test site").waitFor({ timeout: 30_000 });
    await popup.close();
  });

  await step("revocation in the desktop disconnects the extension", async () => {
    await desktop.click(button("Settings"));
    await desktop.click("//ul[@aria-label='Connected extensions']//button[normalize-space(.)='Remove']");
    await desktop.find("//*[contains(., 'The extension was removed.')]");
    const popup = await popupFor(site);
    await popup.getByRole("button", { name: "Connect" }).waitFor({ timeout: 10_000 });
    await popup.close();
  });

  await step("the vault files on disk contain none of the secrets", async () => {
    for (const file of ["vault.lkvault", "vault.lkvault-wal"]) {
      const path = join(dataDir, file);
      if (!existsSync(path)) continue;
      const bytes = readFileSync(path);
      for (const secret of [SITE_PASSWORD, "carol-Pass-77", "alice@site.test"]) {
        if (bytes.includes(Buffer.from(secret))) throw new Error(`"${secret}" found in ${file}`);
      }
    }
  });
} finally {
  await context?.close().catch(() => undefined);
  await desktop?.end().catch(() => undefined);
  driver.kill();
  web.close();
  spawnSync("pkill", ["-f", "WebKitWebDriver"]);
  rmSync(root, { recursive: true, force: true });
}

if (failures > 0) process.exit(1);
console.log("All autofill end-to-end steps passed");
process.exit(0);
