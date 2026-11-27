// @vitest-environment node
// Authentication (same vectors as crates/lk-bridge), the session against a
// scripted desktop speaking the bridge protocol, and the router.

import { createHmac, timingSafeEqual } from "node:crypto";
import type { ConnectionState, PageView } from "../shared/messages";
import { clientProof, fromBase64, importPairingKey, toBase64, verifyServerProof } from "./auth";
import type { NativePort } from "./connection";
import { memoryKeyStore } from "./keystore";
import { handleContent, handlePopup, type RouterDeps, type TabsApi } from "./router";
import { Session } from "./session";
import { Frames, Saves, memoryArea, type FrameInfo } from "./state";

const KEY = toBase64(new Uint8Array(32).fill(7));
const CLIENT = "00112233445566778899aabbccddeeff";

describe("authentication", () => {
  it("matches the desktop's known-answer vectors", async () => {
    const key = await importPairingKey(KEY);
    const nc = new Uint8Array(32).fill(1);
    const ns = new Uint8Array(32).fill(2);
    // crates/lk-bridge/src/auth.rs, test `known_answer`.
    expect(await clientProof(key, CLIENT, nc, ns)).toBe("9Nc+NplOA858ruq6QWjCWWCIdZXiMPpgn96XtMVbcyk=");
    expect(await verifyServerProof(key, CLIENT, nc, ns, "ALZwLEYrQEG4xn8nmvNO+Kz+2BYCF1ysL57WaG1mJ+s=")).toBe(true);
    // Swapped nonces, another client, the client's own proof, garbage.
    expect(await verifyServerProof(key, CLIENT, ns, nc, "ALZwLEYrQEG4xn8nmvNO+Kz+2BYCF1ysL57WaG1mJ+s=")).toBe(false);
    expect(await verifyServerProof(key, "ff" + CLIENT.slice(2), nc, ns, "ALZwLEYrQEG4xn8nmvNO+Kz+2BYCF1ysL57WaG1mJ+s=")).toBe(false);
    expect(await verifyServerProof(key, CLIENT, nc, ns, "9Nc+NplOA858ruq6QWjCWWCIdZXiMPpgn96XtMVbcyk=")).toBe(false);
    expect(await verifyServerProof(key, CLIENT, nc, ns, "not base64!")).toBe(false);
  });

  it("refuses keys of the wrong length and makes them non-extractable", async () => {
    await expect(importPairingKey(toBase64(new Uint8Array(31)))).rejects.toThrow();
    const key = await importPairingKey(KEY);
    expect(key.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", key)).rejects.toThrow();
    expect(Array.from(fromBase64(toBase64(new Uint8Array([0, 255, 128]))))).toEqual([0, 255, 128]);
  });
});

/** A scripted desktop behind a native port: the bridge protocol, with
 * HMAC proofs computed by Node (independently of the extension's code). */
class FakeDesktop {
  key = Buffer.from(fromBase64(KEY));
  clientId = CLIENT;
  locked = false;
  paired = true;
  approve: boolean | null = true;
  impostor = false;
  unavailable = false;
  received: Record<string, unknown>[] = [];
  private emit: ((m: unknown) => void) | null = null;
  private disconnect: (() => void) | null = null;
  private serverNonce = Buffer.alloc(0);
  private clientNonce = Buffer.alloc(0);
  responses: Record<string, (m: Record<string, unknown>) => Record<string, unknown>> = {};
  /** Error code to answer to an authenticated request instead of a result. */
  failWith: ((m: Record<string, unknown>) => string | null) | null = null;

  private mac(label: string, a: Buffer, b: Buffer): Buffer {
    return createHmac("sha256", this.key).update(label).update(this.clientId).update(a).update(b).digest();
  }

  port = (): NativePort => ({
    postMessage: (raw: unknown) => {
      const m = raw as Record<string, unknown>;
      this.received.push(m);
      queueMicrotask(() => this.handle(m));
    },
    disconnect: () => {
      this.emit = null;
    },
    onMessage: { addListener: (cb) => (this.emit = cb) },
    onDisconnect: { addListener: (cb) => (this.disconnect = cb) },
  });

  send(m: Record<string, unknown>): void {
    this.emit?.(m);
  }

  drop(): void {
    this.emit = null;
    this.disconnect?.();
  }

  private reply(m: Record<string, unknown>, type: string, body: Record<string, unknown> = {}): void {
    this.send({ id: m.id, type, ...body });
  }

  private handle(m: Record<string, unknown>): void {
    if (this.unavailable) {
      this.send({ id: 0, type: "error", code: "desktop_unavailable" });
      this.drop();
      return;
    }
    switch (m.type) {
      case "hello": {
        if (!this.paired || m.clientId !== this.clientId) return this.reply(m, "error", { code: "unknown_client" });
        this.clientNonce = Buffer.from(fromBase64(String(m.nonce)));
        this.serverNonce = Buffer.alloc(32, 9);
        const proof = this.impostor
          ? Buffer.alloc(32, 1)
          : this.mac("lk-bridge v1 server proof\0", this.clientNonce, this.serverNonce);
        return this.reply(m, "challenge", { nonce: this.serverNonce.toString("base64"), proof: proof.toString("base64") });
      }
      case "auth": {
        const expected = this.mac("lk-bridge v1 client proof\0", this.serverNonce, this.clientNonce);
        const given = Buffer.from(String(m.proof), "base64");
        if (given.length !== 32 || !timingSafeEqual(given, expected)) return this.reply(m, "error", { code: "auth_failed" });
        return this.reply(m, "ready", { locked: this.locked, vaultExists: true, version: "test" });
      }
      case "pair": {
        this.reply(m, "pairing", { code: "K7M-4QX" });
        if (this.approve === true) {
          setTimeout(() => {
            this.paired = true;
            this.reply(m, "paired", { clientId: this.clientId, key: KEY });
          }, 5);
        } else if (this.approve === false) {
          setTimeout(() => this.reply(m, "error", { code: "pairing_refused" }), 5);
        }
        return;
      }
      default: {
        if (this.locked && m.type !== "status" && m.type !== "focus") return this.reply(m, "error", { code: "locked" });
        const code = this.failWith?.(m);
        if (code) return this.reply(m, "error", { code });
        const answer = this.responses[String(m.type)];
        if (answer) return this.reply(m, String(m.type) === "list" ? "logins" : "ok", answer(m));
        return this.reply(m, "ok");
      }
    }
  }
}

async function paired(desktop: FakeDesktop) {
  const keys = memoryKeyStore();
  keys.value = { clientId: CLIENT, key: await importPairingKey(KEY) };
  const states: ConnectionState[] = [];
  const session = new Session({ connect: desktop.port, keys, clientName: "Test", notify: () => states.push(session.current()) });
  return { session, keys, states };
}

const until = async (check: () => boolean) => {
  for (let i = 0; i < 200 && !check(); i += 1) await new Promise((r) => setTimeout(r, 5));
  expect(check()).toBe(true);
};

describe("session", () => {
  it("authenticates mutually and follows the lock state", async () => {
    const desktop = new FakeDesktop();
    const { session } = await paired(desktop);
    expect(await session.ensure()).toEqual({ state: "ready", locked: false });
    expect(desktop.received.map((m) => m.type)).toEqual(["hello", "auth"]);
    desktop.send({ id: 0, type: "event", event: "locked" });
    expect(session.current()).toEqual({ state: "ready", locked: true });
    desktop.send({ id: 0, type: "event", event: "unlocked" });
    expect(session.current()).toEqual({ state: "ready", locked: false });
    // A second ensure() reuses the authenticated connection.
    await session.ensure();
    expect(desktop.received).toHaveLength(2);
  });

  it("never sends its proof to an impostor", async () => {
    const desktop = new FakeDesktop();
    desktop.impostor = true;
    const { session } = await paired(desktop);
    expect(await session.ensure()).toEqual({ state: "unavailable" });
    expect(desktop.received.map((m) => m.type)).toEqual(["hello"]);
  });

  it("forgets a pairing the desktop no longer knows, or revoked", async () => {
    const desktop = new FakeDesktop();
    desktop.paired = false;
    const { session, keys } = await paired(desktop);
    expect(await session.ensure()).toEqual({ state: "unpaired" });
    expect(keys.value).toBeNull();

    const d2 = new FakeDesktop();
    const p2 = await paired(d2);
    await p2.session.ensure();
    d2.send({ id: 0, type: "event", event: "revoked" });
    await until(() => p2.session.current().state === "unpaired");
    expect(p2.keys.value).toBeNull();
  });

  it("pairs: code, approval, then authentication", async () => {
    const desktop = new FakeDesktop();
    desktop.paired = false;
    const keys = memoryKeyStore();
    const session = new Session({ connect: desktop.port, keys, clientName: "Chrome · Linux", notify: () => undefined });
    expect(await session.ensure()).toEqual({ state: "unpaired" });
    expect(await session.pair()).toEqual({ state: "pairing", code: "K7M-4QX" });
    expect(desktop.received[0]).toMatchObject({ type: "pair", clientName: "Chrome · Linux" });
    await until(() => session.current().state === "ready");
    expect(keys.value?.clientId).toBe(CLIENT);
    expect(keys.value?.key.extractable).toBe(false);
  });

  it("tells the popup only of actual changes (no reload loop)", async () => {
    const desktop = new FakeDesktop();
    desktop.paired = false;
    let notified = 0;
    const session = new Session({ connect: desktop.port, keys: memoryKeyStore(), clientName: "x", notify: () => (notified += 1) });
    for (let i = 0; i < 5; i += 1) await session.ensure();
    expect(notified).toBe(1);
    expect(desktop.received).toEqual([]);
  });

  it("keeps the pairing connection while the popup asks for the state", async () => {
    const desktop = new FakeDesktop();
    desktop.paired = false;
    desktop.approve = null; // the user has not answered yet
    const session = new Session({ connect: desktop.port, keys: memoryKeyStore(), clientName: "x", notify: () => undefined });
    await session.ensure();
    const pairing = session.pair();
    // A popup reload asks for the state while the request is in flight.
    expect(await session.ensure()).toEqual({ state: "unpaired" });
    expect(await pairing).toEqual({ state: "pairing", code: "K7M-4QX" });
    expect(await session.ensure()).toEqual({ state: "pairing", code: "K7M-4QX" });
    // The desktop approves later, on the same connection.
    desktop.paired = true;
    desktop.send({ id: 1, type: "paired", clientId: CLIENT, key: KEY });
    await until(() => session.current().state === "ready");
  });

  it("reports a refused pairing and an unreachable application", async () => {
    const desktop = new FakeDesktop();
    desktop.paired = false;
    desktop.approve = false;
    const session = new Session({ connect: desktop.port, keys: memoryKeyStore(), clientName: "x", notify: () => undefined });
    await session.pair();
    await until(() => session.current().state === "unpaired");
    expect(session.current()).toEqual({ state: "unpaired", refused: "refused" });

    const gone = new FakeDesktop();
    gone.unavailable = true;
    const s2 = await paired(gone);
    expect(await s2.session.ensure()).toEqual({ state: "unavailable" });
  });

  it("marks the session locked when a request fails with `locked`", async () => {
    const desktop = new FakeDesktop();
    const { session } = await paired(desktop);
    await session.ensure();
    desktop.locked = true;
    await expect(session.call("list", { pageUrl: "https://a.example/" })).rejects.toMatchObject({ code: "locked" });
    expect(session.current()).toEqual({ state: "ready", locked: true });
  });

  it("reconnects after the application went away", async () => {
    const desktop = new FakeDesktop();
    const { session } = await paired(desktop);
    await session.ensure();
    desktop.drop();
    expect(session.current()).toEqual({ state: "unavailable" });
    expect(await session.ensure()).toEqual({ state: "ready", locked: false });
  });
});

function fakeTabs(urls: Record<number, string>) {
  const sent: { tabId: number; frame: FrameInfo; message: unknown }[] = [];
  const badges: Record<number, boolean> = {};
  const answers: { filled: number }[] = [];
  const prepared: number[] = [];
  const tabs: TabsApi = {
    async url(tabId) {
      return urls[tabId];
    },
    async prepare(tabId) {
      prepared.push(tabId);
      return access.granted;
    },
    async send(tabId, frame, message) {
      sent.push({ tabId, frame, message });
      return answers.shift() ?? { filled: 2 };
    },
    async badge(tabId, on) {
      badges[tabId] = on;
    },
  };
  return { tabs, sent, badges, answers, prepared };
}

const access = { granted: true };

async function router(urls: Record<number, string>) {
  const desktop = new FakeDesktop();
  const { session } = await paired(desktop);
  const store = memoryArea();
  const t = fakeTabs(urls);
  const deps: RouterDeps = { session, frames: new Frames(store), saves: new Saves(store), tabs: t.tabs };
  return { desktop, deps, store, ...t };
}

const LOGIN = { id: "item-1", title: "Example", username: "alice", matched: "exact_host", hasPassword: true, hasTotp: false, favorite: false };

describe("router", () => {
  it("shows the page's logins and form state", async () => {
    const r = await router({ 1: "https://login.example.com/signin", 2: "chrome://settings/" });
    r.desktop.responses.list = (m) => {
      expect(m.pageUrl).toBe("https://login.example.com/signin");
      return { logins: [LOGIN] };
    };
    await handleContent({ kind: "forms", login: true, newPassword: false, otp: false }, { tabId: 1, frameId: 0, url: "https://login.example.com/signin" }, r.deps);
    const view = (await handlePopup({ kind: "page", tabId: 1 }, r.deps)) as { ok: true; value: PageView };
    expect(view.value).toMatchObject({ eligible: true, host: "login.example.com", hasLoginForm: true, internationalized: false, detection: true });
    expect(r.prepared).toEqual([1]);
    expect(view.value.logins).toEqual([LOGIN]);
    const other = (await handlePopup({ kind: "page", tabId: 2 }, r.deps)) as { ok: true; value: PageView };
    expect(other.value.eligible).toBe(false);
    expect(other.value.logins).toEqual([]);
    // Nothing is injected into a page that cannot be filled.
    expect(r.prepared).toEqual([1]);
  });

  it("reports when access to every site is not granted (click-to-fill)", async () => {
    access.granted = false;
    try {
      const r = await router({ 1: "https://example.com/" });
      r.desktop.responses.list = () => ({ logins: [LOGIN] });
      const view = (await handlePopup({ kind: "page", tabId: 1 }, r.deps)) as { ok: true; value: PageView };
      expect(view.value.detection).toBe(false);
      expect(view.value.logins).toEqual([LOGIN]);
      expect(r.prepared).toEqual([1]);
    } finally {
      access.granted = true;
    }
  });

  it("flags internationalized hosts", async () => {
    const r = await router({ 1: "https://xn--pple-43d.com/" });
    r.desktop.responses.list = () => ({ logins: [] });
    const view = (await handlePopup({ kind: "page", tabId: 1 }, r.deps)) as { ok: true; value: PageView };
    expect(view.value.internationalized).toBe(true);
  });

  it("fills the top frame after the desktop's check", async () => {
    const r = await router({ 1: "https://example.com/login" });
    r.desktop.responses.fill = (m) => {
      expect(m).toMatchObject({ itemId: "item-1", pageUrl: "https://example.com/login", frameUrl: "https://example.com/login", crossOriginConfirmed: false });
      return { username: "alice", password: "s3cret", totp: null };
    };
    await handleContent({ kind: "forms", login: true, newPassword: false, otp: false }, { tabId: 1, frameId: 0, url: "https://example.com/login", documentId: "doc-1" }, r.deps);
    const result = await handlePopup({ kind: "fill", tabId: 1, itemId: "item-1" }, r.deps);
    expect(result).toEqual({ ok: true, value: { filled: 2 } });
    expect(r.sent).toHaveLength(1);
    expect(r.sent[0]?.frame.documentId).toBe("doc-1");
    expect(r.sent[0]?.message).toEqual({ kind: "fill", origin: "https://example.com", username: "alice", password: "s3cret", totp: null });
  });

  it("asks for confirmation before filling a frame of another origin", async () => {
    const r = await router({ 1: "https://www.example.com/" });
    // Like lk-client: a frame of another origin needs the user's confirmation.
    r.desktop.failWith = (m) => (m.type === "fill" && !m.crossOriginConfirmed ? "confirmation_required" : null);
    r.desktop.responses.fill = () => ({ username: "alice", password: "s3cret", totp: null });
    await handleContent({ kind: "forms", login: false, newPassword: false, otp: false }, { tabId: 1, frameId: 0, url: "https://www.example.com/" }, r.deps);
    await handleContent({ kind: "forms", login: true, newPassword: false, otp: false }, { tabId: 1, frameId: 7, url: "https://login.example.com/frame" }, r.deps);
    const first = await handlePopup({ kind: "fill", tabId: 1, itemId: "item-1" }, r.deps);
    expect(first).toEqual({ ok: true, value: { confirm: { frameId: 7, frameHost: "login.example.com" } } });
    expect(r.sent).toHaveLength(0);
    const confirmed = await handlePopup({ kind: "fill", tabId: 1, itemId: "item-1", confirmFrame: 7 }, r.deps);
    expect(confirmed).toEqual({ ok: true, value: { filled: 2 } });
    expect(r.sent[0]?.frame.frameId).toBe(7);
    expect(r.sent[0]?.message).toMatchObject({ origin: "https://login.example.com" });
  });

  it("refuses when no frame matches, and on ineligible pages", async () => {
    const r = await router({ 1: "https://evil.example/", 2: "file:///tmp/x.html" });
    r.desktop.failWith = (m) => (m.type === "fill" ? "origin_mismatch" : null);
    await handleContent({ kind: "forms", login: true, newPassword: false, otp: false }, { tabId: 1, frameId: 0, url: "https://evil.example/" }, r.deps);
    await handleContent({ kind: "forms", login: true, newPassword: false, otp: false }, { tabId: 1, frameId: 4, url: "https://evil.example/frame" }, r.deps);
    expect(await handlePopup({ kind: "fill", tabId: 1, itemId: "x" }, r.deps)).toEqual({ ok: false, code: "origin_mismatch" });
    // Both frames were checked; nothing was sent to the page.
    expect(r.desktop.received.filter((m) => m.type === "fill").map((m) => m.frameUrl)).toEqual([
      "https://evil.example/",
      "https://evil.example/frame",
    ]);
    expect(r.sent).toHaveLength(0);
    expect(await handlePopup({ kind: "fill", tabId: 2, itemId: "x" }, r.deps)).toEqual({ ok: false, code: "ineligible_page" });
    expect(await handlePopup({ kind: "copy", tabId: 2, itemId: "x", field: "password" }, r.deps)).toEqual({ ok: false, code: "ineligible_page" });
  });

  it("keeps submitted credentials, proposes, saves and clears", async () => {
    const r = await router({ 1: "https://shop.example.net/register" });
    const saved: Record<string, unknown>[] = [];
    r.desktop.responses.save_check = () => ({ proposal: { action: "new", title: "example.net", url: "https://shop.example.net/" } });
    r.desktop.responses.save = (m) => {
      saved.push(m);
      return { itemId: "new-id" };
    };
    r.desktop.responses.list = () => ({ logins: [] });
    await r.deps.session.ensure();
    await handleContent({ kind: "submitted", username: " carol ", password: "pw" }, { tabId: 1, frameId: 0, url: "https://shop.example.net/register" }, r.deps);
    expect(r.badges[1]).toBe(true);
    const view = (await handlePopup({ kind: "page", tabId: 1 }, r.deps)) as { ok: true; value: PageView };
    expect(view.value.pendingSave).toEqual({
      host: "shop.example.net",
      username: "carol",
      proposal: { action: "new", title: "example.net", url: "https://shop.example.net/" },
    });
    // The password is not in what the popup receives.
    expect(JSON.stringify(view.value)).not.toContain("\"pw\"");
    expect(await handlePopup({ kind: "save", tabId: 1 }, r.deps)).toEqual({ ok: true, value: null });
    expect(saved[0]).toMatchObject({ pageUrl: "https://shop.example.net/register", username: "carol", password: "pw" });
    expect(saved[0]).not.toHaveProperty("updateId");
    expect(r.badges[1]).toBe(false);
    expect(await r.deps.saves.get(1)).toBeNull();
  });

  it("updates an existing login and drops unchanged submissions", async () => {
    const r = await router({ 1: "https://example.com/", 2: "https://example.com/" });
    let proposal: Record<string, unknown> = { action: "update_password", id: "item-1", title: "Example" };
    const saved: Record<string, unknown>[] = [];
    r.desktop.responses.save_check = () => ({ proposal });
    r.desktop.responses.save = (m) => {
      saved.push(m);
      return {};
    };
    await r.deps.session.ensure();
    await handleContent({ kind: "submitted", username: "alice", password: "new" }, { tabId: 1, frameId: 0, url: "https://example.com/" }, r.deps);
    await handlePopup({ kind: "save", tabId: 1 }, r.deps);
    expect(saved[0]).toMatchObject({ updateId: "item-1", password: "new" });
    proposal = { action: "unchanged", id: "item-1" };
    await handleContent({ kind: "submitted", username: "alice", password: "same" }, { tabId: 2, frameId: 0, url: "https://example.com/" }, r.deps);
    expect(await r.deps.saves.get(2)).toBeNull();
    expect(r.badges[2]).toBe(false);
  });

  it("keeps a submission made while locked until the popup can ask", async () => {
    const r = await router({ 1: "https://example.com/" });
    await r.deps.session.ensure();
    r.desktop.locked = true;
    r.desktop.send({ id: 0, type: "event", event: "locked" });
    await handleContent({ kind: "submitted", username: "alice", password: "pw" }, { tabId: 1, frameId: 0, url: "https://example.com/" }, r.deps);
    expect((await r.deps.saves.get(1))?.proposal).toBeNull();
    expect(r.badges[1]).toBe(true);
    r.desktop.locked = false;
    r.desktop.send({ id: 0, type: "event", event: "unlocked" });
    r.desktop.responses.list = () => ({ logins: [] });
    r.desktop.responses.save_check = () => ({ proposal: { action: "new", title: "example.com", url: "https://example.com/" } });
    const view = (await handlePopup({ kind: "page", tabId: 1 }, r.deps)) as { ok: true; value: PageView };
    expect(view.value.pendingSave?.proposal).toEqual({ action: "new", title: "example.com", url: "https://example.com/" });
  });

  it("keeps every frame when frames report at the same moment", async () => {
    // A store whose operations take time, like the browser's session storage.
    const slow = memoryArea();
    const delayed = {
      get: async <T,>(k: string) => {
        await new Promise((r) => setTimeout(r, 5));
        return slow.get<T>(k);
      },
      set: async (k: string, v: unknown) => {
        await new Promise((r) => setTimeout(r, 5));
        return slow.set(k, v);
      },
      remove: (k: string) => slow.remove(k),
    };
    const frames = new Frames(delayed);
    await Promise.all(
      [0, 3, 7].map((frameId) =>
        frames.update(1, { frameId, url: `https://a.example/${frameId}`, login: true, newPassword: false, otp: false }),
      ),
    );
    expect((await frames.list(1)).map((f) => f.frameId)).toEqual([0, 3, 7]);
  });

  it("expires submissions after five minutes and ignores ineligible senders", async () => {
    let now = 1_000_000;
    const store = memoryArea();
    const saves = new Saves(store, () => now);
    await saves.put(1, { url: "https://a.example/", username: null, password: "x", proposal: null, at: now });
    now += 5 * 60_000 + 1;
    expect(await saves.get(1)).toBeNull();

    const r = await router({ 1: "https://example.com/" });
    await handleContent({ kind: "submitted", username: null, password: "x" }, { tabId: 1, frameId: 0, url: "file:///x" }, r.deps);
    await handleContent({ kind: "forms", login: true, newPassword: false, otp: false }, { tabId: 1, frameId: 0, url: "about:blank" }, r.deps);
    expect(r.store.data.size).toBe(0);
  });

  it("fills a generated password only into frames of the page's origin", async () => {
    const r = await router({ 1: "https://example.com/signup" });
    await handleContent({ kind: "forms", login: false, newPassword: true, otp: false }, { tabId: 1, frameId: 0, url: "https://example.com/signup" }, r.deps);
    await handleContent({ kind: "forms", login: false, newPassword: true, otp: false }, { tabId: 1, frameId: 3, url: "https://ads.other.net/frame" }, r.deps);
    const result = await handlePopup({ kind: "fillGenerated", tabId: 1, password: "G3n" }, r.deps);
    expect(result).toEqual({ ok: true, value: { filled: 2 } });
    expect(r.sent.map((s) => s.frame.frameId)).toEqual([0]);
    expect(r.sent[0]?.message).toEqual({ kind: "fillNewPassword", origin: "https://example.com", password: "G3n" });
  });
});
