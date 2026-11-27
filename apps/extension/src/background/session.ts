// The extension's session with the desktop: pairing, mutual
// authentication on every connection, lock state and revocation.

import type { ConnectionState } from "../shared/messages";
import { clientProof, fromBase64, importPairingKey, newNonce, toBase64, verifyServerProof } from "./auth";
import { BridgeError, DesktopConnection, type Message, type NativePort } from "./connection";
import type { KeyStore } from "./keystore";

export interface SessionDeps {
  connect: () => NativePort;
  keys: KeyStore;
  /** Name shown in the desktop's pairing dialog. */
  clientName: string;
  /** Called whenever the state changes (to refresh an open popup). */
  notify: () => void;
}

export class Session {
  private conn: DesktopConnection | null = null;
  private state: ConnectionState = { state: "unavailable" };
  private connecting: Promise<ConnectionState> | null = null;
  private pairId = 0;
  private pairingInProgress = false;

  constructor(private readonly deps: SessionDeps) {}

  current(): ConnectionState {
    return this.state;
  }

  /** Changes the state; an open popup is told only of actual changes (it
   * reloads, which asks for the state again). */
  private set(state: ConnectionState): ConnectionState {
    const changed = JSON.stringify(state) !== JSON.stringify(this.state);
    this.state = state;
    if (changed) this.deps.notify();
    return state;
  }

  private open(): DesktopConnection {
    if (this.conn?.isOpen) return this.conn;
    const conn = new DesktopConnection(this.deps.connect);
    conn.onMessage((m) => void this.onMessage(conn, m));
    conn.onClose(() => {
      if (this.conn !== conn) return;
      this.conn = null;
      if (this.state.state === "ready" || this.state.state === "pairing") this.set({ state: "unavailable" });
    });
    this.conn = conn;
    conn.start();
    return conn;
  }

  /** Connects and authenticates if paired; returns the resulting state. */
  ensure(): Promise<ConnectionState> {
    if (this.conn?.isOpen && (this.state.state === "ready" || this.state.state === "pairing")) {
      return Promise.resolve(this.state);
    }
    return this.reauthenticate();
  }

  private reauthenticate(): Promise<ConnectionState> {
    if (!this.connecting) {
      this.connecting = this.authenticate().finally(() => {
        this.connecting = null;
      });
    }
    return this.connecting;
  }

  private async authenticate(): Promise<ConnectionState> {
    const pairing = await this.deps.keys.load();
    if (!pairing) {
      // Leave a pairing in progress (and its connection) alone, and keep
      // the reason of a refused pairing.
      if (this.pairingInProgress || this.state.state === "pairing" || this.state.state === "unpaired") {
        return this.state;
      }
      return this.set({ state: "unpaired" });
    }
    const conn = this.open();
    const clientNonce = newNonce();
    try {
      const challenge = await conn.request("hello", {
        clientId: pairing.clientId,
        nonce: toBase64(clientNonce),
      });
      const serverNonce = fromBase64(String(challenge.nonce));
      const genuine = await verifyServerProof(
        pairing.key,
        pairing.clientId,
        clientNonce,
        serverNonce,
        String(challenge.proof),
      );
      if (!genuine) {
        // Not our desktop (or a corrupted key): never send our proof.
        conn.close();
        return this.set({ state: "unavailable" });
      }
      const proof = await clientProof(pairing.key, pairing.clientId, clientNonce, serverNonce);
      const ready = await conn.request("auth", { proof });
      return this.set({ state: "ready", locked: ready.locked === true });
    } catch (e) {
      if (e instanceof BridgeError && e.code === "unknown_client") {
        await this.deps.keys.clear();
        return this.set({ state: "unpaired" });
      }
      conn.close();
      return this.set({ state: "unavailable" });
    }
  }

  /** Starts pairing; the state becomes `pairing` with the code to compare. */
  async pair(): Promise<ConnectionState> {
    this.conn?.close();
    this.pairingInProgress = true;
    const conn = this.open();
    this.pairId = conn.nextId;
    try {
      const answer = await conn.request("pair", { clientName: this.deps.clientName });
      return this.set({ state: "pairing", code: String(answer.code) });
    } catch (e) {
      const code = e instanceof BridgeError ? e.code : "internal";
      if (code === "pairing_busy") return this.set({ state: "unpaired", refused: "busy" });
      if (code === "rate_limited") return this.set({ state: "unpaired", refused: "rate_limited" });
      conn.close();
      return this.set({ state: "unavailable" });
    } finally {
      this.pairingInProgress = false;
    }
  }

  private async onMessage(conn: DesktopConnection, m: Message): Promise<void> {
    if (m.type === "event") {
      if (m.event === "locked" && this.state.state === "ready") this.set({ state: "ready", locked: true });
      if (m.event === "unlocked" && this.state.state === "ready") this.set({ state: "ready", locked: false });
      if (m.event === "revoked") {
        await this.deps.keys.clear();
        conn.close();
        this.set({ state: "unpaired" });
      }
      return;
    }
    if (m.id === 0 && m.type === "error") {
      // The relay could not reach the application.
      conn.close();
      this.set({ state: "unavailable" });
      return;
    }
    if (m.id !== this.pairId || this.state.state !== "pairing") return;
    if (m.type === "paired" && typeof m.clientId === "string" && typeof m.key === "string") {
      const key = await importPairingKey(m.key);
      await this.deps.keys.save({ clientId: m.clientId, key });
      await this.reauthenticate();
    } else if (m.type === "error") {
      const refused = m.code === "pairing_timeout" ? "timeout" : "refused";
      this.set({ state: "unpaired", refused });
    }
  }

  /** A request on an authenticated connection. */
  async call(type: string, body: Record<string, unknown> = {}): Promise<Message> {
    const state = await this.ensure();
    if (state.state !== "ready" || !this.conn) {
      throw new BridgeError(state.state === "unpaired" ? "unpaired" : "desktop_unavailable");
    }
    try {
      return await this.conn.request(type, body);
    } catch (e) {
      if (e instanceof BridgeError && e.code === "locked" && this.state.state === "ready" && !this.state.locked) {
        this.set({ state: "ready", locked: true });
      }
      throw e;
    }
  }
}
