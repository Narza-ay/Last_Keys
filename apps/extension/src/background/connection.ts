// One native messaging connection to the desktop (through its relay):
// requests correlated by `id`, responses with `type: "error"` turned into
// rejections, and everything else (events, the second answer to a pairing
// request) given to listeners.

export interface NativePort {
  postMessage(message: unknown): void;
  disconnect(): void;
  onMessage: { addListener(callback: (message: unknown) => void): void };
  onDisconnect: { addListener(callback: () => void): void };
}

export interface Message {
  id: number;
  type: string;
  [field: string]: unknown;
}

/** An error answer of the desktop (`code`), or `desktop_unavailable`. */
export class BridgeError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "BridgeError";
  }
}

interface Pending {
  resolve: (message: Message) => void;
  reject: (error: BridgeError) => void;
  timer: ReturnType<typeof setTimeout>;
}

function isMessage(value: unknown): value is Message {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return typeof v.id === "number" && typeof v.type === "string";
}

export class DesktopConnection {
  private port: NativePort | null = null;
  private next = 1;
  private readonly pending = new Map<number, Pending>();
  private readonly listeners = new Set<(message: Message) => void>();
  private readonly closeListeners = new Set<() => void>();

  constructor(private readonly connect: () => NativePort) {}

  get isOpen(): boolean {
    return this.port !== null;
  }

  /** Opens the connection (starts the relay). */
  start(): void {
    if (this.port) return;
    const port = this.connect();
    this.port = port;
    port.onMessage.addListener((message) => this.receive(message));
    port.onDisconnect.addListener(() => {
      if (this.port === port) this.closed();
    });
  }

  onMessage(listener: (message: Message) => void): void {
    this.listeners.add(listener);
  }

  onClose(listener: () => void): void {
    this.closeListeners.add(listener);
  }

  /** Sends a request; resolves with its first answer. */
  request(type: string, body: Record<string, unknown> = {}, timeoutMs = 15_000): Promise<Message> {
    const port = this.port;
    if (!port) return Promise.reject(new BridgeError("desktop_unavailable"));
    const id = this.next;
    this.next += 1;
    return new Promise<Message>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new BridgeError("timeout"));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try {
        port.postMessage({ ...body, id, type });
      } catch {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new BridgeError("desktop_unavailable"));
      }
    });
  }

  /** The id the next request will use. */
  get nextId(): number {
    return this.next;
  }

  close(): void {
    const port = this.port;
    if (!port) return;
    this.closed();
    try {
      port.disconnect();
    } catch {
      // Already gone.
    }
  }

  private receive(raw: unknown): void {
    if (!isMessage(raw)) return;
    const waiting = raw.id > 0 ? this.pending.get(raw.id) : undefined;
    if (waiting) {
      this.pending.delete(raw.id);
      clearTimeout(waiting.timer);
      if (raw.type === "error") waiting.reject(new BridgeError(String(raw.code ?? "internal")));
      else waiting.resolve(raw);
      return;
    }
    this.listeners.forEach((l) => l(raw));
  }

  private closed(): void {
    this.port = null;
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new BridgeError("desktop_unavailable"));
    }
    this.pending.clear();
    this.closeListeners.forEach((l) => l());
  }
}
