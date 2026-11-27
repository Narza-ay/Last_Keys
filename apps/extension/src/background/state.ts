// Per-tab state kept in session storage (memory only, cleared when the
// browser closes; survives the background being suspended): the frames
// that reported forms, and submitted credentials waiting for a decision.
// Session storage is not exposed to content scripts.

import type { SaveProposal } from "../shared/messages";

export interface KeyValue {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  remove(key: string): Promise<void>;
}

export function sessionStorageArea(area: chrome.storage.StorageArea): KeyValue {
  return {
    async get<T>(key: string) {
      const record = await area.get(key);
      return record[key] as T | undefined;
    },
    async set(key, value) {
      await area.set({ [key]: value });
    },
    async remove(key) {
      await area.remove(key);
    },
  };
}

export function memoryArea(): KeyValue & { data: Map<string, unknown> } {
  const data = new Map<string, unknown>();
  return {
    data,
    async get<T>(key: string) {
      return structuredClone(data.get(key)) as T | undefined;
    },
    async set(key, value) {
      data.set(key, structuredClone(value));
    },
    async remove(key) {
      data.delete(key);
    },
  };
}

/** A frame as its content script reported it (URL from the browser). */
export interface FrameInfo {
  frameId: number;
  url: string;
  documentId?: string;
  login: boolean;
  newPassword: boolean;
  otp: boolean;
}

export class Frames {
  /** Read-modify-write updates run one after another: frames of a page
   * report at the same moment, and none may overwrite another's report. */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly store: KeyValue) {}

  private key(tabId: number): string {
    return `frames:${tabId}`;
  }

  private serialized<T>(work: () => Promise<T>): Promise<T> {
    const next = this.queue.then(work, work);
    this.queue = next.catch(() => undefined);
    return next;
  }

  update(tabId: number, frame: FrameInfo): Promise<void> {
    return this.serialized(async () => {
      const frames = (await this.store.get<Record<string, FrameInfo>>(this.key(tabId))) ?? {};
      frames[String(frame.frameId)] = frame;
      await this.store.set(this.key(tabId), frames);
    });
  }

  /** Frames of a tab, the top-level frame first. */
  async list(tabId: number): Promise<FrameInfo[]> {
    const frames = (await this.store.get<Record<string, FrameInfo>>(this.key(tabId))) ?? {};
    return Object.values(frames).sort((a, b) => a.frameId - b.frameId);
  }

  clear(tabId: number): Promise<void> {
    return this.serialized(() => this.store.remove(this.key(tabId)));
  }
}

/** How long submitted credentials wait for a decision. */
export const SAVE_TTL_MS = 5 * 60_000;

export interface StoredSave {
  url: string;
  username: string | null;
  password: string;
  proposal: SaveProposal | null;
  at: number;
}

export class Saves {
  constructor(
    private readonly store: KeyValue,
    private readonly now: () => number = Date.now,
  ) {}

  private key(tabId: number): string {
    return `save:${tabId}`;
  }

  async put(tabId: number, save: StoredSave): Promise<void> {
    await this.store.set(this.key(tabId), save);
  }

  async get(tabId: number): Promise<StoredSave | null> {
    const save = await this.store.get<StoredSave>(this.key(tabId));
    if (!save) return null;
    if (this.now() - save.at > SAVE_TTL_MS) {
      await this.store.remove(this.key(tabId));
      return null;
    }
    return save;
  }

  async clear(tabId: number): Promise<void> {
    await this.store.remove(this.key(tabId));
  }
}
