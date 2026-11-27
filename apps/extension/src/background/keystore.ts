// Where the pairing lives: IndexedDB of the extension's own origin, which
// content scripts (running in the page's origin) cannot open. The key is a
// non-extractable CryptoKey.

export interface Pairing {
  clientId: string;
  key: CryptoKey;
}

export interface KeyStore {
  load(): Promise<Pairing | null>;
  save(pairing: Pairing): Promise<void>;
  clear(): Promise<void>;
}

const DB = "lastkeys";
const STORE = "pairing";
const RECORD = "current";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("indexedDB"));
  });
}

async function run<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const request = work(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(request.result);
      tx.onerror = () => reject(tx.error ?? new Error("indexedDB"));
      tx.onabort = () => reject(tx.error ?? new Error("indexedDB"));
    });
  } finally {
    db.close();
  }
}

export const indexedDbKeyStore: KeyStore = {
  async load() {
    const value = (await run("readonly", (s) => s.get(RECORD))) as Partial<Pairing> | undefined;
    if (!value || typeof value.clientId !== "string" || !(value.key instanceof CryptoKey)) return null;
    return { clientId: value.clientId, key: value.key };
  },
  async save(pairing) {
    await run("readwrite", (s) => s.put(pairing, RECORD));
  },
  async clear() {
    await run("readwrite", (s) => s.delete(RECORD));
  },
};

/** In-memory store for tests. */
export function memoryKeyStore(): KeyStore & { value: Pairing | null } {
  return {
    value: null,
    async load() {
      return this.value;
    },
    async save(pairing) {
      this.value = pairing;
    },
    async clear() {
      this.value = null;
    },
  };
}
