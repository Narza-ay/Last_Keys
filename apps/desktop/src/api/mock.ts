// Scripted back end for the browser preview, UI tests and screenshots.
// Bundled only when VITE_LK_MOCK=1; never part of a Tauri build. It mimics
// the Rust semantics closely enough to exercise the UI (no cryptography).
//
// URL parameters: ?state=fresh|locked|unlocked (default fresh),
// &registered=1, &lang=fr|en, &theme=light|dark, &bridge=1 (browser
// integration on, one paired extension), &pairing=1 (a pairing request is
// waiting).

import type { Backend } from "./backend";
import type {
  AppStatus,
  BridgeStatus,
  ContentView,
  DeviceView,
  Field,
  ItemDraft,
  ItemKind,
  ItemSummary,
  ItemView,
  PairingRequestView,
  SecretChange,
  Settings,
  SyncSummary,
  UiError,
  VaultInfo,
} from "./types";

export const MOCK_PASSWORD = "correct horse battery staple";
export const MOCK_RECOVERY_KEY = "LK1-7Q2M-4KXH-9D3P-T6VW-2BCE-8JNA-5RZF-1GYS-0K4H-MXQ7-3PDW-HV6T";

interface Secrets {
  password?: string;
  totp?: string;
  backupCodes: string[];
  cardNumber?: string;
  securityCode?: string;
  pin?: string;
  documentNumbers: string[];
}

interface Rec {
  id: string;
  title: string;
  favorite: boolean;
  folder: string | null;
  tags: string[];
  notes?: string;
  customFields: { name: string; kind: "text" | "hidden" | "url" | "email"; value: string }[];
  createdAt: number;
  updatedAt: number;
  history: { password: string; replacedAt: number }[];
  content: ContentView;
  secrets: Secrets;
}

const fail = (kind: string, message = kind): UiError => ({ kind, message });
const now = () => Math.floor(Date.now() / 1000);
const delay = (ms = 120) => new Promise((r) => setTimeout(r, ms));
let counter = 0;
const uuid = () =>
  `${(++counter).toString(16).padStart(8, "0")}-4b1e-4c2d-9e3f-${Math.floor(Math.random() * 1e12)
    .toString(16)
    .padStart(12, "0")}`;

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function normalizeUrl(input: string): string {
  const t = input.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:/i.test(t) ? t : `https://${t}`;
  const u = new URL(withScheme);
  if (u.protocol !== "https:" && u.protocol !== "http:") throw fail("invalid_input", "invalid URL");
  return u.toString();
}

function apply(change: SecretChange, current: string | undefined): string | undefined {
  if (change.op === "keep") return current;
  if (change.op === "clear") return undefined;
  return change.value === "" ? undefined : change.value;
}

function seed(): Rec[] {
  const t = now();
  const day = 86_400;
  const rec = (partial: Partial<Rec> & Pick<Rec, "title" | "content">): Rec => ({
    id: uuid(),
    favorite: false,
    folder: null,
    tags: [],
    customFields: [],
    createdAt: t - 40 * day,
    updatedAt: t - 3 * day,
    history: [],
    secrets: { backupCodes: [], documentNumbers: [] },
    ...partial,
  });
  return [
    rec({
      title: "Banque Populaire",
      favorite: true,
      folder: "Finance",
      tags: ["banque"],
      content: { type: "login", username: "alice.martin", hasPassword: true, urls: ["https://www.banquepopulaire.fr/"], hasTotp: true, backupCodes: 0 },
      secrets: { password: "Tr0ub4dour&3-Saphir", totp: "otpauth://totp/Banque?secret=JBSWY3DPEHPK3PXP", backupCodes: [], documentNumbers: [] },
      history: [{ password: "old-password-2023", replacedAt: t - 90 * day }],
    }),
    rec({
      title: "GitHub",
      favorite: true,
      tags: ["dev"],
      content: { type: "login", username: "amartin", hasPassword: true, urls: ["https://github.com/login"], hasTotp: true, backupCodes: 2 },
      secrets: { password: "gh-9xK!vQ2#mZp7", totp: "otpauth://totp/GitHub?secret=KRSXG5CTMVRXEZLU", backupCodes: ["a1b2-c3d4", "e5f6-g7h8"], documentNumbers: [] },
    }),
    rec({
      title: "Netflix",
      content: { type: "login", username: "alice@example.com", hasPassword: true, urls: ["https://www.netflix.com/"], hasTotp: false, backupCodes: 0 },
      secrets: { password: "popcorn-Velvet-42", backupCodes: [], documentNumbers: [] },
    }),
    rec({
      title: "Amazon",
      content: { type: "login", username: "alice@example.com", hasPassword: true, urls: ["https://www.amazon.fr/"], hasTotp: false, backupCodes: 0 },
      secrets: { password: "Aq7!rT9#bLm2", backupCodes: [], documentNumbers: [] },
    }),
    rec({
      title: "Wi-Fi maison",
      notes: "Réseau : Martin-5G\nMot de passe : hunter2-hunter2",
      content: { type: "secure_note" },
    }),
    rec({
      title: "Visa Premier",
      folder: "Finance",
      content: {
        type: "payment_card",
        cardholderName: "Alice Martin",
        hasNumber: true,
        numberLast4: "4242",
        expiryMonth: 9,
        expiryYear: 2029,
        hasSecurityCode: true,
        hasPin: true,
        billingAddress: null,
      },
      secrets: { cardNumber: "4242424242424242", securityCode: "123", pin: "0000", backupCodes: [], documentNumbers: [] },
    }),
    rec({
      title: "Identité",
      content: {
        type: "identity",
        honorific: null,
        firstName: "Alice",
        middleName: null,
        lastName: "Martin",
        birthDate: "1990-04-12",
        email: "alice@example.com",
        phone: "+33 6 12 34 56 78",
        company: null,
        address: { line1: "12 rue des Lilas", line2: null, city: "Lyon", postalCode: "69003", region: null, country: "FR" },
        documents: [{ kind: "passport", issuingCountry: "FR", expiryDate: "2031-06-30", hasNumber: true }],
      },
      secrets: { backupCodes: [], documentNumbers: ["19AB12345"] },
    }),
  ];
}

function summary(r: Rec): ItemSummary {
  const c = r.content;
  let subtitle: string | null = null;
  let host: string | null = null;
  let hasTotp = false;
  if (c.type === "login") {
    subtitle = c.username;
    host = c.urls[0] ? hostOf(c.urls[0]) : null;
    hasTotp = c.hasTotp;
  } else if (c.type === "payment_card") {
    const digits = c.numberLast4 ? `•••• ${c.numberLast4}` : null;
    subtitle = [c.cardholderName, digits].filter(Boolean).join(" · ") || null;
  } else if (c.type === "identity") {
    subtitle = [c.firstName, c.lastName].filter(Boolean).join(" ") || c.email;
  }
  return {
    id: r.id,
    kind: c.type,
    title: r.title,
    subtitle,
    favorite: r.favorite,
    folder: r.folder,
    tags: r.tags,
    host,
    hasTotp,
    updatedAt: r.updatedAt,
  };
}

function view(r: Rec): ItemView {
  return {
    id: r.id,
    kind: r.content.type,
    title: r.title,
    favorite: r.favorite,
    folder: r.folder,
    tags: r.tags,
    hasNotes: !!r.notes,
    customFields: r.customFields.map((f) => ({
      name: f.name,
      kind: f.kind,
      value: f.kind === "hidden" ? null : f.value,
      hasValue: f.value !== "",
    })),
    history: r.history.map((h) => ({ replacedAt: h.replacedAt })),
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
    content: structuredClone(r.content),
  };
}

function applyDraft(r: Rec, draft: ItemDraft, existing: boolean): void {
  if (!draft.title.trim()) throw fail("invalid_input", "a title is required");
  if (existing && draft.content.type !== r.content.type) throw fail("wrong_item_type");
  r.title = draft.title.trim();
  r.favorite = draft.favorite;
  r.folder = draft.folder?.trim() || null;
  r.tags = [...new Set(draft.tags.map((t) => t.trim()).filter(Boolean))];
  r.notes = apply(draft.notes, r.notes);
  const oldFields = r.customFields;
  r.customFields = draft.customFields.map((f) => {
    let value: string;
    if (f.value.op === "keep") {
      const source = f.source === null ? undefined : oldFields[f.source];
      if (!source) throw fail("invalid_input", "a kept custom field needs its source");
      value = source.value;
    } else value = f.value.op === "set" ? f.value.value : "";
    return { name: f.name, kind: f.kind, value };
  });
  const d = draft.content;
  const s = r.secrets;
  if (d.type === "login") {
    const urls = [...new Set(d.urls.filter((u) => u.trim()).map(normalizeUrl))];
    const previous = s.password;
    const next = apply(d.password, previous);
    if (existing && previous && next !== previous) {
      r.history.unshift({ password: previous, replacedAt: now() });
      r.history = r.history.slice(0, 20);
    }
    s.password = next;
    s.totp = d.totp.op === "set" && d.totp.value.trim()
      ? (/^otpauth:/.test(d.totp.value) ? d.totp.value : `otpauth://totp/${encodeURIComponent(r.title)}?secret=${d.totp.value.replace(/\s/g, "").toUpperCase()}`)
      : apply(d.totp, s.totp);
    if (d.backupCodes.op === "set") s.backupCodes = d.backupCodes.values.filter(Boolean);
    if (d.backupCodes.op === "clear") s.backupCodes = [];
    r.content = {
      type: "login",
      username: d.username?.trim() || null,
      hasPassword: !!s.password,
      urls,
      hasTotp: !!s.totp,
      backupCodes: s.backupCodes.length,
    };
  } else if (d.type === "secure_note") {
    r.content = { type: "secure_note" };
  } else if (d.type === "payment_card") {
    if (d.expiryMonth !== null && (d.expiryMonth < 1 || d.expiryMonth > 12)) throw fail("invalid_input", "invalid month");
    s.cardNumber = apply(d.number, s.cardNumber)?.replace(/[\s-]/g, "");
    s.securityCode = apply(d.securityCode, s.securityCode);
    s.pin = apply(d.pin, s.pin);
    r.content = {
      type: "payment_card",
      cardholderName: d.cardholderName,
      hasNumber: !!s.cardNumber,
      numberLast4: s.cardNumber ? s.cardNumber.slice(-4) : null,
      expiryMonth: d.expiryMonth,
      expiryYear: d.expiryYear,
      hasSecurityCode: !!s.securityCode,
      hasPin: !!s.pin,
      billingAddress: d.billingAddress,
    };
  } else {
    const oldNumbers = s.documentNumbers;
    s.documentNumbers = d.documents.map((doc) => {
      if (doc.number.op === "keep") {
        const kept = doc.source === null ? undefined : oldNumbers[doc.source];
        if (kept === undefined) throw fail("invalid_input", "a kept document needs its source");
        return kept;
      }
      return doc.number.op === "set" ? doc.number.value : "";
    });
    r.content = {
      type: "identity",
      honorific: d.honorific,
      firstName: d.firstName,
      middleName: d.middleName,
      lastName: d.lastName,
      birthDate: d.birthDate,
      email: d.email,
      phone: d.phone,
      company: d.company,
      address: d.address,
      documents: d.documents.map((doc, i) => ({
        kind: doc.kind,
        issuingCountry: doc.issuingCountry?.toUpperCase() ?? null,
        expiryDate: doc.expiryDate,
        hasNumber: (s.documentNumbers[i] ?? "") !== "",
      })),
    };
  }
  r.updatedAt = Math.max(now(), r.updatedAt);
}

function randomFrom(alphabet: string, n: number): string {
  const out: string[] = [];
  const buf = new Uint32Array(n);
  crypto.getRandomValues(buf);
  for (const x of buf) out.push(alphabet[x % alphabet.length] ?? "a");
  return out.join("");
}

const WORDS = ["abricot", "boussole", "canyon", "dauphin", "étoile", "falaise", "glacier", "horizon", "iris", "jasmin", "kayak", "lagune", "mistral", "nuage", "orage", "prairie", "quartz", "rivière", "safran", "tilleul", "vallon", "zéphyr"];

export function createMockBackend(): Backend {
  const params = new URLSearchParams(window.location.search);
  const initial = params.get("state") ?? "fresh";
  let vaultExists = initial !== "fresh";
  let unlocked = initial === "unlocked";
  let password = MOCK_PASSWORD;
  let unlockedWith: VaultInfo["unlockedWith"] = "master_password";
  let items: Rec[] = vaultExists ? seed() : [];
  let remote: VaultInfo["remote"] =
    params.get("registered") === "1" ? { server: "https://sync.example.org", email: "alice@example.com" } : null;
  let settings: Settings = {
    language: (params.get("lang") as Settings["language"] | null) ?? "system",
    theme: (params.get("theme") as Settings["theme"] | null) ?? "system",
    autoLockMinutes: 5,
    clipboardClearSeconds: 30,
    browserIntegration: params.get("bridge") === "1",
  };
  const lockListeners = new Set<() => void>();
  const changeListeners = new Set<() => void>();
  const pairingListeners = new Set<(r: PairingRequestView) => void>();
  const pairingClosedListeners = new Set<(id: number) => void>();
  let pairingId = 0;
  let pending: PairingRequestView | null = null;
  let clients: BridgeStatus["clients"] = settings.browserIntegration
    ? [
        {
          clientId: "00112233445566778899aabbccddeeff",
          name: "Chrome · Linux",
          browser: "chromium",
          extension: "bblheiicocdmmkjnhdeehaedddgcfhok",
          createdAt: now() - 7 * 86_400,
          lastUsedAt: now() - 600,
        },
      ]
    : [];
  const bridge = (): BridgeStatus => ({
    enabled: settings.browserIntegration,
    running: settings.browserIntegration,
    error: null,
    browsers: settings.browserIntegration
      ? [
          { browser: "chrome", state: "installed" },
          { browser: "chromium", state: "not_detected" },
          { browser: "brave", state: "not_detected" },
          { browser: "firefox", state: "installed" },
        ]
      : [
          { browser: "chrome", state: "not_installed" },
          { browser: "chromium", state: "not_detected" },
          { browser: "brave", state: "not_detected" },
          { browser: "firefox", state: "not_installed" },
        ],
    clients: clients.map((c) => ({ ...c })),
    pending: pending ? { ...pending } : null,
  });
  const requestPairing = () => {
    pending = {
      id: ++pairingId,
      code: "K7M-4QX",
      clientName: "Firefox · Linux",
      browser: "firefox",
      extension: "browser-extension@lastkeys.app",
    };
    const request = pending;
    pairingListeners.forEach((l) => l(request));
  };
  if (params.get("pairing") === "1") requestPairing();
  let deviceName = "Laptop";
  const devices: DeviceView[] = [
    { id: "d0000001-0000-4000-8000-000000000001", name: "Laptop", platform: "linux", status: "this_device", enrolledAt: now() - 60 * 86_400, lastSeen: now() },
    { id: "d0000002-0000-4000-8000-000000000002", name: "Pixel 8", platform: "android", status: "active", enrolledAt: now() - 30 * 86_400, lastSeen: now() - 3600 },
    { id: "d0000003-0000-4000-8000-000000000003", name: "Bureau", platform: "windows", status: "active", enrolledAt: now() - 20 * 86_400, lastSeen: now() - 2 * 86_400 },
    { id: "d0000004-0000-4000-8000-000000000004", name: "Ancien téléphone", platform: "ios", status: "revoked", enrolledAt: now() - 300 * 86_400, lastSeen: now() - 200 * 86_400 },
  ];

  const requireUnlocked = () => {
    if (!unlocked) throw fail("locked");
  };
  const find = (id: string): Rec => {
    requireUnlocked();
    const r = items.find((x) => x.id === id);
    if (!r) throw fail("not_found");
    return r;
  };
  const checkNew = (pw: string, confirmation: string) => {
    if (pw !== confirmation) throw fail("password_mismatch");
    if (Array.from(pw).length < 12) throw fail("weak_master_password");
  };

  const backend: Backend = {
    async appStatus(): Promise<AppStatus> {
      return { vaultExists, unlocked, platform: "linux", version: "0.1.0", defaultDeviceName: "Laptop" };
    },
    async getSettings() {
      return { ...settings };
    },
    async setSettings(next) {
      if (next.autoLockMinutes < 1 || next.autoLockMinutes > 240) throw fail("invalid_setting");
      settings = { ...next, browserIntegration: settings.browserIntegration };
      return { ...settings };
    },
    async touch() {},
    async lock() {
      unlocked = false;
    },
    async createVault(pw, confirmation, name) {
      await delay(400);
      if (vaultExists) throw fail("vault_exists");
      checkNew(pw, confirmation);
      password = pw;
      deviceName = name.trim();
      vaultExists = true;
      unlocked = true;
      unlockedWith = "master_password";
      items = [];
      return MOCK_RECOVERY_KEY;
    },
    async enrollDevice(server, email, pw, name) {
      await delay(500);
      if (!/^https:\/\//.test(server)) throw fail("invalid_server_url");
      if (pw !== MOCK_PASSWORD) throw fail("invalid_credentials");
      vaultExists = true;
      unlocked = true;
      deviceName = name;
      items = seed();
      remote = { server, email };
      return items.length;
    },
    async unlock(pw) {
      await delay(300);
      if (pw !== password) throw fail("invalid_credentials");
      unlocked = true;
      unlockedWith = "master_password";
    },
    async unlockWithRecoveryKey(key) {
      await delay(300);
      if (!/^LK1-/i.test(key.trim())) throw fail("invalid_recovery_key");
      if (key.trim().toUpperCase() !== MOCK_RECOVERY_KEY) throw fail("invalid_credentials");
      unlocked = true;
      unlockedWith = "recovery_key";
    },
    async vaultInfo(): Promise<VaultInfo> {
      requireUnlocked();
      return {
        accountId: "a3f1c2d4-5b6e-4f70-8a9b-0c1d2e3f4a5b",
        deviceId: devices[0]?.id ?? "",
        deviceName,
        platform: "linux",
        enrolledAt: now() - 60 * 86_400,
        kdf: { memoryKib: 65_536, iterations: 3, parallelism: 4 },
        recoveryKeyConfigured: true,
        items: items.length,
        pendingChanges: 0,
        remote,
        unlockedWith,
      };
    },
    async listItems(query) {
      requireUnlocked();
      const q = query.trim().toLowerCase();
      return items
        .filter((r) => {
          if (!q) return true;
          const s = summary(r);
          return [r.title, r.folder ?? "", ...r.tags, s.subtitle ?? "", ...(r.content.type === "login" ? r.content.urls : [])]
            .some((x) => x.toLowerCase().includes(q));
        })
        .map(summary)
        .sort((a, b) => a.title.localeCompare(b.title));
    },
    async getItem(id) {
      return view(find(id));
    },
    async revealField(id, field) {
      return backend_value(find(id), field);
    },
    async copyField(id, field) {
      backend_value(find(id), field);
      return { clearsInSeconds: settings.clipboardClearSeconds };
    },
    async copyText() {
      return { clearsInSeconds: settings.clipboardClearSeconds };
    },
    async totp(id) {
      const r = find(id);
      if (!r.secrets.totp) throw fail("no_totp");
      const t = now();
      const step = Math.floor(t / 30);
      const code = String((step * 7919 + r.title.length * 104_729) % 1_000_000).padStart(6, "0");
      return { code, period: 30, remaining: 30 - (t % 30) };
    },
    async createItem(draft) {
      requireUnlocked();
      const r: Rec = {
        id: uuid(),
        title: "",
        favorite: false,
        folder: null,
        tags: [],
        customFields: [],
        createdAt: now(),
        updatedAt: now(),
        history: [],
        content: { type: draft.content.type } as ContentView,
        secrets: { backupCodes: [], documentNumbers: [] },
      };
      applyDraft(r, draft, false);
      items.push(r);
      return r.id;
    },
    async updateItem(id, draft) {
      const r = find(id);
      const copy = structuredClone(r);
      applyDraft(copy, draft, true);
      Object.assign(r, copy);
    },
    async deleteItem(id) {
      find(id);
      items = items.filter((r) => r.id !== id);
    },
    async restorePassword(id, index) {
      const r = find(id);
      const entry = r.history[index];
      if (!entry) throw fail("invalid_input");
      r.history.splice(index, 1);
      if (r.secrets.password) r.history.unshift({ password: r.secrets.password, replacedAt: now() });
      r.secrets.password = entry.password;
      r.updatedAt = now();
    },
    async deleteHistoryEntry(id, index) {
      const r = find(id);
      if (!r.history[index]) throw fail("invalid_input");
      r.history.splice(index, 1);
    },
    async generatePassword(o) {
      let alphabet = "";
      if (o.lowercase) alphabet += o.excludeAmbiguous ? "abcdefghijkmnopqrstuvwxyz" : "abcdefghijklmnopqrstuvwxyz";
      if (o.uppercase) alphabet += o.excludeAmbiguous ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      if (o.digits) alphabet += o.excludeAmbiguous ? "23456789" : "0123456789";
      if (o.symbols) alphabet += "!#$%&*+-=?@^_";
      if (!alphabet) throw fail("invalid_input", "select at least one character class");
      const bits = o.length * Math.log2(alphabet.length);
      return { value: randomFrom(alphabet, o.length), entropyBits: bits, level: level(bits) };
    },
    async generatePassphrase(o) {
      const words = Array.from({ length: o.words }, () => {
        const w = WORDS[Math.floor(Math.random() * WORDS.length)] ?? "mot";
        return o.capitalize ? w.charAt(0).toUpperCase() + w.slice(1) : w;
      });
      if (o.includeNumber) words.push(String(Math.floor(Math.random() * 10)));
      const bits = o.words * 12.9 + (o.includeNumber ? 3.3 : 0);
      return { value: words.join(o.separator), entropyBits: bits, level: level(bits) };
    },
    async changeMasterPassword(current, next, confirmation) {
      requireUnlocked();
      if (unlockedWith === "master_password" && current !== password) throw fail("invalid_credentials");
      checkNew(next, confirmation);
      await delay(300);
      password = next;
      unlockedWith = "master_password";
    },
    async rotateRecoveryKey(pw) {
      requireUnlocked();
      if (pw !== password) throw fail("invalid_credentials");
      return MOCK_RECOVERY_KEY.replace("7Q2M", "8W3N");
    },
    async register(server, email, key) {
      requireUnlocked();
      await delay(400);
      if (!/^https:\/\//.test(server)) throw fail("invalid_server_url");
      if (!/^LK1-/i.test(key.trim())) throw fail("invalid_recovery_key");
      remote = { server, email };
      return { received: 0, sent: items.length, conflicts: 0, conflictCopies: 0 };
    },
    async sync(): Promise<SyncSummary> {
      requireUnlocked();
      if (!remote) throw fail("not_registered");
      await delay(250);
      return { received: 0, sent: 0, conflicts: 0, conflictCopies: 0 };
    },
    async devices() {
      requireUnlocked();
      if (!remote) throw fail("not_registered");
      return devices.map((d) => ({ ...d }));
    },
    async revokeDevice(id) {
      const d = devices.find((x) => x.id === id);
      if (!d) throw fail("not_found");
      if (d.status === "this_device") throw fail("cannot_revoke_self");
      d.status = "revoked";
    },
    async onLocked(callback) {
      lockListeners.add(callback);
      return () => lockListeners.delete(callback);
    },
    async onVaultChanged(callback) {
      changeListeners.add(callback);
      return () => changeListeners.delete(callback);
    },
    async bridgeStatus() {
      await delay(40);
      return bridge();
    },
    async setBrowserIntegration(enabled) {
      await delay();
      settings = { ...settings, browserIntegration: enabled };
      if (!enabled) clients = [];
      return bridge();
    },
    async pairingDecision(id, approve) {
      if (!pending || pending.id !== id) return false;
      const request = pending;
      pending = null;
      if (approve) {
        clients = [
          {
            clientId: `${id.toString(16).padStart(8, "0")}${"0".repeat(24)}`,
            name: request.clientName,
            browser: request.browser,
            extension: request.extension,
            createdAt: now(),
            lastUsedAt: null,
          },
          ...clients,
        ];
      }
      pairingClosedListeners.forEach((l) => l(id));
      return true;
    },
    async revokeBrowser(clientId) {
      const before = clients.length;
      clients = clients.filter((c) => c.clientId !== clientId);
      if (clients.length === before) throw fail("not_found");
      return bridge();
    },
    async onPairingRequest(callback) {
      pairingListeners.add(callback);
      return () => pairingListeners.delete(callback);
    },
    async onPairingClosed(callback) {
      pairingClosedListeners.add(callback);
      return () => pairingClosedListeners.delete(callback);
    },
  };

  // Test hooks: a browser extension asks to pair; a login saved from a
  // browser.
  const hooks = window as unknown as { __lkMockPairing?: () => void; __lkMockSavedFromBrowser?: () => void };
  hooks.__lkMockPairing = requestPairing;
  hooks.__lkMockSavedFromBrowser = () => {
    const at = now();
    items = [
      ...items,
      {
        id: uuid(),
        title: "example.net",
        favorite: false,
        folder: null,
        tags: [],
        customFields: [],
        createdAt: at,
        updatedAt: at,
        history: [],
        content: { type: "login", username: "carol", hasPassword: true, urls: ["https://shop.example.net/"], hasTotp: false, backupCodes: 0 },
        secrets: { password: "saved-from-browser", backupCodes: [], documentNumbers: [] },
      },
    ];
    changeListeners.forEach((l) => l());
  };

  // Test hook: simulate the auto-lock timer.
  (window as unknown as { __lkMockAutoLock?: () => void }).__lkMockAutoLock = () => {
    unlocked = false;
    lockListeners.forEach((l) => l());
  };

  function backend_value(r: Rec, field: Field): string {
    const s = r.secrets;
    const c = r.content;
    const value = (() => {
      switch (field.field) {
        case "username":
          return c.type === "login" ? c.username : null;
        case "password":
          return s.password;
        case "url":
          return c.type === "login" ? c.urls[field.index] : null;
        case "totpCode":
          return s.totp ? "123456" : null;
        case "totpSecret":
          return s.totp;
        case "backupCode":
          return s.backupCodes[field.index];
        case "notes":
          return r.notes;
        case "cardNumber":
          return s.cardNumber;
        case "securityCode":
          return s.securityCode;
        case "pin":
          return s.pin;
        case "customField":
          return r.customFields[field.index]?.value;
        case "historyPassword":
          return r.history[field.index]?.password;
        case "documentNumber":
          return s.documentNumbers[field.index];
      }
    })();
    if (!value) throw fail("not_found");
    return value;
  }

  return backend;
}

function level(bits: number): "very_weak" | "weak" | "fair" | "strong" | "very_strong" {
  if (bits < 35) return "very_weak";
  if (bits < 50) return "weak";
  if (bits < 64) return "fair";
  if (bits < 80) return "strong";
  return "very_strong";
}

export type { ItemKind };
