// Mutual challenge-response authentication with the desktop
// (crates/lk-bridge/src/auth.rs): the same labels, inputs and encodings.
// The pairing key is imported as a non-extractable WebCrypto key: once
// stored, its bytes cannot be read back by JavaScript.

export const SERVER_LABEL = "lk-bridge v1 server proof\0";
export const CLIENT_LABEL = "lk-bridge v1 client proof\0";
export const NONCE_LEN = 32;

const encoder = new TextEncoder();

export function toBase64(bytes: Uint8Array): string {
  let text = "";
  for (const b of bytes) text += String.fromCharCode(b);
  return btoa(text);
}

export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

export function newNonce(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(NONCE_LEN));
}

/** Imports the key received at pairing (Base64, 32 bytes). */
export async function importPairingKey(base64: string): Promise<CryptoKey> {
  const raw = fromBase64(base64);
  if (raw.length !== 32) throw new Error("invalid pairing key");
  try {
    return await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
      "verify",
    ]);
  } finally {
    raw.fill(0);
  }
}

function message(label: string, clientId: string, first: Uint8Array, second: Uint8Array): Uint8Array<ArrayBuffer> {
  const parts = [encoder.encode(label), encoder.encode(clientId), first, second];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Checks the desktop's proof (HMAC verification, constant time in WebCrypto). */
export async function verifyServerProof(
  key: CryptoKey,
  clientId: string,
  clientNonce: Uint8Array,
  serverNonce: Uint8Array,
  proof: string,
): Promise<boolean> {
  let signature: Uint8Array<ArrayBuffer>;
  try {
    signature = fromBase64(proof);
  } catch {
    return false;
  }
  if (signature.length !== 32 || serverNonce.length !== NONCE_LEN) return false;
  return crypto.subtle.verify(
    "HMAC",
    key,
    signature,
    message(SERVER_LABEL, clientId, clientNonce, serverNonce),
  );
}

/** The extension's proof. */
export async function clientProof(
  key: CryptoKey,
  clientId: string,
  clientNonce: Uint8Array,
  serverNonce: Uint8Array,
): Promise<string> {
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    message(CLIENT_LABEL, clientId, serverNonce, clientNonce),
  );
  return toBase64(new Uint8Array(mac));
}
