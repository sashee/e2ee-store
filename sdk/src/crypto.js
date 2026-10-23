// Encoding helpers and the WebCrypto primitives (SPEC §3.1).

const subtle = globalThis.crypto.subtle;
export const te = new TextEncoder();
export const td = new TextDecoder("utf-8", { fatal: true });

export const bytes = (data) => (data instanceof Uint8Array ? data : new Uint8Array(data));

export function concat(parts) {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  parts.reduce((offset, part) => {
    out.set(part, offset);
    return offset + part.length;
  }, 0);
  return out;
}

export const equalBytes = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);

export function b64urlEncode(data) {
  let binary = "";
  for (const b of bytes(data)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("not base64url");
  return Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
}

export function hexEncode(data) {
  return Array.from(bytes(data), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexDecode(text) {
  if (typeof text !== "string" || text.length % 2 !== 0 || !/^[0-9a-f]*$/.test(text)) throw new Error("not lowercase hex");
  return Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}

export function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

export async function sha256(data) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes(data)));
}

export async function sha256Hex(data) {
  return hexEncode(await sha256(data));
}

/** A non-extractable AES-256-GCM key: HKDF-SHA256 over `ikm` with an empty salt and `info`. */
export async function hkdfAesKey(ikm, info) {
  const base = await subtle.importKey("raw", bytes(ikm), "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: te.encode(info) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** `length` bytes from HKDF-SHA256 over `ikm` with an empty salt and `info`. */
export async function hkdfBytes(ikm, info, length) {
  const base = await subtle.importKey("raw", bytes(ikm), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: te.encode(info) }, base, length * 8));
}

/** A non-extractable HKDF key over HKDF-SHA256(ikm, empty salt, info): the root to derive further keys from. */
export async function hkdfBaseKey(ikm, info) {
  return subtle.importKey("raw", await hkdfBytes(ikm, info, 32), "HKDF", false, ["deriveKey"]);
}

/** A non-extractable AES-256-GCM key: HKDF-SHA256 from an HKDF key (`hkdfBaseKey`), with a salt and `info`. */
export async function hkdfSaltedAesKey(baseKey, salt, info) {
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: bytes(salt), info: te.encode(info) },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Encrypts with a fresh random 12-byte nonce, unless one is given (only with a key that is used once). */
export async function aesGcmEncrypt(key, plaintext, aad, nonce = randomBytes(12)) {
  const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, bytes(plaintext)));
  return { nonce, ciphertext };
}

/** Throws `DecryptError` when authentication fails (wrong key or tampered data). */
export async function aesGcmDecrypt(key, nonce, ciphertext, aad) {
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: bytes(nonce), additionalData: aad }, key, bytes(ciphertext)));
  } catch {
    throw new DecryptError();
  }
}

export class DecryptError extends Error {
  constructor() {
    super("decryption failed");
    this.name = "DecryptError";
  }
}
