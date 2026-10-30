// The backend client (backend/SPEC.md §8). Same origin, so the session cookie and `Origin` go automatically.

import { sha256Hex } from "./crypto.js";

// Messages come from here, not from the server, so a misbehaving server can't put its own text in front of
// the user (e.g. asking for the recovery key).
const MESSAGES = {
  unauthenticated: "Your session has ended. Unlock again.",
  authentication_failed: "The passkey login failed.",
  invalid_token: "This setup link has expired or was already used.",
  reauth_required: "Confirm with your passkey to do this.",
  passkey_session_required: "Log in with your passkey to do this.",
  registration_failed: "The passkey couldn't be registered.",
  passkey_exists: "This passkey is already registered.",
  last_passkey: "Your last passkey can't be deleted.",
  not_found: "Not found.",
  blob_not_found: "The data the vault points to is missing on the server.",
  blob_referenced: "This data is still in use.",
  blob_offloadable: "The vault's root has to stay in the server's database.",
  blob_lost: "This file was stored outside the server's database, and that storage lost it.",
  storage_unavailable: "The server's storage can't be reached right now. Try again later.",
  storage_full: "The server's disk is too full for this.",
  precondition_failed: "Someone else changed this at the same time.",
  blob_too_large: "This is too large to store.",
  unknown_host: "This address isn't served by the server.",
  forbidden: "The server refused the request.",
};

export class ApiError extends Error {
  constructor(status, body) {
    const code = typeof body?.error === "string" && /^[a-z_]{1,40}$/.test(body.error) ? body.error : "unknown";
    super(MESSAGES[code] ?? `The server refused the request (${code}, HTTP ${status}).`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

/** Blob IDs go into URLs, so anything that isn't exactly a SHA-256 in hex is refused (no `../…`). */
export function checkBlobId(id) {
  if (typeof id !== "string" || !/^[0-9a-f]{64}$/.test(id)) throw new IntegrityError(`an invalid blob ID from the server (${String(id).slice(0, 20)})`);
  return id;
}

export class IntegrityError extends Error {
  constructor(what) {
    super(`Integrity check failed: ${what}. The server returned data that doesn't match what was stored.`);
    this.name = "IntegrityError";
  }
}

/** A read of an offloadable blob whose content the server has lost (SPEC §6.13); `id` is the blob's. */
export class BlobLostError extends ApiError {
  constructor(id, body) {
    super(410, body);
    this.name = "BlobLostError";
    this.id = id;
  }
}

const lost = (id) => (error) => {
  throw error?.code === "blob_lost" ? new BlobLostError(id, error.body) : error;
};

/** Called with every 401 from an authenticated endpoint, so the app can lock. */
let onUnauthenticated = () => {};
export const setUnauthenticatedHandler = (handler) => {
  onUnauthenticated = handler;
};

/**
 * The pauses before each further attempt of a request that may be made again (SPEC §6.14): about 30 s in all. After the
 * last, the failure stands.
 */
export const RETRY_DELAYS_MS = [500, 1000, 2000, 4000, 8000, 16000];
let retryDelays = RETRY_DELAYS_MS;
/** Other pauses: shorter ones in tests, none for no retries. */
export const setRetryDelays = (delays) => {
  retryDelays = [...delays];
};

/** What may pass: the tunnel didn't reach the server (502), the server's storage is out of reach (503), a timeout (504). */
const PASSING = new Set([502, 503, 504]);

/** Waits `ms`, or rejects with the signal's reason when it is aborted first. */
function pause(ms, signal) {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const aborted = () => {
      clearTimeout(timer);
      reject(signal.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", aborted);
      resolve();
    }, ms);
    signal?.addEventListener("abort", aborted, { once: true });
  });
}

/**
 * `fetch`, made again after a pause while it fails in a way that may pass: a network error (a TypeError, which an
 * abort isn't), or a status in PASSING. Only for requests that may be made twice (`retried`).
 */
async function send(url, init, retried) {
  for (const delay of retried ? retryDelays : []) {
    try {
      const response = await fetch(url, init);
      if (!PASSING.has(response.status)) return response;
      await response.body?.cancel().catch(() => {});
    } catch (error) {
      if (!(error instanceof TypeError) || init.signal?.aborted) throw error;
    }
    await pause(delay, init.signal);
  }
  return fetch(url, init);
}

/** `retried`: the request may be made again after a failure that may pass (`send`): it does the same twice. */
async function call(method, path, { json, body, headers = {}, okStatuses = [], quiet401 = false, signal, retried = false } = {}) {
  const init = { method, headers: { ...headers }, credentials: "same-origin", signal };
  if (json !== undefined) {
    init.body = JSON.stringify(json);
    init.headers["Content-Type"] = "application/json";
  } else if (body !== undefined) {
    init.body = body;
    init.headers["Content-Type"] = "application/octet-stream";
  }
  const response = await send(`/api/v1${path}`, init, retried);
  if (response.ok || okStatuses.includes(response.status)) return response;
  const error = new ApiError(response.status, await response.json().catch(() => null));
  if (response.status === 401 && error.code === "unauthenticated" && !quiet401) onUnauthenticated();
  throw error;
}

const json = async (response) => (response.status === 204 ? null : response.json());

export const me = () =>
  call("GET", "/me", { quiet401: true, retried: true })
    .then(json)
    .catch((e) => (e.status === 401 ? null : Promise.reject(e)));
export const loginStart = () => call("POST", "/auth/login/start", { json: {} }).then(json);
export const loginFinish = (credential) => call("POST", "/auth/login/finish", { json: { credential } }).then(json);
export const exchangeSetupToken = (token) => call("POST", "/auth/setup-token", { json: { token } }).then(json);
export const logout = () => call("POST", "/auth/logout", { json: {} }).then(json);
export const passkeys = () => call("GET", "/me/passkeys", { retried: true }).then(json);
export const registerStart = () => call("POST", "/me/passkeys/register/start", { json: {} }).then(json);
export const registerFinish = (name, credential) => call("POST", "/me/passkeys/register/finish", { json: { name, credential } }).then(json);

/** The ref's target blob ID, or null if the ref doesn't exist. */
export async function getRef(name) {
  const response = await call("GET", `/refs/${name}`, { okStatuses: [404], retried: true });
  return response.status === 404 ? null : checkBlobId((await response.json()).blob);
}

/**
 * Writes a ref. `expected` is the blob ID it must currently point to, or null for "must not exist".
 * Returns { ok: true } or, on 412, { ok: false, current }. A ref already pointing to `blobId` counts as written: it
 * holds exactly what this write puts there, as a blob's ID is its content's hash. That is a write made again after its
 * answer was lost (SPEC §6.14).
 */
export async function putRef(name, blobId, expected) {
  const headers = expected === null ? { "If-None-Match": "*" } : { "If-Match": `"${checkBlobId(expected)}"` };
  const response = await call("PUT", `/refs/${name}`, { json: { blob: blobId }, headers, okStatuses: [412], retried: true });
  if (response.status === 412) {
    const current = (await response.json()).current;
    if (current === blobId) return { ok: true };
    return { ok: false, current: current === null ? null : checkBlobId(current) };
  }
  return { ok: true };
}

/** Uploads a blob under its SHA-256 and returns the ID. `offloadable` (SPEC §6.13) only applies to a new blob. */
export async function putBlob(bytes, { offloadable = false, signal } = {}) {
  const id = await sha256Hex(bytes);
  await call("PUT", `/blobs/${id}`, { body: bytes, headers: offloadable ? { "Blob-Offloadable": "true" } : {}, signal, retried: true });
  return id;
}

/** Sets whether a blob is offloadable (SPEC §6.13). */
export async function setOffloadable(id, offloadable) {
  await call("PATCH", `/blobs/${checkBlobId(id)}`, { json: { offloadable }, retried: true });
}

/** Downloads a blob and checks that it hashes to its ID. */
export async function getBlob(id) {
  const data = new Uint8Array(await (await call("GET", `/blobs/${checkBlobId(id)}`, { retried: true }).catch(lost(id))).arrayBuffer());
  if ((await sha256Hex(data)) !== id) throw new IntegrityError(`blob ${id}`);
  return data;
}

/**
 * A blob's bytes as they arrive: all of them, or `range` ({ from, to }: [from, to), `to` null for the rest).
 * → { start, total, body }: the offset the body starts at, and the blob's size from `Content-Range`; a server that
 * sends the whole blob instead gives start 0 and no size. The bytes aren't checked here: blobs.js does that.
 */
export async function getBlobStream(id, { range = null, signal } = {}) {
  const headers = range === null ? {} : { Range: `bytes=${range.from}-${range.to === null ? "" : range.to - 1}` };
  const response = await call("GET", `/blobs/${checkBlobId(id)}`, { headers, signal, retried: true }).catch(lost(id));
  if (response.status !== 206) return { start: 0, total: null, body: response.body };
  const match = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(response.headers.get("content-range") ?? "");
  const [start, end, total] = (match ?? []).slice(1).map(Number);
  const asked = range !== null && start === range.from && start <= end && end < total && (range.to === null || end < range.to);
  if (!match || !asked) throw new IntegrityError(`blob ${id} came back with a range that wasn't asked for`);
  return { start, total, body: response.body };
}

export const deletePasskey = (id) => call("DELETE", `/me/passkeys/${encodeURIComponent(id)}`).then(json);
export const createSetupToken = () => call("POST", "/me/setup-tokens", { json: {} }).then(json);

/**
 * One page of blobs, plus the server's clock from the `Date` header (for the cleanup grace period); null without
 * one. Never this device's clock: blobs' times are the server's, and the two clocks can be days apart.
 */
export async function listBlobs(after = null) {
  const response = await call("GET", `/blobs${after ? `?after=${checkBlobId(after)}` : ""}`, { retried: true });
  const date = Date.parse(response.headers.get("date") ?? "");
  return { ...(await response.json()), serverNow: Number.isNaN(date) ? null : date };
}

/** Deletes a blob; one that is already gone counts as deleted. */
export async function deleteBlob(id) {
  await call("DELETE", `/blobs/${checkBlobId(id)}`, { okStatuses: [404], retried: true });
}
