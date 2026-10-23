// Stand-ins for what surrounds the SDK in a browser, so the flows run under `node --test`:
//
// - the backend behind `fetch`: blobs, refs, passkeys and a session, with the behaviour of backend/SPEC.md §7–§8
//   that the SDK relies on (compare-and-swap refs, hash-checked uploads, ranges, step-up). Passkeys belong to ALICE unless
//   they name another user; the storage is ALICE's whoever logs in.
// - a platform authenticator with PRF behind `navigator.credentials`
//
// Both are plain state the tests read and change directly, e.g. to play another device or a misbehaving server.

import { createHash, createHmac, randomBytes } from "node:crypto";

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const iso = (ms) => new Date(ms).toISOString();
export const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

export const ALICE = { id: "00000000-0000-4000-8000-000000000001", username: "alice", created_at: "2020-01-01T00:00:00.000Z" };
export const BOB = { id: "00000000-0000-4000-8000-000000000002", username: "bob", created_at: "2020-01-01T00:00:00.000Z" };
const owner = (entry) => entry.user ?? ALICE;

export function fakeServer() {
  const server = {
    /** The server's clock: blobs' `created_at` and the `Date` header. Deliberately far from the client's. */
    now: Date.parse("2020-01-01T00:00:00Z"),
    pageSize: 1000,
    /** Whether responses carry the server's clock in a `Date` header. */
    sendsDate: true,
    setupToken: null,
    /** { user (ALICE if not set), passkey: credential ID or null for a setup-token session, fresh: within the step-up window } */
    session: null,
    passkeys: new Map(), // credential ID → { name, user (ALICE if not set) }
    blobs: new Map(), // blob ID → { bytes, created_at }
    refs: new Map(), // ref name → blob ID
    challenges: new Set(),
    /** Every request: { method, path, json, range, signal }. */
    requests: [],
    /** Blob bodies arrive in pieces of this many bytes, as from a network. */
    pieceSize: 16 * 1024,
    /** Answers a `Range` request with the whole blob, as a server without range support would. */
    ignoresRanges: false,
    /** Runs just before a ref write is checked: another device can write first. */
    beforeRefWrite: (_name) => {},
    /** Blob IDs whose deletion fails with a 500. */
    failingDeletes: new Set(),

    /** Stores a blob as if uploaded now; returns its ID. */
    put(bytes) {
      const id = sha256Hex(bytes);
      if (!server.blobs.has(id)) server.blobs.set(id, { bytes: new Uint8Array(bytes), created_at: server.now });
      return id;
    },
    /** The bytes a ref points to. */
    read(ref) {
      return server.blobs.get(server.refs.get(ref))?.bytes;
    },
  };

  const reply = (status, body) =>
    new Response(status === 204 ? null : body instanceof Uint8Array ? body : JSON.stringify(body), {
      status,
      headers: server.sendsDate ? { date: new Date(server.now).toUTCString() } : {},
    });
  const error = (status, code) => reply(status, { error: code, message: `server says: ${code}` });

  /** A blob body that arrives in pieces and breaks off when the request is aborted, like fetch's. */
  const pieces = (bytes, signal) =>
    new ReadableStream({
      start(controller) {
        signal?.addEventListener("abort", () => controller.error(signal.reason), { once: true });
      },
      pull(controller) {
        if (bytes.length === 0) return controller.close();
        controller.enqueue(bytes.slice(0, server.pieceSize));
        bytes = bytes.subarray(server.pieceSize);
      },
    });

  /** backend/SPEC.md §8.4: one range of the forms a-b, a- and -n; anything else is the whole blob. */
  function byteRange(header, size) {
    const match = /^bytes=(\d*)-(\d*)$/.exec(header ?? "");
    if (!match || (match[1] === "" && match[2] === "")) return "full";
    const [first, last] = [match[1], match[2]].map((n) => (n === "" ? null : Number(n)));
    if (first === null) return last === 0 || size === 0 ? "unsatisfiable" : { start: Math.max(0, size - last), end: size - 1 };
    if (last !== null && last < first) return "full";
    return first >= size ? "unsatisfiable" : { start: first, end: Math.min(last ?? size - 1, size - 1) };
  }

  function getBlob({ match, headers, signal }) {
    const blob = server.blobs.get(match[1]);
    if (!blob) return error(404, "not_found");
    const size = blob.bytes.length;
    const range = server.ignoresRanges ? "full" : byteRange(headers.Range, size);
    const date = server.sendsDate ? { date: new Date(server.now).toUTCString() } : {};
    if (range === "unsatisfiable") {
      return new Response(JSON.stringify({ error: "range_not_satisfiable", message: "server says: range_not_satisfiable" }), {
        status: 416,
        headers: { ...date, "content-range": `bytes */${size}` },
      });
    }
    const { start, end } = range === "full" ? { start: 0, end: size - 1 } : range;
    const partial = range !== "full";
    return new Response(pieces(blob.bytes.subarray(start, end + 1), signal), {
      status: partial ? 206 : 200,
      headers: { ...date, "content-length": String(end + 1 - start), ...(partial ? { "content-range": `bytes ${start}-${end}/${size}` } : {}) },
    });
  }

  const authed = (handler) => (request) => (server.session ? handler(request) : error(401, "unauthenticated"));
  const fresh = (handler) => authed((request) => (server.session.fresh ? handler(request) : error(403, "reauth_required")));

  /** The ceremony's challenge, used up; false if the response doesn't answer one of ours. */
  const takeChallenge = (credential, type) => {
    const clientData = JSON.parse(Buffer.from(credential.response.clientDataJSON, "base64url"));
    return clientData.type === type && server.challenges.delete(clientData.challenge);
  };
  const newChallenge = () => {
    const challenge = b64url(randomBytes(16));
    server.challenges.add(challenge);
    return challenge;
  };

  const routes = [
    ["GET", /^\/me$/, authed(() => reply(200, owner(server.session)))],
    ["POST", /^\/auth\/login\/start$/, () => reply(200, { options: { challenge: newChallenge(), rpId: "localhost", allowCredentials: [], userVerification: "required" } })],
    [
      "POST",
      /^\/auth\/login\/finish$/,
      ({ json }) => {
        if (!takeChallenge(json.credential, "webauthn.get") || !server.passkeys.has(json.credential.id)) return error(401, "authentication_failed");
        const user = owner(server.passkeys.get(json.credential.id));
        server.session = { user, passkey: json.credential.id, fresh: true };
        return reply(200, { user });
      },
    ],
    [
      "POST",
      /^\/auth\/setup-token$/,
      ({ json }) => {
        if (!server.setupToken || json.token !== server.setupToken) return error(401, "invalid_token");
        server.setupToken = null;
        server.session = { user: ALICE, passkey: null, fresh: true };
        return reply(200, { user: ALICE });
      },
    ],
    [
      "POST",
      /^\/auth\/logout$/,
      () => {
        server.session = null;
        return reply(204);
      },
    ],
    [
      "GET",
      /^\/me\/passkeys$/,
      authed(() => {
        const own = [...server.passkeys].filter(([, passkey]) => owner(passkey) === owner(server.session));
        return reply(200, { passkeys: own.map(([id, { name }]) => ({ id, name, rp_id: "localhost", current: id === server.session.passkey })) });
      }),
    ],
    [
      "POST",
      /^\/me\/passkeys\/register\/start$/,
      fresh(() =>
        reply(200, {
          options: {
            challenge: newChallenge(),
            rp: { id: "localhost", name: "Test" },
            user: { id: b64url(Buffer.from(owner(server.session).id)), name: owner(server.session).username, displayName: owner(server.session).username },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            excludeCredentials: [...server.passkeys.keys()].map((id) => ({ type: "public-key", id })),
            authenticatorSelection: { residentKey: "required", userVerification: "required" },
            attestation: "none",
            extensions: {},
          },
        }),
      ),
    ],
    [
      "POST",
      /^\/me\/passkeys\/register\/finish$/,
      authed(({ json }) => {
        if (!takeChallenge(json.credential, "webauthn.create")) return error(400, "registration_failed");
        if (server.passkeys.has(json.credential.id)) return error(409, "passkey_exists");
        server.passkeys.set(json.credential.id, { name: json.name, user: owner(server.session) });
        return reply(201, { passkey: { id: json.credential.id, name: json.name } });
      }),
    ],
    [
      "DELETE",
      /^\/me\/passkeys\/([^/]+)$/,
      fresh(({ match }) => {
        const id = decodeURIComponent(match[1]);
        if (!server.passkeys.has(id) || owner(server.passkeys.get(id)) !== owner(server.session)) return error(404, "not_found");
        if ([...server.passkeys.values()].filter((p) => owner(p) === owner(server.session)).length === 1) return error(409, "last_passkey");
        server.passkeys.delete(id);
        if (server.session.passkey === id) server.session = null;
        return reply(204);
      }),
    ],
    [
      "GET",
      /^\/blobs$/,
      authed(({ query }) => {
        const after = query.get("after");
        const ids = [...server.blobs.keys()].sort().filter((id) => !after || id > after);
        const page = ids.slice(0, server.pageSize);
        const meta = (id) => ({ id, size: server.blobs.get(id).bytes.length, created_at: iso(server.blobs.get(id).created_at) });
        return reply(200, { blobs: page.map(meta), next: ids.length > page.length ? page.at(-1) : null });
      }),
    ],
    [
      "PUT",
      /^\/blobs\/([0-9a-f]{64})$/,
      authed(({ match, body }) => {
        if (sha256Hex(body) !== match[1]) return error(400, "hash_mismatch");
        const created = !server.blobs.has(match[1]);
        server.put(body);
        return reply(created ? 201 : 200, { id: match[1], size: body.length, created_at: iso(server.blobs.get(match[1]).created_at) });
      }),
    ],
    ["GET", /^\/blobs\/([0-9a-f]{64})$/, authed(getBlob)],
    [
      "DELETE",
      /^\/blobs\/([0-9a-f]{64})$/,
      authed(({ match }) => {
        const id = match[1];
        if ([...server.refs.values()].includes(id)) return error(409, "blob_referenced");
        if (server.failingDeletes.has(id)) return error(500, "internal");
        return server.blobs.delete(id) ? reply(204) : error(404, "not_found");
      }),
    ],
    ["GET", /^\/refs\/(.+)$/, authed(({ match }) => (server.refs.has(match[1]) ? reply(200, { name: match[1], blob: server.refs.get(match[1]) }) : error(404, "not_found")))],
    [
      "PUT",
      /^\/refs\/(.+)$/,
      authed(({ match, json, headers }) => {
        const name = match[1];
        server.beforeRefWrite(name);
        const current = server.refs.get(name) ?? null;
        const ifMatch = headers["If-Match"];
        const holds = headers["If-None-Match"] === "*" ? current === null : ifMatch === undefined || ifMatch === `"${current}"`;
        if (!holds) return reply(412, { error: "precondition_failed", message: "server says: precondition_failed", current });
        if (!server.blobs.has(json.blob)) return error(409, "blob_not_found");
        server.refs.set(name, json.blob);
        return reply(current === null ? 201 : 200, { name, blob: json.blob });
      }),
    ],
  ];

  server.fetch = async (url, init = {}) => {
    const { pathname, searchParams } = new URL(url, "http://localhost");
    const path = pathname.replace(/^\/api\/v1/, "");
    const method = init.method ?? "GET";
    const headers = init.headers ?? {};
    const json = headers["Content-Type"] === "application/json" ? JSON.parse(init.body) : undefined;
    const body = headers["Content-Type"] === "application/octet-stream" ? new Uint8Array(init.body) : undefined;
    server.requests.push({ method, path, json, range: headers.Range, signal: init.signal });
    init.signal?.throwIfAborted();
    for (const [routeMethod, pattern, handler] of routes) {
      const match = routeMethod === method && path.match(pattern);
      if (match) return handler({ match, json, body, headers, query: searchParams, signal: init.signal });
    }
    return error(404, "not_found");
  };
  return server;
}

/**
 * `prf`: the authenticator supports PRF. `prfAtCreate`: it also returns the output at registration (some give
 * it only at sign-in).
 */
export function fakeAuthenticator({ prf = true, prfAtCreate = true } = {}) {
  const authenticator = {
    prf,
    prfAtCreate,
    credentials: new Map(), // credential ID → (PRF input) → 32-byte output
    /** The credential a discoverable sign-in answers with; the newest one if null. */
    pick: null,
    newest: null,
    /** The `allowCredentials` IDs of every sign-in. */
    signIns: [],

    /** Adds a credential with a given PRF function, e.g. a fixed output for test vectors. */
    add(id, prfOf) {
      authenticator.credentials.set(id, prfOf);
      authenticator.newest = id;
    },
  };

  const credential = (id, type, challenge, output, response) => {
    const prfResults = (first) => (authenticator.prf ? { prf: { ...(type === "webauthn.create" ? { enabled: true } : {}), ...(output ? { results: { first } } : {}) } } : {});
    return {
      id,
      rawId: new Uint8Array(Buffer.from(id, "base64url")).buffer,
      type: "public-key",
      authenticatorAttachment: "platform",
      getClientExtensionResults: () => prfResults(output?.buffer),
      // As browsers serialize it: the PRF output in base64url, which the SDK must not send to the server.
      toJSON: () => ({
        id,
        rawId: id,
        type: "public-key",
        authenticatorAttachment: "platform",
        response: { clientDataJSON: b64url(JSON.stringify({ type, challenge: b64url(challenge) })), ...response },
        clientExtensionResults: prfResults(output && b64url(output)),
      }),
    };
  };
  const prfOutput = (id, publicKey, enabled) => {
    const input = publicKey.extensions?.prf?.eval?.first;
    return enabled && input ? authenticator.credentials.get(id)(input) : null;
  };

  authenticator.api = {
    async create({ publicKey }) {
      if ((publicKey.excludeCredentials ?? []).some((d) => authenticator.credentials.has(b64url(d.id)))) {
        throw new DOMException("The authenticator already has a credential for this account", "InvalidStateError");
      }
      const id = b64url(randomBytes(16));
      const secret = randomBytes(32);
      authenticator.add(id, (input) => new Uint8Array(createHmac("sha256", secret).update(input).digest()));
      const output = prfOutput(id, publicKey, authenticator.prf && authenticator.prfAtCreate);
      return credential(id, "webauthn.create", publicKey.challenge, output, { attestationObject: "", transports: ["internal"] });
    },
    async get({ publicKey }) {
      const allowed = (publicKey.allowCredentials ?? []).map((d) => b64url(d.id));
      authenticator.signIns.push(allowed);
      const id = allowed.length > 0 ? allowed.find((a) => authenticator.credentials.has(a)) : (authenticator.pick ?? authenticator.newest);
      if (!authenticator.credentials.has(id)) throw new DOMException("No credential was chosen", "NotAllowedError");
      const output = prfOutput(id, publicKey, authenticator.prf);
      return credential(id, "webauthn.get", publicKey.challenge, output, { authenticatorData: "", signature: "", userHandle: "" });
    },
  };
  return authenticator;
}

/** Makes `authenticator` the one `navigator.credentials` uses, e.g. a second device's. */
export function useAuthenticator(authenticator) {
  globalThis.window = globalThis;
  globalThis.PublicKeyCredential ??= class PublicKeyCredential {};
  Object.defineProperty(navigator, "credentials", { value: authenticator.api, configurable: true });
  return authenticator;
}

/** Puts both in place of the browser's `fetch` and `navigator.credentials`. */
export function install(options) {
  const server = fakeServer();
  globalThis.fetch = server.fetch;
  return { server, authenticator: useAuthenticator(fakeAuthenticator(options)) };
}
