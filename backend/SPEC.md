# Backend Specification: Users & Storage

Status: **Draft v0.5** (2026-10-10)

## 1. Purpose & scope

This is a generic backend that does not know about any particular application. It provides:

- **Users** who sign in with **passkeys** (WebAuthn). Accounts are bootstrapped with short-lived **setup tokens**.
- **Git-like storage** for each user: immutable, content-addressed **blobs** and mutable **refs** that point at blobs.

Apps keep all of their logic (data format, encryption, sync) in the browser, on top of the SDK (`../sdk/SPEC.md`). The backend stores only opaque bytes. It must not contain any concepts of a particular app, so every app can use it as it is.

Non-goals for v1:

- Encrypting stored data or interpreting it in any way.
- Sharing data between users.
- Server-side garbage collection. The server cannot see references inside encrypted blobs.
- Self-service sign-up and an admin web UI.

## 2. Key decisions

| #   | Topic              | Decision |
|-----|--------------------|----------|
| D1  | Blob identity      | The ID is the SHA-256 of the content. The client sends it in the URL and the server verifies it. |
| D2  | Ref target         | A ref must point to an existing blob of the same user. A blob can't be deleted while a ref points to it. |
| D3  | Expect / CAS       | Sent as HTTP preconditions: `If-Match: "<id>"` (the ref points to that blob), `If-None-Match: *` (the ref does not exist), `If-Match: *` (the ref exists). |
| D4  | Provisioning       | Users can only be created with the admin CLI. Setup tokens can be created by the CLI, or by a logged-in user for their own account. |
| D5  | Setup token        | Single-use, expires 15 minutes after creation, gives a normal session. |
| D6  | Storage            | SQLite only (metadata and blob bytes). Maximum blob size 16 MiB. No quotas. |
| D7  | Sessions           | `HttpOnly` cookie, expires 4 hours after login, `Secure` only when served over HTTPS. |
| D8  | Network            | The server listens on a Unix domain socket. Browsers reach it through an iroh tunnel (plain HTTP on a loopback name) or through an HTTPS reverse proxy. The backend serves the frontend on both paths. |
| D9  | Hosts              | Only loopback names and the configured public hosts are accepted. The WebAuthn RP ID is the request's host, so each passkey belongs to one host. |
| D10 | PRF                | The client handles PRF entirely. The server never requests or checks it; it only accepts responses that contain extensions it didn't request. |
| D11 | Step-up            | Adding or deleting a passkey, or creating a setup token, needs a session less than 5 minutes old (step-up = log in again). The last passkey can't be deleted. |

## 3. Architecture

- Written in Rust as a single binary `backend`, with subcommands for the server and for admin tasks.
- Suggested crates:
  - `axum` + `tokio` for HTTP.
  - `webauthn_rp` with the features `serde_relaxed` and `serializable_server_state`, for WebAuthn. It is pure Rust on RustCrypto; `webauthn-rs` would bring in OpenSSL.
  - `rusqlite` for SQLite in WAL mode.
  - `sha2`, `getrandom`, `base64`, `serde` + `serde_json`, `toml`, `humantime`, `clap`, `tracing`.
- One crate, with a module for each responsibility:
  - `domain`: pure types and rules. This covers validating IDs, names and hosts, parsing ranges, evaluating preconditions and computing expiry times. It does no I/O, and the current time is always passed in as an argument.
  - `store`: plain functions over a SQLite connection, one per query or transaction; the caller passes the time.
  - `db`: opening the database (WAL, foreign keys) and its migrations.
  - `accounts`: what the HTTP API and the admin commands share: creating users, setup tokens and their links.
  - `passkey`: WebAuthn ceremonies on top of `webauthn_rp`.
  - `secret`: session and setup tokens, of which only hashes are stored.
  - `http`: routes, extractors, the host/origin checks and the mapping from errors to responses.
  - `server`: the Unix socket and the background cleanup.
  - `config`: the configuration file and the environment.
  - `main.rs`: the binary's subcommands, the admin commands among them.

### 3.1 How browsers reach the server

The server listens only on a Unix domain socket, never on a TCP port. There are two ways to reach it:

```
iroh (main):  browser → http://localhost:PORT or http://<label>.localhost:PORT
                → local shim (socat on a laptop, iroh-webview-app on Android)
                → iroh-uds-connect ══ iroh QUIC ══> iroh-uds-listen → backend.sock

direct:       browser → https://app.example.com → reverse proxy (TLS) → backend.sock
```

- **Everything goes to the socket:** on both paths, all requests (API, frontend, `/healthz`) are forwarded to the socket. The backend serves the frontend from `static_dir`, so both paths behave the same.
- **iroh path:** it uses plain HTTP. `localhost` and `*.localhost` are secure contexts, so WebAuthn and WebCrypto work. iroh's QUIC connection encrypts the traffic and authenticates the server by its endpoint ID.
- **Direct path:** the reverse proxy terminates TLS. It must pass the original `Host` header through. Caddy does this by default; nginx needs `proxy_set_header Host $host`.
- **Root-relative URLs:** every URL the server emits is root-relative. The only exception is setup links (§6.6). The iroh path's local port is arbitrary, so an absolute URL would only work from one place.
- **Local development:** `socat TCP-LISTEN:8080,bind=127.0.0.1,fork UNIX-CONNECT:./data/backend.sock`, then open `http://localhost:8080`. This needs no TLS.
- **Socket handling:**
  - On startup, the server removes a stale socket file and creates the socket with mode `0660`.
  - It removes the socket on shutdown.
  - Access is controlled by file permissions: whatever connects (`iroh-uds-listen`, the proxy) must be in the socket's group.

```
backend/   the Rust backend (this spec), no app-specific code
sdk/       the browser side: keys, encryption, flows (../sdk/SPEC.md)
nix/       the NixOS module (one instance per app) and its VM test
```

## 4. Identifiers & formats

| Item          | Format |
|---------------|--------|
| User ID       | UUIDv4 string. Its 16 bytes are also the WebAuthn user handle. |
| Username      | `[a-z0-9._-]{1,64}`, unique. Used only for display and the CLI; login does not use it. |
| Passkey ID    | WebAuthn credential ID, base64url without padding |
| RP ID         | The request's host name without the port, lowercase: `localhost`, `<label>.localhost` or one of `public_hosts` |
| Blob ID       | 64 lowercase hex characters: the SHA-256 of the blob content |
| Ref name      | 1–256 bytes made of `/`-separated segments of `[A-Za-z0-9._-]+`. Segments can't be empty, `.` or `..`. |
| Timestamp     | RFC 3339 UTC with milliseconds, e.g. `2026-10-09T20:57:00.123Z` |
| Secret tokens | 32 bytes from a CSPRNG, encoded as base64url. Only their SHA-256 hash is stored. |

## 5. Data model

```sql
CREATE TABLE users (
  id          BLOB PRIMARY KEY,                 -- 16 bytes
  username    TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL                  -- unix ms (all timestamps)
);

CREATE TABLE passkeys (
  id            BLOB PRIMARY KEY,               -- credential ID
  user_id       BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rp_id         TEXT NOT NULL,                  -- host it was registered on
  name          TEXT NOT NULL,
  static_state  BLOB NOT NULL,                  -- webauthn_rp: public key + extension capabilities
  dynamic_state BLOB NOT NULL,                  -- webauthn_rp: sign counter + flags, updated at login
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER
);

CREATE TABLE sessions (
  token_hash  BLOB PRIMARY KEY,                 -- SHA-256(token)
  user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  passkey_id  BLOB REFERENCES passkeys(id) ON DELETE CASCADE,  -- NULL when created from a setup token
  created_at  INTEGER NOT NULL,                 -- = time of authentication
  expires_at  INTEGER NOT NULL
);
CREATE INDEX sessions_by_expiry ON sessions(expires_at);

CREATE TABLE setup_tokens (
  token_hash  BLOB PRIMARY KEY,
  user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX setup_tokens_by_expiry ON setup_tokens(expires_at);

CREATE TABLE ceremonies (                       -- pending WebAuthn challenges
  challenge   BLOB PRIMARY KEY,                 -- 16 bytes; the browser's response carries it
  kind        TEXT NOT NULL CHECK (kind IN ('login', 'register')),
  user_id     BLOB REFERENCES users(id) ON DELETE CASCADE,  -- set for 'register'
  state       BLOB NOT NULL,                    -- webauthn_rp serialized server state
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX ceremonies_by_expiry ON ceremonies(expires_at);

CREATE TABLE blobs (
  user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  id          BLOB NOT NULL,                    -- 32 bytes
  size        INTEGER NOT NULL,                 -- kept so content can move to another store later
  content     BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  offloadable INTEGER NOT NULL DEFAULT 0 CHECK (offloadable IN (0, 1)),  -- §7.1; added in 1.1
  PRIMARY KEY (user_id, id)
);

CREATE TABLE refs (
  user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  blob_id     BLOB NOT NULL,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, name),
  -- NO ACTION (not RESTRICT): checked at the end of the statement,
  -- so deleting a user still cascades cleanly.
  FOREIGN KEY (user_id, blob_id) REFERENCES blobs(user_id, id)
);
CREATE INDEX refs_by_blob ON refs(user_id, blob_id);
```

### 5.1 Expiry

Every row that can expire stores its `expires_at`, which is set when the row is created and never extended.

- A row is valid only while `now < expires_at`. Lookups filter on this, so an expired row is never used, even before the cleanup task has deleted it.
- A background task runs every 10 minutes and deletes rows with `expires_at <= now`.

| Row         | `expires_at` |
|-------------|--------------|
| Session     | `created_at + session_ttl` (4 h by default) |
| Setup token | `created_at + 15 min` |
| Ceremony    | `created_at + 5 min` |

Step-up (§6.5) is a separate rule based on the session's age. It doesn't change when the session expires.

### 5.2 Schema versions

The schema is migrated with plain SQL when the server starts. Its version is `major.minor`, stored in `PRAGMA user_version` as `major * 1000 + minor`, with `N.0` as the bare `N`: the databases from before versions had a minor hold `1`, which is `1.0`.

The split lets an older binary keep running against a database a newer one has migrated. That happens routinely: the host's nightly upgrade replaces a generation switched to by hand with the one the pipeline last delivered.

| The database is…                  | At startup |
|-----------------------------------|------------|
| older                             | Every pending migration runs, in one transaction |
| at this binary's version          | Nothing; the database isn't written to |
| a newer minor of the same major   | A warning, then the server runs |
| a newer major                     | The server refuses to start |

- **A minor migration may only:**
  - create a table or an index;
  - add a column that is nullable or has a default, so an older binary's `INSERT`, which doesn't name it, still works;
  - rebuild a table to change only how it is stored, keeping every column and refusing exactly the rows it refused before.
- **Everything else is a major:** dropping or renaming a table or column, changing a column's type, a constraint an older binary's writes could break, or a new meaning for existing data. The test is whether the previous binary would still behave correctly against the database.
- **A new major stops every older binary from starting.** Deliver a binary that no longer depends on what the major changes first, through the pipeline, and only then the major. The binary pins its major at compile time, so changing it is a deliberate edit.
- Binaries from before this scheme refuse anything above `1`, so the first one to migrate to `1.1` can't be reverted to them; the server just doesn't start until the newer binary is back.

| Version | Change |
|---------|--------|
| 1.0     | The tables above, without `blobs.offloadable` |
| 1.1     | `blobs.offloadable` |

## 6. Authentication

### 6.1 Hosts and origins

Every request is checked against its `Host` header before anything else.

- **Allowed hosts:** the host must be one of:
  - `localhost` or `*.localhost`, with any port. These are always reached over `http`.
  - An entry of `public_hosts`, which may include a port. These are always reached over `https`.

  Any other host, including IP addresses, is refused with 400 `unknown_host`. Browsers refuse WebAuthn on IP addresses anyway, so `127.0.0.1` couldn't work.
- **Expected origin:** `<scheme>://<Host header>`, where the scheme follows from the host as above.
- **Origin check:** requests other than GET/HEAD must send an `Origin` header equal to the expected origin. Otherwise the server answers 403 `forbidden`.
- **RP ID:** the host without its port.
- **Why this is safe:**
  - Loopback names always resolve to the device the browser runs on, so no remote site can serve a page there.
  - Public hosts are configured explicitly.
  - Together they block DNS rebinding against the local tunnel port.
  - The Origin check is the main CSRF defense. `SameSite` ignores the port, so any page served from another port on `localhost` counts as same-site.

### 6.2 Passkeys (WebAuthn)

- **Library:** `webauthn_rp`, configured with `error_on_unsolicited_extensions = false` for both registration and login (see §6.3). Ceremony state is serialized into the `ceremonies` table.
- **Registration:**
  - Options: `residentKey: required`, `userVerification: required`, `attestation: none`.
  - Algorithms offered include ES256, which is all the Android app's authenticator supports.
  - `credProtect` is not requested.
  - `excludeCredentials` lists the user's passkeys for the same RP ID.
  - The passkey is stored with the RP ID it was registered on.
- **Login:** uses discoverable credentials, so no username is needed. `allowCredentials` is empty and `userVerification: required`.
  - The server looks up the passkey by credential ID.
  - The passkey's stored RP ID must equal the request's RP ID, and the user handle must match its owner.
  - A sign counter that stays at 0 is accepted. Synced passkeys and the Android app never increment it.
  - On success, the server updates the passkey's dynamic state and `last_used_at`.
- **Verification:** responses are checked against the `finish` request's own origin (port included) and RP ID. A ceremony started on one host or port therefore can't be finished from another.
- **JSON format:** options and credentials use the WebAuthn Level 3 JSON encoding (base64url). The frontend can therefore use `PublicKeyCredential.parseCreationOptionsFromJSON()`, `parseRequestOptionsFromJSON()` and `credential.toJSON()`.
- **Ceremonies:** each ceremony can be used once and is deleted before verification, whatever the outcome. A registration ceremony is bound to the user who started it. Ceremonies are looked up by their challenge, which the browser's response carries, so the client never sends a ceremony ID.

### 6.3 PRF extension

The client handles PRF for end-to-end encryption; the server takes no part in it.

- **Client responsibilities:**
  - Add `prf` to the registration and login options before calling `navigator.credentials.create()` / `get()`.
  - Check `prf.enabled`.
  - Remove `clientExtensionResults.prf.results` before sending the credential to the server.
- **Server:** it never requests PRF and never checks it.
  - It accepts responses that contain extensions it didn't ask for. This covers `prf` in the client results and `hmac-secret` in the authenticator data.
  - `webauthn_rp` still records at registration whether a credential supports `hmac-secret`, and checks later logins against that.
  - The server never stores or logs client extension results.
- **Per-passkey keys:** passkeys are tied to one host and PRF output is different for every passkey. Wrapping the data key once per passkey, and moving keys to a new host, is the SDK's job (`../sdk/SPEC.md` §3).

### 6.4 Sessions

- **Creation:** a session is created by a successful passkey login or by exchanging a setup token. If the login request already carries a valid session cookie, that old session is deleted.
- **Lifetime:** a session expires `session_ttl` (4 hours by default) after it is created. Activity doesn't extend it.
- **Cookie:** `session=<token>; Path=/; HttpOnly; SameSite=Strict; Max-Age=<session_ttl>`.
  - `Secure` is added on public hosts (HTTPS) only. On the iroh path, browsers may withhold a `Secure` cookie from `http://localhost`. There, iroh provides the transport security.
  - The `__Host-` name prefix isn't used, because it requires `Secure`.
- **Scope:** the cookie has no `Domain`, so it belongs to one host only. A session only works on the host where it was created.
- **Passkey deletion:** deleting a passkey deletes every session created with it.
- **CSRF defense:**
  - The Origin check (§6.1).
  - `SameSite=Strict` cookies.
  - Blob uploads require `Content-Type: application/octet-stream` and JSON bodies require `application/json`. Both force a CORS preflight, and CORS is not enabled.

### 6.5 Step-up

These actions need a recently authenticated session:

- registering a passkey (checked at `start`)
- deleting a passkey
- creating a setup token

A session counts as recent while `now < session.created_at + reauth_window` (5 minutes by default).

If the session is too old, the server returns 403 `reauth_required`. The client then logs in with a passkey, which creates a fresh session, and retries. A session created from a setup token is always fresh, so the bootstrap flow needs no extra prompt.

### 6.6 Setup tokens

- **Creation:** setup tokens can be created in two ways. Either way, the token is shown once.
  - By the admin CLI: `user create` and `setup-token create`.
  - By a logged-in user for their own account: `POST /me/setup-tokens`. This needs step-up, and the session must have been created with a passkey (not from a setup token). Otherwise a stolen setup-token session could keep creating setup tokens and renew itself forever, invisibly, even after every passkey is deleted.
- **Purposes:**
  - Bootstrapping a new user.
  - Adding a device on a host where the user has no passkey yet (passkeys are tied to one host, §6.1).
  - Recovery after losing all passkeys.
- **Links:**
  - A setup link is `<origin>/#setup=<token>`. Putting the token in the URL fragment keeps it out of server and proxy logs.
  - The fragment is a list of URL-encoded parameters. `setup` belongs to the backend, and the application may add parameters of its own.
  - The server builds full links only for `public_hosts`. For the iroh path, the user appends `/#setup=<token>` to their local address.
- **Validity:** a token expires 15 minutes after it is created and can be used once (the row is deleted when it is exchanged). A user can have several outstanding tokens.
- **Use:** exchanging the token gives a normal session. The expected flow is: exchange the token, register a passkey for this host, then use the app.
- **Recovery and encrypted data:** a setup token restores access to the account, not to the data. Data encrypted with keys derived from the lost passkeys can't be decrypted unless the application has its own recovery mechanism, such as the SDK's recovery key (`../sdk/SPEC.md` §3.4).
- **Errors:** the client can't tell an unknown, expired or used token apart. All of them return 401 `invalid_token`.

## 7. Storage semantics

All storage belongs to one user. Every store query takes the `user_id` from the session, never from the request.

### 7.1 Blobs

- Blobs are immutable. There is no deduplication across users, and users can't see each other's blobs.
- Uploading is idempotent. Uploading an ID that already exists does nothing, and `created_at` stays the same.
- A blob can't be deleted while a ref points to it (409).
- Each upload is limited by `max_blob_size` (16 MiB by default). There are no per-user quotas.
- **Offloadable blobs.** A client can flag a blob as offloadable: the server may then keep its content outside the database (e.g. in S3, §13), where reads are slower and the content may be lost along with that storage.
  - The flag is set when the blob is uploaded, and only then: re-uploading an existing blob keeps its flag. It can be changed any time afterwards.
  - A ref can't point to an offloadable blob, and a blob a ref points to can't be flagged (409 `blob_offloadable`). What refs point to stays in the database, so a client can always find its way in.
  - For now, every blob's content is in the database; the flag is only stored. A read of a blob whose content is lost returns 410 `blob_lost`, which nothing can produce yet.
  - Binaries before 1.1 (§5.2) upload blobs that aren't offloadable and don't check refs against the flag. Nothing is offloaded yet, so that's harmless.
- Reads use SQLite's incremental BLOB I/O, so a `Range` read holds only the requested bytes in memory. SQLite still reads every page up to the range's end, which makes ranges near the start cheap and ranges near the end of a large blob cost about as much I/O as a full read.

### 7.2 Refs

- A ref is a mutable, named pointer to a blob of the same user. Writing a ref to a blob that doesn't exist fails, so refs never dangle.
- Compare-and-swap works like `git update-ref <name> <new> <old>`. It uses HTTP preconditions on the blob ID the ref currently points to. "Does not exist" is expressed with `If-None-Match: *`.

| Header             | Expectation                | Current ref state          | Result |
|--------------------|----------------------------|----------------------------|--------|
| none               | –                          | any                        | write / delete runs |
| `If-None-Match: *` | ref does not exist         | missing                    | write creates the ref (PUT only) |
| `If-None-Match: *` | ref does not exist         | exists                     | 412 |
| `If-Match: "<id>"` | ref points to `<id>`       | points to `<id>`           | write / delete runs |
| `If-Match: "<id>"` | ref points to `<id>`       | points elsewhere / missing | 412 |
| `If-Match: *`      | ref exists                 | exists                     | write / delete runs |
| `If-Match: *`      | ref exists                 | missing                    | 412 |

- Rejected header combinations (400):
  - `If-Match` and `If-None-Match` sent together.
  - A list of several ETags.
  - `If-None-Match` on DELETE.
- A 412 response always includes the current state (`"current": "<id>"` or `null`), so the client can merge and retry without another request.
- Each ref is updated atomically. There are no multi-ref transactions in v1.

### 7.3 Client usage notes (non-normative)

- **Typical write:**
  1. Upload the new blobs.
  2. Compare-and-swap the ref. When creating a ref, use `If-None-Match: *`.
  3. If that returns 412, merge with `current` and retry.
- **Client-side garbage collection:**
  - Delete only blobs that no ref can reach, and only if their `created_at` is older than a grace period (e.g. 24 h). Another client may have uploaded blobs that it hasn't referenced yet.
  - Re-uploading an existing blob does not refresh its `created_at`.
- **Metadata the server sees:** ref names, blob sizes, counts and timing. Don't put secrets in ref names.
- **Ref names from credential IDs:** credential IDs can be up to 1023 bytes. Hash them before using them in a ref name (e.g. a per-passkey key ref).

## 8. HTTP API

- **Base path:** `/api/v1`. Requests and responses are JSON unless noted.
- **Errors:** `{"error": "<code>", "message": "<human readable>"}`, for every API error, including a query string that doesn't parse or a method a route doesn't have.
- **Response headers:** every API response has `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
- **Request limits:** JSON request bodies are limited to 64 KiB.
- **Authentication:** session-authenticated endpoints return 401 `unauthenticated` when there is no valid session.

### 8.1 Overview

| Method    | Path                           | Auth              | Purpose |
|-----------|--------------------------------|-------------------|---------|
| POST      | `/auth/login/start`            | –                 | Begin passkey login |
| POST      | `/auth/login/finish`           | –                 | Complete login and set the session cookie |
| POST      | `/auth/setup-token`            | –                 | Exchange a setup token for a session |
| POST      | `/auth/logout`                 | session           | End the current session |
| GET       | `/me`                          | session           | Current user |
| POST      | `/me/setup-tokens`             | session + step-up | Create a setup token for yourself |
| GET       | `/me/passkeys`                 | session           | List passkeys |
| POST      | `/me/passkeys/register/start`  | session + step-up | Begin passkey registration |
| POST      | `/me/passkeys/register/finish` | session           | Complete passkey registration |
| DELETE    | `/me/passkeys/{id}`            | session + step-up | Delete a passkey |
| GET       | `/blobs`                       | session           | List blobs |
| PUT       | `/blobs/{id}`                  | session           | Upload a blob |
| GET, HEAD | `/blobs/{id}`                  | session           | Read a blob (supports Range) |
| PATCH     | `/blobs/{id}`                  | session           | Change whether a blob is offloadable |
| DELETE    | `/blobs/{id}`                  | session           | Delete a blob |
| GET       | `/refs`                        | session           | List refs |
| GET       | `/refs/{name}`                 | session           | Read a ref |
| PUT       | `/refs/{name}`                 | session           | Write a ref (supports expect) |
| DELETE    | `/refs/{name}`                 | session           | Delete a ref (supports expect) |
| GET       | `/healthz` (outside `/api/v1`) | –                 | Liveness check |
| GET       | everything else                | –                 | Frontend files from `static_dir` |

### 8.2 Auth

`POST /auth/login/start`, body `{}`:
```json
{ "options": { "challenge": "…", "rpId": "…", "allowCredentials": [], "userVerification": "required" } }
```

`options` is the WebAuthn Level 3 JSON form of the options (the `publicKey` member), ready for `PublicKeyCredential.parseRequestOptionsFromJSON()` / `parseCreationOptionsFromJSON()`.

`POST /auth/login/finish`:
```json
{ "credential": { "...": "PublicKeyCredential.toJSON(), without prf results" } }
```
- **200** `{"user": {"id": "…", "username": "alice", "created_at": "…"}}` (as `GET /me`), plus `Set-Cookie`.
- **401** `authentication_failed`. Causes: unknown credential, a passkey registered on another host, a bad signature, or a ceremony that has expired or doesn't exist.

`POST /auth/setup-token`, body `{"token": "…"}`:
- **200** `{"user": {...}}`, plus `Set-Cookie`.
- **401** `invalid_token`.

`POST /auth/logout`:
- **204**. Deletes the session and clears the cookie. Also returns 204 when there is no session.

### 8.3 Me, setup tokens & passkeys

`GET /me` returns:
```json
{ "id": "…", "username": "alice", "created_at": "…" }
```

`POST /me/setup-tokens`, body `{}`, returns **201**:
```json
{ "token": "…", "expires_at": "…", "links": [ "https://app.example.com/#setup=…" ] }
```
`links` has one entry per configured public host and is empty when there are none.
- **403** `reauth_required`: the session is older than the step-up window.
- **403** `passkey_session_required`: the session wasn't created with a passkey.

`GET /me/passkeys` returns:
```json
{ "passkeys": [ { "id": "…", "name": "YubiKey", "rp_id": "localhost", "created_at": "…", "last_used_at": "…", "current": true } ] }
```
`current` is true for the passkey that the current session was created with. `last_used_at` can be `null`.

`POST /me/passkeys/register/start`, body `{}`:
- Returns `{"options"}`.

`POST /me/passkeys/register/finish`, body `{"name", "credential"}`. `name` is 1–64 characters.
- **201** `{"passkey": {...}}`.
- **400** `registration_failed`.
- **409** `passkey_exists`.

`DELETE /me/passkeys/{id}`:
- **204**. Also revokes the sessions created with this passkey, including the current session if it used this passkey.
- **404** `not_found`.
- **409** `last_passkey`.

### 8.4 Blobs

`PUT /blobs/{id}` takes the raw bytes as the body, with `Content-Type: application/octet-stream`, and an optional `Blob-Offloadable: true` or `false` (the default) for a new blob (§7.1):
- **201** if the blob is new, **200** if it already existed. Body: `{"id", "size", "created_at", "offloadable"}`.
- **400** `hash_mismatch`; `bad_request` for any other `Blob-Offloadable` value.
- **413** `blob_too_large`.
- **415** `unsupported_media_type`.

`GET /blobs/{id}`:
- **Response:** 200 with the full body. With a single satisfiable `Range: bytes=…` header (forms `a-b`, `a-`, `-n`) it returns 206 with `Content-Range`.
- **Multiple ranges:** the server ignores the header and returns 200 with the full body.
- **Unsatisfiable range:** 416 with `Content-Range: bytes */<size>`.
- **Headers:**
  - `Content-Type: application/octet-stream`
  - `Content-Length`
  - `Accept-Ranges: bytes`
  - `ETag: "<id>"`
  - `Content-Disposition: attachment`
  - `Content-Security-Policy: default-src 'none'; sandbox`
- **HEAD:** same headers, no body.
- **404** `not_found`.
- **410** `blob_lost`: the blob was offloadable and its content is gone (§7.1).

`PATCH /blobs/{id}`, body `{"offloadable": true | false}`:
- **200** with `{"id", "size", "created_at", "offloadable"}`, also when the flag already had that value.
- **404** `not_found`.
- **409** `blob_offloadable`: a ref points to the blob.

`DELETE /blobs/{id}`:
- **204**.
- **404** `not_found`.
- **409** `blob_referenced`.

`GET /blobs?after=<id>&limit=<n>` returns:
```json
{ "blobs": [ { "id": "…", "size": 123, "created_at": "…", "offloadable": false } ], "next": "<id>" }
```
- Blobs are sorted by ID.
- `limit` defaults to 1000, which is also the maximum.
- `next` is the `after` value for the next page, or `null` when there are no more pages.

### 8.5 Refs

The ref name is the raw path after `/refs/`. Slashes stay as they are; no percent-encoding is needed because the allowed characters are URL-safe.

`GET /refs/{name}`:
- **200** `{"name", "blob", "updated_at"}`, with `ETag: "<blob>"`.
- **404** `not_found`.

`PUT /refs/{name}`, body `{"blob": "<id>"}`, plus optional precondition headers (§7.2):
- **201** if the ref was created, **200** if it was updated. Body: `{"name", "blob", "updated_at"}`.
- **409** `blob_not_found`; `blob_offloadable` when the target blob is offloadable.
- **412** `precondition_failed`, with body `{"error": "precondition_failed", "message": "…", "current": "<id>" | null}`.

`DELETE /refs/{name}`, with an optional `If-Match` header:
- **204**.
- **404** `not_found`, only when no precondition was sent.
- **412** with `current`.

`GET /refs?prefix=<p>&after=<name>&limit=<n>` returns:
```json
{ "refs": [ { "name": "…", "blob": "…", "updated_at": "…" } ], "next": "<name>" }
```
- `prefix` is a plain string prefix; it doesn't match whole segments.
- Refs are sorted by name, comparing bytes.
- `next` is the `after` value for the next page, or `null`.

### 8.6 Static files

- **What is served:** GET and HEAD for any path outside `/api/` and `/healthz` are served from `static_dir`.
  - `/` serves `index.html`.
  - There is no fallback to `index.html` for unknown paths, and no directory listing. Missing files return 404.
  - Paths that try to escape `static_dir` are refused.
- **Headers:**
  - `Content-Type` based on the file extension.
  - `Content-Security-Policy: <static_csp>`.
  - `X-Content-Type-Options: nosniff`.
  - `Referrer-Policy: no-referrer`.
  - `Cache-Control: no-cache`, so a new deploy takes effect on the next load.
- **Default `static_csp`:** `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.

### 8.7 Error codes

| HTTP | `error`                  | When |
|------|--------------------------|------|
| 400  | `bad_request`            | Malformed input, invalid ID or name, conflicting precondition headers |
| 400  | `unknown_host`           | `Host` is neither a loopback name nor a public host |
| 400  | `hash_mismatch`          | The uploaded bytes don't hash to the blob ID |
| 400  | `registration_failed`    | WebAuthn registration couldn't be verified |
| 401  | `unauthenticated`        | No valid session |
| 401  | `authentication_failed`  | Passkey login failed |
| 401  | `invalid_token`          | The setup token is unknown, expired or already used |
| 403  | `forbidden`              | The Origin check failed |
| 403  | `reauth_required`        | Step-up is needed |
| 403  | `passkey_session_required` | Creating a setup token needs a session created with a passkey |
| 404  | `not_found`              | The blob, ref, passkey or API route doesn't exist |
| 405  | `method_not_allowed`     | The route doesn't have this method; `Allow` lists the ones it has |
| 409  | `blob_referenced`        | A ref still points to the blob |
| 409  | `blob_not_found`         | The ref target doesn't exist |
| 409  | `blob_offloadable`       | A ref would point to an offloadable blob |
| 409  | `last_passkey`           | The user tried to delete their only passkey |
| 409  | `passkey_exists`         | The credential is already registered |
| 410  | `blob_lost`              | The offloadable blob's content is gone |
| 412  | `precondition_failed`    | The expect check failed |
| 413  | `blob_too_large`         | The blob is larger than `max_blob_size`, or a JSON body is over 64 KiB |
| 415  | `unsupported_media_type` | Wrong `Content-Type` |
| 416  | `range_not_satisfiable`  | The range is outside the blob |
| 500  | `internal`               | Anything else; the details are only logged |

## 9. Admin CLI

The CLI works directly on the database. This is safe while the server is running because the database uses WAL mode.

```
backend serve                            run the server on the Unix socket
backend user create <username>           create a user; print a setup token (+ links)
backend user list                        username, id, created_at, passkeys per host, storage used
backend user delete <username> [--yes]   delete the user and all their data
backend setup-token create <username>    print a new setup token (+ links), valid for 15 min
```

- Every command accepts `--config <path>`, which defaults to `./config.toml`.
- Setup tokens are printed as the raw token, the iroh hint `append /#setup=<token> to your local address`, and one link per public host.

## 10. Configuration

Settings come from a TOML file. Any key can be overridden with an environment variable `BACKEND_<KEY>`.

| Key             | Default                  | Meaning |
|-----------------|--------------------------|---------|
| `socket`        | `./data/backend.sock`    | Path of the Unix domain socket the server listens on |
| `database`      | `./data/backend.sqlite3` | Path of the SQLite file |
| `static_dir`    | (required)               | Frontend files, served for every path outside `/api/` and `/healthz` |
| `static_csp`    | see §8.6                 | `Content-Security-Policy` header sent with static files |
| `public_hosts`  | `[]`                     | Hosts reached over HTTPS, e.g. `["app.example.com", "other.example.com:8443"]`. Empty means the iroh path only. An entry that could never match a request is refused at startup: anything but a DNS name with an optional port, a loopback name, or port 443 (browsers leave the default port out of `Host`). |
| `rp_name`       | `"Backend"`              | WebAuthn RP display name |
| `session_ttl`   | `4h`                     | How long a session lasts after login |
| `reauth_window` | `5m`                     | Step-up window |
| `max_blob_size` | `16MiB`                  | Largest accepted upload |

The setup-token lifetime (15 min) and the ceremony lifetime (5 min) are fixed.

## 11. Security notes

- **Network exposure:**
  - Only processes that can open the socket file can reach the server.
  - On the iroh path, the tunnel authenticates and encrypts the connection.
  - On the direct path, the reverse proxy handles TLS and rate limiting, in particular for `/api/v1/auth/*`.
- **Host allowlist:** see §6.1. It blocks DNS rebinding and phishing of passkey registrations through hosts the server doesn't control.
- **Secret storage:** session and setup tokens are 256-bit random values, and only their SHA-256 hashes are stored. A leaked database therefore contains no usable tokens.
- **Step-up:** a stolen session can't add a passkey or create a setup token after its first 5 minutes. This limits how long an attacker can keep access.
- **Logging:** never log tokens, cookies, WebAuthn payloads (including PRF data) or blob contents.
- **No user enumeration:** login doesn't take a username, and all setup-token errors look the same.
- **Blob responses:** blobs are served with a `sandbox` CSP and `attachment` disposition. Stored content can never run on the app origin.
- **Metadata:** the server sees ref names, sizes, counts, timestamps and access patterns. When clients encrypt their data, it never sees the content.
- **Backups:** everything is in one SQLite file. Use `VACUUM INTO` or the SQLite online backup API to get a consistent copy while the server runs.

## 12. Testing

- **Unit tests** for the pure `domain` functions:
  - range parsing and the precondition table
  - validation of names, IDs and hosts
  - the expected origin and RP ID for a given host
  - expiry computation
- **HTTP integration tests** call the router directly against an in-memory SQLite database, so they don't need a socket. They use a software authenticator.
  - **End-to-end flows:** registration, login, step-up, self-service and CLI setup tokens, and expiry.
  - **Hosts and origins:**
    - unknown hosts and IP addresses are refused
    - an `Origin` that doesn't match `Host`, including a different port, is refused and changes nothing
    - a passkey registered on one host is refused on another
    - a ceremony can't be finished from another host or port
  - **Cookies:** `Secure` is present on public hosts and absent on loopback hosts.
  - **PRF:** responses carrying unrequested `prf` client results and `hmac-secret` authenticator data are accepted, and the server neither stores nor returns them.
- **Schema versions:** the stored form of a version, migrating a new and a `1.0` database, and a newer minor accepted and a newer major refused, both left as they are.
- **Smoke test:** the server serves requests over the Unix socket and cleans the socket up on shutdown.
- **Concurrency test:** several writers compare-and-swap the same ref in parallel. Exactly one must win in each round.
- **Manual checks:** register and log in with PRF through:
  - the iroh path on a laptop (Chrome and Firefox)
  - the Android app
  - the HTTPS path

## 13. Future work

- List and revoke sessions; rename passkeys.
- Atomic transactions across several refs.
- Moving the content of offloadable blobs to S3 (§7.1), to support large blobs.
- Fetching several blobs in one request.
