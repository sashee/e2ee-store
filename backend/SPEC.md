# Backend Specification: Users & Storage

Status: **Draft v0.6** (2026-10-26)

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
| D6  | Storage            | SQLite for metadata and blob bytes; offloadable blobs get a copy in each place `blob_target` lists: the database, named storage backends such as S3, or several of them (§7.4). Maximum blob size 16 MiB. No quotas; writes into the database keep a reserve free (§7.5). |
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
  - For S3: `rusty-s3`, which only signs requests, and `reqwest` with rustls on `ring` to send them, trusting the system's CA certificates through `rustls-native-certs`. reqwest's default, aws-lc-rs, takes much longer to build on the host. Also `md-5` (`Content-MD5`) and `url`.
  - `rustix` for the free space on the database's file system (`statvfs`), without `unsafe`.
- One crate, with a module for each responsibility:
  - `domain`: pure types and rules. This covers validating IDs, names and hosts, parsing ranges, evaluating preconditions and computing expiry times. It does no I/O, and the current time is always passed in as an argument.
  - `store`: plain functions over a SQLite connection, one per query or transaction; the caller passes the time.
  - `db`: opening the database (WAL, foreign keys) and its migrations.
  - `accounts`: what the HTTP API and the admin commands share: creating users, setup tokens and their links.
  - `passkey`: WebAuthn ceremonies on top of `webauthn_rp`.
  - `secret`: session and setup tokens, of which only hashes are stored.
  - `http`: routes, extractors, the host/origin checks and the mapping from errors to responses.
  - `objects`: the S3 client: its credential file, object keys and requests.
  - `remotes`: the storage backends, by name and type, over the clients of their types (S3 so far).
  - `placement`: pure rules for a blob's copies (§7.4): where they belong, the steps that get them there, and the order reads try them in.
  - `offload`: making and dropping blobs' copies in the database and the backends, and the pass (§7.4).
  - `disk`: free space on the database's file system (§7.5).
  - `server`: the Unix socket, the background cleanup and the offloading pass.
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
nix/       the NixOS module (one instance per app) and its VM tests: the instance alone, and with S3 backends
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

Every table is `STRICT`.

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
CREATE INDEX passkeys_by_user ON passkeys(user_id);

CREATE TABLE sessions (
  token_hash  BLOB PRIMARY KEY,                 -- SHA-256(token)
  user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  passkey_id  BLOB REFERENCES passkeys(id) ON DELETE CASCADE,  -- NULL when created from a setup token
  created_at  INTEGER NOT NULL,                 -- = time of authentication
  expires_at  INTEGER NOT NULL
);
CREATE INDEX sessions_by_expiry ON sessions(expires_at);
CREATE INDEX sessions_by_passkey ON sessions(passkey_id);

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
  size        INTEGER NOT NULL,                 -- kept so a copy can be made and checked elsewhere
  created_at  INTEGER NOT NULL,
  offloadable INTEGER NOT NULL DEFAULT 0 CHECK (offloadable IN (0, 1)),  -- §7.1
  content     BLOB,                             -- the database's copy, NULL without one (§7.4); last: see below
  PRIMARY KEY (user_id, id)
);

CREATE TABLE blob_copies (                      -- a blob's copies in backends (§7.4)
  user_id   BLOB NOT NULL,
  blob_id   BLOB NOT NULL,
  backend   TEXT NOT NULL,                      -- a backend's name
  PRIMARY KEY (user_id, blob_id, backend),
  FOREIGN KEY (user_id, blob_id) REFERENCES blobs(user_id, id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX blob_copies_by_backend ON blob_copies(backend);

CREATE TABLE backends (                         -- the backends copies went to (§7.4)
  name      TEXT PRIMARY KEY,
  type      TEXT NOT NULL,                      -- 's3'
  identity  TEXT NOT NULL                       -- JSON: where it keeps blobs, nothing secret
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

- **Large values go last.** SQLite reaches a column stored after a large blob by stepping through the blob's overflow pages. With `content` last, reading a blob's metadata never touches its content: in a measurement with 8 MiB blobs, a lookup was 10 times and a scan of all rows 180 times faster than with a column after `content`. Whether `content` is NULL is in the row's header, so it costs nothing either.

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

The schema is migrated with plain SQL when the server or an admin command starts. Its version is `major.minor`, stored in `PRAGMA user_version` as `major * 1000 + minor`, with `N.0` as the bare `N`: the databases from before versions had a minor hold `1`, which is `1.0`.

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
  - rebuild a table to change only how it is stored, keeping every column and refusing exactly the rows it refused before; or to relax a constraint that only a newer configuration's data needs relaxed (1.3).
- **Everything else is a major:** dropping or renaming a table or column, changing a column's type, a constraint an older binary's writes could break, or a new meaning for existing data. The test is whether the previous binary would still behave correctly against the database.
- **One exception:** data that only a newer binary's configuration creates may make an older binary fail loudly, never quietly wrong. 1.2 and 1.3 used it: their blobs in backends made older binaries answer 500 for them.
- **Running a migration:** first the switch to WAL, which a new database needs: SQLite answers "busy" at once when two processes switch together (each could wait for the other), so it is tried again for up to the busy timeout, 5 s. Then one transaction, which takes the write lock before reading the version, so a server and an admin command starting together migrate once. Foreign keys are off around it, as a rebuild drops a table others point to, and `PRAGMA foreign_key_check` must find nothing before it commits. A rebuild first checks that the file system has twice the database's size free, and refuses to start otherwise.
- **How a rebuild goes:** create the new table under another name, copy the rows, drop the old table, rename the new one, recreate its indexes. Never rename the old table away: other tables' foreign keys would follow it.
- **A new major stops every older binary from starting.** Deliver a binary that no longer depends on what the major changes first, through the pipeline, and only then the major. The binary pins its major at compile time, so changing it is a deliberate edit.
- **2.0 skipped that step:** its one deployment had nothing in a backend, and gets new binaries only through the pipeline, so nothing had to run an older binary against it. Booting an older generation by hand now finds the server refusing to start.
- Binaries from before this scheme refuse anything above `1`, so the first one to migrate to `1.1` can't be reverted to them; the server just doesn't start until the newer binary is back.

| Version | Change |
|---------|--------|
| 1.0     | The tables above, without `blobs.offloadable`, `blobs.location` and its index, `backends` and `s3_location`; `content` before `created_at` |
| 1.1     | `blobs.offloadable` |
| 1.2     | `blobs.location`, its index, `s3_location` |
| 1.3     | `blobs` rebuilt: `location` holds `local` or any backend's name; `backends`, with 1.2's S3 as the backend `s3` |
| 2.0     | `blobs` rebuilt: without `location` and its index, `content` NULL where the blob was in a backend; `blob_copies`, with a row for each of those; `s3_location` dropped |

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
- **Per-passkey keys:** passkeys are tied to one host and PRF output is different for every passkey. Wrapping the master key once per passkey, and moving to a new host, is the SDK's job (`../sdk/SPEC.md` §3.1, §6.8).

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
- Uploading is idempotent. Uploading an ID that already exists does nothing, and `created_at` stays the same. Except for a lost blob (§7.4): one with no copy in the database whose copies in backends are all gone or another size, asked for one byte each, is stored again, where it belongs and with the flag it has.
- A blob can't be deleted while a ref points to it (409).
- Each upload is limited by `max_blob_size` (16 MiB by default). There are no per-user quotas.
- **Offloadable blobs.** A client can flag a blob as offloadable: the server may then keep its content outside the database, in one or more storage backends such as S3 (§7.4), where reads are slower and the content may be lost along with that storage.
  - The flag is set when the blob is uploaded, and only then: re-uploading an existing blob keeps its flag. It can be changed any time afterwards.
  - A ref can't point to an offloadable blob, and a blob a ref points to can't be flagged (409 `blob_offloadable`). What refs point to stays in the database, so a client can always find its way in.
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

### 7.4 Storage backends and copies

Offloadable blobs can live in storage backends. Each has a name, a type and a credential file (§10.1); S3 is the one type so far. `blob_target` (§10) lists the places offloadable blobs belong in: `local`, the database, and backends' names. A blob gets a copy in every one of them, so several make it redundant. Every other blob belongs in the database alone. Clients can't tell where a blob is, or how many copies it has.

- **Where a blob's copies are:** its row holds the content when the database has a copy, and `NULL` otherwise; `blob_copies` has a row for each backend with a copy. In S3, a copy's key is `<prefix><user ID>/<blob ID>`. A blob with no copy left keeps its row, and reads as lost.
- **What the rules are** (`placement`): an offloadable blob belongs in each of the targets, any other in the database alone. Copies that are missing are made first; copies anywhere else are only dropped once the blob has a copy in every place it belongs. That is checked again in the transaction that drops one, so a blob never has fewer copies on the way, even while a target is down.
- **A drop trusts no row:** rows can outlive their objects until a sweep notices, so before dropping a copy, the copies the blob keeps in backends are asked for, one byte each. One that isn't there, or is another size, is given up (below), and nothing is dropped. And a pass in which a target backend's list failed, its bucket gone perhaps, drops nothing at all.
- **Making copies:**
  - **Upload:** a new offloadable blob goes to all its targets at once, the backends in parallel, and the upload succeeds once one of them has it; the pass makes the copies that failed. If every backend fails and the database isn't a target, the database takes it anyway, room permitting (§7.5); without the room, 503 `storage_unavailable`. If the database is a target but hasn't the room, the blob is kept in the backends that took it.
  - **Flagging** (`PATCH`, `true`) makes the blob's copies before answering, then drops the database's if `local` isn't a target. If that fails, the request still succeeds, and the pass finishes it.
  - **Unflagging** a blob without a copy in the database brings one in first, in the same step as the flag changes, room permitting. Otherwise the flag doesn't change: 507 `storage_full`, 503 `storage_unavailable`, or 410 `blob_lost` if every copy is gone or damaged. Then its copies in backends are dropped. A blob that isn't offloadable is always in the database, so refs only point to blobs there.
  - **The pass**, at startup and every hour, brings every blob in line: it makes the copies that are missing, then drops the ones that aren't needed. Changing `blob_target` and restarting copies and drops whatever that takes.
  - **A copy is made from** the database's, or else from a backend's, fetched whole into memory and checked against the blob's ID. One read serves all of a blob's missing copies, and the ones in backends are made at once. The database never holds a copy it doesn't keep, so copying between backends needs no room on the host.
  - **Checks:** content going to S3 carries `Content-MD5`, so S3 refuses it if damaged. Requests to S3 time out after 10 s without a connection and 60 s without a byte of the response. Content coming from a backend must hash to the blob ID. A row only changes if the blob is still as it was when the step started.
- **Reads** take the database's copy if there is one, else the backends' in `blob_target`'s order, then any others; reads and copies being made share this. A backend's copy streams from there, with the same `Range` handling: the server asks for exactly the bytes the client asked for, and checks that it gets them. HEAD and unsatisfiable ranges don't ask. When a copy is gone or damaged, or its backend can't be reached, the read tries the next one. With none left: 503 `storage_unavailable` if a backend couldn't be reached; else 410 `blob_lost`, unless the blob's copies changed meanwhile, as a pass may move it while it is read: then it is looked up again, and if it was deleted meanwhile, that is 404.
- **A copy that is gone or damaged,** when a read, a copy being made, a drop or the sweep finds it so, is checked once more under its key's lock, as a sound one may have been made there since: a gone one by asking for one byte, which also tells its size; a damaged one, which came back another size than the blob's or with other bytes, by fetching it whole. If it still is, and the blob has another copy, its row is dropped, a damaged one's object with it, so the pass makes it again. A blob's last copy is never dropped like this: it reads as lost, for the client to see. Reads pass on a copy of the right size whose bytes are wrong: the client checks them.
- **A bucket that doesn't exist** answers like a backend that can't be reached, never like a lost object: a bucket deleted by mistake is an outage, until it is created again, empty, and the pass fills it, or until the backend is forgotten.
- **Deleting** a blob deletes its objects after its row, once it has answered: an unreachable backend would hold the answer up. What fails, the sweep deletes.
- **The sweep** runs first in each pass, for every configured backend, so the copies it finds gone are made again in the same pass. It lists the backend's objects, then deletes the objects no copy owns: left by a crash between two steps, by deleted users, or by a drop that couldn't delete its object. And it checks each copy the database has there but the list doesn't, as above. It doesn't touch keys that don't have the form above, so each server needs a prefix of its own in each bucket. If the list fails, it does neither.
- **Races:** whatever writes or deletes an object, or drops a copy's row, holds a lock on its key in its backend (an upload holds one per backend, always in the same order), and deletes an object only if the database, read under that lock, says no copy is there.
- **The backend guard:** the database records each backend copies went to (`backends`: name, type and identity, nothing secret). `serve` refuses to start if copies are in a backend that isn't configured, or one whose configuration names another type or location (compared as JSON). Otherwise those copies would read as lost, and nothing could drop them.
- **Removing a backend:** take it out of `blob_target` and restart. Each pass drops what is left there, for the blobs that have their copies elsewhere; once `backend storage` shows nothing there, remove its configuration. That works for a backend that is gone for good too: a drop deletes the copy's row, and its object only if it can. What it can't empty is a blob's only copy: once the backend is out of the configuration, `backend forget` (§9) drops those rows, and its record.
- **Migrating between providers:** add the new one to `blob_target`, restart, then remove the old one as above.
- **Free pages:** the database uses incremental auto-vacuum, and each pass returns its free pages to the file system, 1024 at a time. Before 1.2's binary, databases didn't do this; at its first start, `serve` switches the database over with one `VACUUM`. That is a file setting, not a schema change.
- **Backups:** copies in backends aren't in the database's backups. With `local` among the targets, every offloadable blob is; otherwise a blob is only as safe as its copies. That is what offloadable means: the content may be lost. Copies in more places make that less likely.

### 7.5 Free space

Writes into the database keep `min_free_space` (1 GiB by default) free on its file system. A write passes through the WAL before it reaches the database, so while it is in flight its bytes are there twice: a write of `n` bytes needs `2n` above the reserve, and a series of them their total plus the largest.

- **Uploads into the database** that wouldn't fit are refused: 507 `storage_full`. Uploading a blob that is already there writes nothing, so it always succeeds. An offloadable blob a backend took is kept there instead (§7.4).
- **Copies into the database:**
  - The pass adds up every blob that needs one. If they don't all fit, it makes none of them and logs how much is missing. Those blobs stay readable where they are, and the next pass tries again. All or nothing, as some of them would fill the disk and still leave the rest out.
  - Each copy checks again, as other writes use the space too.
  - Unflagging a blob without a copy here: 507 `storage_full` if it doesn't fit.
- **Copies in backends, and dropping copies,** need no room.
- `backend storage` (§9) shows the copies in each place, how many copies the blobs have, which are lost, and whether bringing every other blob into the database would fit.

## 8. HTTP API

- **Base path:** `/api/v1`. Requests and responses are JSON unless noted.
- **Errors:** `{"error": "<code>", "message": "<human readable>"}`, for every API error, including a query string that doesn't parse or a method a route doesn't have.
- **Response headers:** every response from an API route has `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. The host and Origin checks (§6.1) answer before the routes, so their 400 `unknown_host` and 403 `forbidden` don't carry them; browsers don't cache those statuses.
- **Request limits:** JSON request bodies are limited to 64 KiB.
- **Authentication:** session-authenticated endpoints return 401 `unauthenticated` when there is no valid session.

### 8.1 Overview

| Method    | Path                           | Auth              | Purpose |
|-----------|--------------------------------|-------------------|---------|
| POST      | `/auth/login/start`            | –                 | Begin passkey login |
| POST      | `/auth/login/finish`           | –                 | Complete login and set the session cookie |
| POST      | `/auth/setup-token`            | –                 | Exchange a setup token for a session |
| POST      | `/auth/logout`                 | –                 | End the current session, if there is one |
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
- **201** if the blob is new, **200** if it already existed (a lost one is stored again, §7.1). Body: `{"id", "size", "created_at", "offloadable"}`.
- **400** `hash_mismatch`; `bad_request` for any other `Blob-Offloadable` value.
- **413** `blob_too_large`.
- **415** `unsupported_media_type`.
- **503** `storage_unavailable`: an offloadable blob couldn't go to any of its target backends, and the database hasn't the room for it either (§7.4).
- **507** `storage_full`: the blob goes into the database, and it hasn't the room (§7.5).

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
- **410** `blob_lost`: the blob has no copy in the database, and every copy in a backend is gone (§7.4).
- **503** `storage_unavailable`: the blob has no copy in the database, and a backend with a copy can't be reached or answered wrongly.

`PATCH /blobs/{id}`, body `{"offloadable": true | false}`:
- **200** with `{"id", "size", "created_at", "offloadable"}`, also when the flag already had that value.
- **404** `not_found`.
- **409** `blob_offloadable`: a ref points to the blob.
- When unflagging a blob without a copy in the database (§7.4): **410** `blob_lost`, **503** `storage_unavailable`, **507** `storage_full` (§7.5).

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

- **What is served:** GET and HEAD for any path outside `/api/v1/` and `/healthz` are served from `static_dir`.
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
| 409  | `blob_offloadable`       | A ref would point to an offloadable blob, or to one without a copy in the database; or a blob a ref points to would be flagged offloadable |
| 409  | `last_passkey`           | The user tried to delete their only passkey |
| 409  | `passkey_exists`         | The credential is already registered |
| 410  | `blob_lost`              | Every copy of the offloadable blob is gone or damaged |
| 412  | `precondition_failed`    | The expect check failed |
| 413  | `blob_too_large`         | The blob is larger than `max_blob_size`, or a JSON body is over 64 KiB |
| 415  | `unsupported_media_type` | Wrong `Content-Type` |
| 416  | `range_not_satisfiable`  | The range is outside the blob |
| 500  | `internal`               | Anything else; the details are only logged |
| 503  | `storage_unavailable`    | A storage backend can't be reached, answered wrongly or has no bucket, an upload to every target backend failed and the database hasn't the room, the free space can't be read, or the blob's copies kept changing; the details are only logged |
| 507  | `storage_full`           | Writing into the database would take its file system below `min_free_space` (§7.5) |

## 9. Admin CLI

The CLI works directly on the database. This is safe while the server is running because the database uses WAL mode.

```
backend serve                            run the server on the Unix socket
backend storage                          copies and bytes per place, blobs by copies, lost blobs, free space, and whether all would fit here
backend forget <backend> [--accept-loss] forget a backend that is gone for good: its copies' rows and its record
backend user create <username>           create a user; print a setup token (+ links)
backend user list                        username, id, created_at, passkeys per host, storage used
backend user delete <username> [--yes]   delete the user and all their data
backend setup-token create <username>    print a new setup token (+ links), valid for 15 min
```

- Every command accepts `--config <path>`, which defaults to `./config.toml`.
- `forget` (§7.4) is for a backend gone for good, and refuses while it is configured: taken out of `blob_target`, the passes drop its copies that have others themselves, and one the server still reaches would lose its objects in the next sweep, the only copies among them. So: remove it from the configuration (the server then refuses to start, §7.4's guard), forget it, start the server. It refuses a name with neither a record nor copies, likely a typo; and when blobs would be left without any copy, it lists them and changes nothing. With `--accept-loss` it forgets their copies anyway, and they read as lost (410). It works on the database alone.
- Setup tokens are printed as the raw token, the iroh hint `append /#setup=<token> to your local address`, and one link per public host.

## 10. Configuration

Settings come from a TOML file. Any key can be overridden with an environment variable `BACKEND_<KEY>`.

| Key             | Default                  | Meaning |
|-----------------|--------------------------|---------|
| `socket`        | `./data/backend.sock`    | Path of the Unix domain socket the server listens on |
| `database`      | `./data/backend.sqlite3` | Path of the SQLite file |
| `static_dir`    | (required)               | Frontend files, served for every path outside `/api/v1/` and `/healthz` |
| `static_csp`    | see §8.6                 | `Content-Security-Policy` header sent with static files |
| `public_hosts`  | `[]`                     | Hosts reached over HTTPS, e.g. `["app.example.com", "other.example.com:8443"]`. Empty means the iroh path only. From the environment, a comma-separated list. An entry that could never match a request is refused at startup: anything but a DNS name with an optional port, a loopback name, or port 443 (browsers leave the default port out of `Host`). |
| `rp_name`       | `"Backend"`              | WebAuthn RP display name |
| `session_ttl`   | `4h`                     | How long a session lasts after login |
| `reauth_window` | `5m`                     | Step-up window |
| `max_blob_size` | `16MiB`                  | Largest accepted upload |
| `blob_target`   | `["local"]`              | Where offloadable blobs belong, a copy in each (§7.4): `local` and names of `backends`, not empty and each once. Reads try the database first, then the backends in this order. One name is a list of one. From the environment, a comma-separated list. |
| `backends`      | (none)                   | The storage backends, a table per name: `[backends.<name>]` with `type` (`"s3"`) and `file`, the credential file (§10.1). A name is 1–32 of `a-z`, `0-9` and `-`, not starting with `-`, and not `local`. Not overridable from the environment. |
| `min_free_space` | `1GiB`                  | What writes into the database keep free on its file system (§7.5) |

The setup-token lifetime (15 min) and the ceremony lifetime (5 min) are fixed.

```toml
blob_target = ["local", "backblaze"]

[backends.aws]
type = "s3"
file = "/run/credentials/music.service/aws"

[backends.backblaze]
type = "s3"
file = "/run/credentials/music.service/backblaze"
```

### 10.1 A backend's credential file

Everything about a backend is in its own file, apart from the configuration, as all of it is secret: the bucket and its endpoint as much as the keys. Only `serve` reads it. On NixOS it is a systemd credential, decrypted for the service only (the module's `storageBackends`).

For S3:

```toml
endpoint = "https://s3.eu-central-003.backblazeb2.com"
region = "eu-central-003"
bucket = "music-blobs"
prefix = "music/"              # required; one per server, as the sweep deletes the keys of its form under it
access_key_id = "…"
secret_access_key = "…"
# url_style = "virtual-host"   # default "path"
```

- Unknown keys, an empty prefix or one starting with `/` are refused at startup. A file that doesn't parse is reported by line and message only, never with the line itself, which could hold a secret.
- TLS uses the system's CA certificates (`SSL_CERT_FILE` when set).

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
- **Backups:** everything is in one SQLite file, except blobs with no copy in the database (§7.4). Use `VACUUM INTO` or the SQLite online backup API to get a consistent copy while the server runs.
- **Storage backends** see what the server sees of the blobs they have copies of: their bytes (end-to-end encrypted when clients encrypt), sizes and timing, and keys made of user IDs and blob IDs. Credential files are never logged, and neither are the locations they name.

## 12. Testing

- **Unit tests** for the pure `domain` functions:
  - range parsing and the precondition table
  - validation of names, IDs and hosts
  - the expected origin and RP ID for a given host
  - expiry computation
- **HTTP integration tests** call the router directly against a SQLite database in a temporary directory, so they don't need a socket. They use a software authenticator.
  - **End-to-end flows:** registration, login, step-up, self-service and CLI setup tokens, and expiry.
  - **Hosts and origins:**
    - unknown hosts and IP addresses are refused
    - an `Origin` that doesn't match `Host`, including a different port, is refused and changes nothing
    - a passkey registered on one host is refused on another
    - a ceremony can't be finished from another host or port
  - **Cookies:** `Secure` is present on public hosts and absent on loopback hosts.
  - **PRF:** responses carrying unrequested `prf` client results and `hmac-secret` authenticator data are accepted, and the server neither stores nor returns them.
- **Placement:** unit tests of the pure rules: where copies belong, that nothing is dropped before every target has a copy, and the order reads try copies in.
- **Offloading:** against a stand-in S3 per backend on 127.0.0.1 (`tests/common/s3.rs`): uploads and reads through S3, uploads to several targets with some of them failing, a lost blob uploaded again, reads falling back from copy to copy and looking the blob up again when its copies change, every range form, S3 answering errors, refusing connections, never answering (bounded by the timeouts) or without its bucket, lost and damaged copies, lengths that aren't the blob's, a suspect copy checked again before it goes, a blob's last copy kept, flag changes both ways, the targets at each pass, copies dropped only once every target has one, confirmed there, and never after a target's list failed, one read for all of a blob's copies, copies between backends with no room on the host, the sweep in both directions and what it leaves alone, a deleted user's objects, refs, races between steps and passes, the space returned, the backend guard, `forget`, and errors that don't name the location or carry a signed URL.
- **Free space** (with the free space a test sets): uploads keep the reserve, a blob is unflagged only if it fits, and blobs come home all together or not at all.
- **Migrations:** the stored form of versions, a new and a 1.0 database, a newer minor accepted and a newer major refused (both left as they are), the 2.0 rebuild of a 1.3 database with blobs here and in two backends, one of them not offloadable, and refs (rows, copies, foreign keys, the column order, and what is gone), and many connections starting at once on new, 1.0 and 1.2 databases.
- **VM test with S3** (`nix/tests/s3.nix`): the NixOS module with two backends, each a systemd-encrypted credential file and a bucket in Garage, behind nginx for TLS with a test CA.
  - Blobs go to S3, are read back through the API, whole and in a range, come back when the targets change, and move from one backend to the other and back.
  - With two backends and the database as targets, a blob has a copy in each; a bucket emptied behind the server's back is filled again by the next pass; and a backend whose bucket is gone, taken out of the targets, is emptied, and while it is configured, `forget` refuses it.
  - The credentials are encrypted at rest, and only the service user can read the decrypted copies.
  - Against a real S3: the sweep deletes an orphan and leaves keys that aren't its own; while S3 is down, uploads still work and reads fail with 503, and the next pass moves what waited; an object deleted in S3 reads as 410.
  - Nothing of the credential file reaches the journal, failures included.
- **Smoke test:** the server serves requests over the Unix socket and cleans the socket up on shutdown; the socket is its group's alone, and a stale one is replaced but a live one isn't.
- **Admin commands:** `user create`, `list` and `delete`, `setup-token create`, `storage` and `forget`, against the binary.
- **VM test of the NixOS module** (`nix/tests/lib.nix`): the socket's access control, the admin wrapper running as the service user, a restart, and the sandbox. Apps and hosts run it on their own instance and machine.
- **Concurrency test:** several writers compare-and-swap the same ref in parallel. Exactly one must win in each round.
- **Manual checks:** register and log in with PRF through:
  - the iroh path on a laptop (Chrome and Firefox)
  - the Android app
  - the HTTPS path

## 13. Future work

- List and revoke sessions; rename passkeys.
- Atomic transactions across several refs.
- A larger size limit for offloadable blobs, with uploads streamed to the backend instead of held in memory.
- More backend types (e.g. a REST store): a variant in `remotes`, with its own credential file.
- Checking copies' bytes now and then, not only that they exist: a damaged copy is only found when it is read or copied.
- Fetching several blobs in one request.
