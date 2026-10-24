# SDK Specification: End-to-End Encrypted Vaults

Status: **Draft v0.3** (2026-10-23)

## 1. Purpose & scope

The browser side of e2ee-store. An app builds on it to keep its data end-to-end encrypted in the backend (`../backend/SPEC.md`), unlocked with passkeys through the WebAuthn PRF extension. The backend sees only opaque blobs and refs; everything here runs in the browser.

The SDK provides:

- the backend client, WebAuthn ceremonies with PRF, and the cryptography
- a master key per user, wrapped once per passkey and once for a recovery key
- the **vault**: one encrypted tree of directories and files per user (§5), saved by compare-and-swap, with rollback detection. Files can be as large as the backend allows, and are read whole or in ranges, as streams (§6.12).
- setup links, adding devices, recovery, and cleanup of unneeded blobs
- a browser-test harness for apps (§9)

The app provides:

- its **namespace** (§2), which separates its keys from every other app's
- its **files**: their formats, and where in the tree they go (§5)
- the UI. The SDK has no DOM code.

Non-goals for v1:

- More than one vault per user, and sharing between users.
- Rotating the master key.

## 2. Labels

Every HKDF info, AAD, the PRF input and the keys format start with the app's namespace (`labels.js`). The namespace is 1–64 characters of `[a-z0-9._-]`, starting with a letter or digit.

| Label            | Value |
|------------------|-------|
| `prf`            | `<ns>/prf/v1` |
| `keysFormat`     | `<ns>/keys` |
| `kek.passkey`    | `<ns>/kek/passkey/v1` |
| `kek.recovery`   | `<ns>/kek/recovery/v1` |
| `slot.passkey`   | `<ns>/keys/v1/passkey` |
| `slot.recovery`  | `<ns>/keys/v1/recovery` |
| `stream`         | `<ns>/stream/v1` |
| `dir`            | `<ns>/dir/v1` |
| `file`           | `<ns>/file/v1` |
| `stateId`        | `<ns>/device-state-id/v1` |

- **Fixed forever:** every key and blob of an existing vault is bound to the labels. An app must never change its namespace; a test should pin it against data written by an earlier version.
- **Separation:** a passkey used by two apps on the same host gives each app a different PRF output, and a blob of one app doesn't decrypt in another.

## 3. Cryptography

### 3.1 Keys

All derivations use HKDF-SHA256, with an empty salt except for blob keys, which use the blob's own salt (§3.2).

| Key             | Origin | Purpose |
|-----------------|--------|---------|
| Master key (MK) | 32 random bytes, generated when the vault is created | Root key. It is never stored unwrapped. |
| Content key     | `HKDF(ikm = MK, info = labels.stream)` | The root of every blob's key (§3.2) |
| Passkey KEK     | `HKDF(ikm = PRF output, info = labels.kek.passkey)` | Wraps the MK for one passkey |
| Recovery KEK    | `HKDF(ikm = recovery key, info = labels.kek.recovery)` | Wraps the MK for the recovery key |

- **Algorithms:** all derived keys are non-extractable `CryptoKey`s: the content key an HKDF key, the others AES-256-GCM keys. A keyslot's encryption uses a fresh random 12-byte nonce; a blob's chunks are numbered, under a key of the blob's own (§3.2).
- **The MK in memory:** while the vault is unlocked, the MK is held as raw bytes, because it has to be wrapped again whenever a passkey is added. The app drops it by reloading the page.
- **PRF input:** a constant, `prf.eval.first = UTF-8(labels.prf)`. Login uses discoverable credentials, so the client doesn't know which credential will answer and can't choose a different input per credential. The PRF output is still unique to each passkey.
- **No key stretching:** the recovery key is 32 random bytes, so HKDF is enough.
- **Sizes are checked:** a PRF output must be exactly 32 bytes in an `ArrayBuffer` or a view of one, and wrapping refuses any secret or master key that isn't 32 bytes. A client that returned the PRF output in another form (e.g. a base64 string) would otherwise wrap the master key under a key anyone can compute.
- **State ID:** `HKDF(MK, info = labels.stateId)`, 16 bytes in hex. What a device remembers about the vault in `localStorage` is filed under it, so the server can't redirect it (e.g. by reporting another user ID).

### 3.2 Encrypted blobs

Every encrypted blob, the vault included, has this format (`stream.js`). It is age's STREAM construction with AES-256-GCM in place of ChaCha20-Poly1305, which WebCrypto doesn't have. Any part of a blob can be read and checked without the rest.

```
salt (16 bytes) ‖ length block (8 + 16-byte tag) ‖ chunk_0 ‖ … ‖ chunk_n-1
```

- **Blob key:** `HKDF(ikm = content key, salt = the blob's salt, info = UTF-8(label))`, an AES-256-GCM key. The salt is 16 random bytes, so no two blobs share a key. The label names the kind of blob (`labels.dir` for directories, `labels.file` for files), so a blob of one kind can't be passed off as another.
- **Length block:** the plaintext's length as 8 bytes, big-endian, encrypted with the nonce `0 (11 bytes) ‖ 0x02`.
- **Chunks:** the padded plaintext in chunks of 64 KiB (`CHUNK_SIZE`); the last one may be shorter. Chunk `i` is encrypted with the nonce `i (11 bytes, big-endian) ‖ 0x01` if it is the last, `‖ 0x00` otherwise, so chunks can't be reordered, dropped or cut off. There is no AAD.
- **Padding:** zeros, to a multiple of 4096 bytes (at least 4096). This is the writer's choice: readers take any padding, as the length block says where the plaintext ends. Padding can change (e.g. to Padmé) without a new format.
- **Shape:** every chunk but the last is full, the last holds at least one byte, and the length is at most the padded length. Anything else is an integrity error.
- **Nothing in plaintext** apart from the salt, not even the format version. A new format gets new labels, and readers try the formats they know; every format is authenticated, so a blob can't be read as the wrong one.
- **Directories and files** (§5) are both blobs of this format. A directory's plaintext is its UTF-8 JSON, a file's its bytes. The padding hides small changes in their size.
- **Integrity:**
  - A blob read whole is checked with `SHA-256(bytes) == blob ID` before use (a file's stream: before it closes, §6.12). A mismatch or a failed decryption is an integrity error and is shown to the user; the data is never used.
  - A range (§6.12) can't be checked against the ID. Each chunk is authenticated on its own, and the nonces fix its place and the end, so the data is the user's, of this kind, unaltered and in place. That it is this blob, and not another of the same kind, is certain because the key comes from the salt the blob's directory entry lists, not from the blob.

### 3.3 Keys blob

The keys blob is plaintext JSON. Its secret parts are the wrapped keys.

```json
{
  "format": "<ns>/keys",
  "version": 1,
  "recovery": { "nonce": "…", "wrapped_key": "…", "created_at": "…" },
  "passkeys": {
    "<credential id>": { "nonce": "…", "wrapped_key": "…", "created_at": "…" }
  }
}
```

- **Keyslots:** each slot holds the MK encrypted with AES-256-GCM using the KEK for its kind (§3.1).
  - The AAD is `UTF-8(labels.slot[kind])`, where `kind` is `recovery` or `passkey`.
  - Nonces and wrapped keys are base64url. A wrapped key is the 32-byte MK plus the 16-byte tag.
- **Slot names:** passkey slots are named by the credential ID as the browser returns it in `credential.id` (base64url).
- **Wrong keys:** a wrong key fails GCM authentication. For example, a mistyped recovery key produces "Wrong recovery key".
- **Versioning:**
  - `version` covers both this document and the tree's formats (§5).
  - Unknown fields are preserved when the document is rewritten.
  - A `version` greater than 1 makes the SDK refuse to write anything and ask to update the app. The tree opens read-only (`session.root.writable` is false), and an interrupted creation isn't completed (§6.1, step 5).
  - A session reads the keys' version when it unlocks. Afterwards it checks again only where it finds the keys changed anyway: when a save runs into a conflict, and before cleanup. A save without a conflict doesn't read the keys, so a newer version that changes the tree's format must still read trees written in the old one until every device has updated.

### 3.4 Recovery key

- **Generation:** 32 random bytes, shown as 64 lowercase hex characters.
- **Input:** whitespace is removed and the text is lowercased. Anything that isn't exactly 64 hex characters is rejected before any decryption is attempted.
- **Uses:**
  - recovery after losing all passkeys
  - setting up a new device that has no usable passkey (§6.8)

## 4. Storage layout

| Ref     | Points to | Changes |
|---------|-----------|---------|
| `keys`  | The keys blob (plaintext JSON, §3.3) | Created with the vault. Updated by compare-and-swap when passkeys or the recovery key change. |
| `vault` | The root directory (§5) | Created with the vault. Updated by compare-and-swap on every save. |

- **Other blobs:** the directories and files the root reaches, including earlier versions an app keeps in the tree; and replaced keys blobs and roots. Maintenance deletes whatever nothing reaches (§6.11).
- **Existence:** the `keys` ref is the sign that a vault exists. It is written first when the vault is created (§6.3).

## 5. The tree

An app's data is a tree of directories and files. The `vault` ref points to its root.

- **Files** are blobs of the stream format (§3.2) with `labels.file`. Their content is the app's.
- **Directories** are blobs with `labels.dir`, holding UTF-8 JSON:

```json
{
  "version": 1,
  "entries": [
    { "name": "01 Intro.flac", "kind": "file", "id": "9f2c…", "salt": "4be1…", "size": 18734512, "sha256": "e3b0…", "modified": "2026-10-23T14:02:11.000Z", "app": { "duration": 251.4 } },
    { "name": "Bonus", "kind": "dir", "id": "…", "salt": "…" }
  ]
}
```

- **The root** is a directory with a `revision` as well: `{ "version": 1, "revision": 42, "entries": […] }`. The revision grows by one with every save, for rollback detection (§6.5). A new vault starts at 1.
- **Entries:**

  | Field | Meaning |
  |-------|---------|
  | `name` | The entry's name. A directory holds its children's names; it has no name of its own. |
  | `kind` | `file` or `dir`. It also fixes the label the blob is opened with. |
  | `id`, `salt` | The blob, and its salt (§3.2). Reads of a file are pinned to that salt. |
  | `size` | Files: the plaintext's length. |
  | `sha256` | Files: the plaintext's SHA-256 in hex, e.g. to recognise a lost file. |
  | `modified` | Files: the file's own time, as an ISO 8601 string. |
  | `app` | Files, optional: the app's own data, which the SDK keeps as it is. |

- **Names:** not empty, not `.` or `..`, no `/`, no C0 control characters and no DEL, at most 255 UTF-8 bytes, and stored in NFC (`validName` checks one). A directory's entries are sorted by name (UTF-16 code units) and unique.
- **Paths** are arrays of names; `[]` is the root.
- **Checks:** a directory that isn't shaped like this is an integrity error. One of a higher `version` than the SDK knows can be read but not changed. A root of a higher version makes the whole tree read-only, as newer keys do (§3.3).
- **Unknown fields:** a directory's unknown top-level fields are kept when it is rewritten, and entries a save doesn't change are kept as they are.
- **History** is up to the app, e.g. a copy of an entry under another name (`vault@41`) before it is replaced. Copies share their blobs, so a kept version costs only what changed.
- **Reachability:** a blob stays only while the root reaches it (§6.11). A blob referenced only from inside a file's content isn't kept.
- **Offloadable files** (§6.13) may be kept outside the server's database. Entries don't record it.

## 6. Flows

`flows.js` implements these on top of the API, WebAuthn and the pure modules; the app drives them from its UI.

### 6.1 Unlock with a passkey

1. `POST /auth/login/start`. The client adds `extensions.prf.eval.first = UTF-8(labels.prf)` to the options and calls `navigator.credentials.get()`. This is the only prompt.
2. It reads the PRF output from `getClientExtensionResults().prf.results.first`. If there is none, it stops: "This passkey can't unlock the vault: it doesn't support the PRF extension."
3. It deletes `clientExtensionResults.prf` from the credential JSON and calls `POST /auth/login/finish`, which creates the session.
4. It loads the keys blob (`GET /refs/keys`, then the blob) and unwraps the MK from `passkeys[credential.id]`.
   - If there is no `keys` ref, the result is `no-vault`, or `keys-missing` if a `vault` ref exists (§6.2, step 3).
   - If there is no such slot, the result is `no-slot`. The app offers to unlock with the recovery key, which then sets the passkey up (§6.9).
5. It loads the root directory (the `vault` blob), verifies, decrypts and checks it (§5). The app checks for rollback (§6.5).
   - If `keys` exists but `vault` doesn't, a vault creation was interrupted. The client creates an empty root with `If-None-Match: *`, unless the keys are from a newer version: then it asks to update the app.

When the app starts, it calls `GET /me`.
- **401:** it shows the unlock screen.
- **Valid session but no MK in memory** (after a reload or an interrupted setup): it shows the unlock screen with a second option, "Use recovery key". A passkey unlock still logs in again, which replaces the session.

### 6.2 Setup links

A setup link has the form `<origin>/#setup=<token>`, where the token is the backend's setup token.

When the app starts with a fragment:

1. It reads the token and immediately removes the fragment with `history.replaceState`, so it doesn't stay in history or on screen.
2. `POST /auth/setup-token`. A 401 means "This setup link has expired or was already used."
3. `GET /refs/keys`:
   - **No `keys` ref and no `vault` ref:** create the vault (§6.3).
   - **No `keys` ref but a `vault` ref:** stop and tell the user to restore the server's data. A new vault would come with new keys, and the existing vault could never be opened again. `unlockWithPasskey` and `createVault` report this as `keys-missing`.
   - **`keys` exists:** ask for the recovery key and unwrap the MK from `recovery`.
4. With the MK in memory, it registers a passkey on this host and sets it up (§6.6, steps 1–6). The setup-token session is fresh, so step 1 needs no step-up. The user can skip this step, but then the next unlock on this host needs the recovery key again.

### 6.3 Creating the vault

1. Register a passkey on this host and get its PRF output (§6.6, steps 1–5).
2. Generate the MK and the recovery key.
3. Show the recovery key. The user has to confirm they saved it before continuing. Nothing has been stored yet, so closing the tab here leaves no trace.
4. Check that there is a `keys` ref or no `vault` ref. A `vault` ref without a `keys` ref stops the creation before anything is written (`keys-missing`, §6.2).
5. Build the keys document (with the recovery slot and this passkey's slot) and an empty root at revision 1. Upload both blobs.
6. `PUT keys` with `If-None-Match: *`. This is the commit.
   - A 412 means another device created a vault in the meantime. The client discards its own and switches to unlocking. Maintenance removes the orphaned blobs.
7. `PUT vault` with `If-None-Match: *`. If the client is interrupted before this step, the next unlock creates the empty vault (§6.1, step 5).

### 6.4 Saving changes

**The keys document** changes through operations, pure functions of the form `document → document`: `setPasskey(credentialId, slot)`, `removePasskey(credentialId)`, `setRecovery(slot)` and `prune(existingCredentialIds)`. A save applies the operation, uploads the result, and writes `PUT keys` with `If-Match: "<loaded blob id>"`. On a 412, it reads the current keys, checks their version (§3.3), and applies the operation to them again; at most 5 attempts in all.

**The tree** changes through `save(session, steps, { signal, onProgress }) → { session }`. Each step is a function `(tx) => tx`, or a promise of one: it takes a transaction and returns the next.

| On `tx` | |
|---------|---|
| `revision` | The revision the save is based on. The root it writes has the next one. |
| `put(path, content) → tx` | Places `content` at `path`, replacing what is there and making missing directories. `content` is what `upload` returned, or an entry read from `tx` or from `list`: an existing file or directory is re-pointed, not uploaded again. An entry may come back with a new `modified` and `app`, but otherwise as it was read. |
| `remove(path) → tx` | Removes a file, or a directory with everything in it. Nothing at `path` is no change. |
| `mkdir(path) → tx` | Makes an empty directory, and missing parents. An existing directory is no change. |
| `upload(bytes, { modified, app, offloadable }) → content` | New file content: a `Uint8Array`, or a `Blob` that is read only when it's uploaded. `modified` defaults to the save's time; `offloadable` (§6.13) to false. |
| `entry(path) → Promise<entry \| null>` | What is at `path` now. |
| `list(path) → Promise<[entry]>` | A directory's entries now, sorted by name. |
| `read(path) → Promise<Uint8Array \| null>` | A file's content now, whole and checked. |

- **`tx` never changes:** writes return a new one, and reads see the writes before them. Writes are only recorded; reads load the directories they need.
- **Moves and copies:** a move is `put(to, await tx.entry(from))` then `remove(from)`, and a copy is the `put` alone. Content made in this save (an upload, or a directory made or changed) can be put at more than one path, and is written once. The same bytes uploaded offloadable and not are two uploads.

A save:

1. Runs the steps on the loaded root.
2. Uploads the new files, three at a time, and writes each changed directory once, as soon as what it lists is written (bottom-up), then a new root with the next revision.
3. `PUT vault` with `If-Match: "<loaded root's blob id>"`.
4. On a 412, it reads the current root, checks it (§6.5), and runs the steps on it again from the start. Uploads of the same source (the same `Uint8Array` or `Blob`, with the same `offloadable`) are reused, so only directories are written again. The client tries at most 5 times, then reports an error.

- **Steps must be pure functions of `tx`.** They may run more than once, and only what they write to `tx` takes effect.
- **Errors** are `TreeError`s, with a `code` and the `path` concerned: `invalid_name`, `not_found`, `not_a_directory`, `is_a_directory`, `no_content`, `invalid_content`, `read_only` and `too_large`. Invalid arguments (a path that isn't an array, `[]` where only `list` takes it, a bad `upload`, steps that aren't an array of functions) are `TypeError`s. Any error, or a step that doesn't return a tx, fails the save, and the ref doesn't move.
- **Progress and abort:** `onProgress({ files, bytes, totalFiles, totalBytes })` follows the uploads. `signal` aborts them, and the save, until the ref moves; after that, the save is done. Blobs uploaded by a save that didn't finish are orphans that cleanup removes.
- **Size limit:** a file over the backend's `max_blob_size` fails the save with `too_large`, naming its path. The SDK doesn't know the limit in advance.
- **Large imports:** upload in several saves (e.g. one per album), so a failure costs one part, and each save finishes well within cleanup's 24-hour grace period.
- **When remote changes arrive:** there is no polling. A client sees other devices' changes when it unlocks, and through the 412 when it saves.

### 6.5 Rollback detection

- The app stores the highest root revision it has seen in `localStorage`, under the state ID (§3.1). `rollbackCheck(highestSeen, session.root.revision)` compares the two.
- If a loaded root has a lower revision, the app shows a warning and blocks saving until the user acknowledges it, which resets the stored value.
- A save that runs into a conflict whose current root isn't newer than the one being saved over is a rollback too: the save stops with `RollbackError`, and nothing is written on top of the older root.

### 6.6 Adding a passkey on this host

1. `POST /me/passkeys/register/start`. On 403 `reauth_required`, log in again with a passkey (`reauthenticate(session)`) and retry. The passkey must belong to the session's user: another account's passkey on this host would switch the session to that account while this one's MK is in memory, so the SDK logs that login out again and the app has to unlock.
2. Add `extensions.prf.eval.first = UTF-8(labels.prf)` to the options, then call `navigator.credentials.create()`.
3. The passkey can be used only if `prf.enabled === true` or PRF results came back. Otherwise the client doesn't call `finish` and tells the user that this authenticator can't unlock the vault.
4. Remove `clientExtensionResults.prf` and call `POST /me/passkeys/register/finish`.
5. If `create()` already returned a PRF output, use it. Otherwise log in with the new passkey to get one: the login options are given `allowCredentials: [new id]` and the PRF input. This is a second prompt, and the new login becomes the session.
6. Wrap the MK with the passkey KEK and save the keys document with `setPasskey`.

**Setting up an existing passkey:** a passkey on this host can exist without a slot, for example when step 6 was interrupted. Steps 5–6 set it up.

**Passkeys on other hosts:** these can only be set up on their own host. A passkey's RP ID is its host, so it can't be used from here.

### 6.7 Removing a passkey

1. The app asks for confirmation. If this is the last passkey with a slot, it warns that the recovery key will be needed afterwards. The backend refuses to delete a user's very last passkey (409 `last_passkey`).
2. `DELETE /me/passkeys/{id}`. On `reauth_required`, log in again with a passkey (`reauthenticate(session)`) and retry.
3. If the session still exists, save the keys document with `removePasskey`. Deleting the passkey that created the current session ends that session. In that case the app locks, and maintenance removes the slot later.

### 6.8 Adding a device

The new device may use another host, e.g. the HTTPS path when this device uses iroh.

1. `POST /me/setup-tokens`, handling step-up as in §6.6. A session that wasn't created with a passkey (e.g. right after a setup link) gets `passkey_session_required` and is asked to log in with a passkey, the same way.
2. Show the setup links:
   - every link from the response
   - the fragment on its own, `/#setup=<token>`, to add to a local iroh address
3. On the new device, the user opens the link and enters the recovery key (§6.2). Then they register a passkey there.

A setup link alone doesn't open the vault; the recovery key is also needed.

### 6.9 Recovery

**When all passkeys are lost:**

1. The user gets a setup link from the admin (`backend setup-token create`) or from another device where they are still logged in.
2. They open it, which starts §6.2.
3. The app asks for the recovery key and unwraps the MK from `recovery`.
4. The app registers a new passkey and sets it up.

**From the unlock screen:** a user who has a session but no MK uses "Use recovery key" for the same steps 3–4. Afterwards, the app offers to set up the current passkey or to add a new one.

### 6.10 Replacing the recovery key

1. Generate a new key and show it; the user confirms as in §6.3.
2. Save the keys document with `setRecovery`.

The old key stops working, but this does not re-encrypt anything. Rotating the master key is future work.

`testRecoveryKey` checks a key the user wrote down against the current recovery slot, without changing anything.

### 6.11 Maintenance

The server never cleans anything up, so the client does. The app runs `maintain` in two ways:

- **Automatically** in the background after an unlock, at most once every 24 hours per device (`isDue`). `localStorage` records the last report.
- **Manually**, e.g. from a "Clean up now" button. This runs immediately and reports its progress.

**Steps:**

0. **Check before changing anything.** Stop, deleting nothing, if:
   - either ref is missing
   - the server's current root or keys document is from a newer version
   - the server's root is older than this session's (the app also doesn't run it while a rollback warning is shown)
1. **Prune the keys document:** remove passkey slots whose credential ID is not in `GET /me/passkeys`. Nothing is saved if nothing changed. Only the slots found stale are removed, also when the save is re-applied after a conflict, so a slot another device just added is never pruned.
2. **Build the keep set:** the current `keys` blob, the root, and every directory and file the root reaches. Each directory is read once; ones this session has already read or written come from memory. A directory that can't be read stops the run here.
3. **Delete old blobs:**
   - List all blobs. Stop, deleting nothing, if any listed blob ID isn't 64 hex characters (IDs go into URLs), or the list has no `Date` header (below).
   - Delete every blob that is not in the keep set and whose `created_at` is more than 24 hours before the server's time (taken from the `Date` header of the list response). Without that header, nothing is deleted: this device's clock is no substitute, as it can be days off.
   - The grace period protects blobs that another device has uploaded but not yet referenced. It also applies to manual runs.
   - Blobs uploaded by saves that lost a compare-and-swap race (§6.4) were never committed, so they are deleted too.

**Report:** each run is best-effort and produces a report (`makeReport`); `summary(report)` is a one-line description of it.

| Field          | Meaning |
|----------------|---------|
| `started_at`, `finished_at`, `trigger` | When the run happened, and whether it was `automatic` or `manual` |
| `slots_removed` | Passkey slots pruned from the keys document |
| `blobs_total`, `bytes_total` | All blobs found |
| `kept`         | The keep set's blobs, with their bytes |
| `deleted`      | Blobs deleted, with their bytes |
| `too_recent`   | Unreferenced blobs that were left alone because of the grace period |
| `failed`       | Blobs whose deletion failed, with the error |
| `error`        | Set if the run stopped early (e.g. lost session); the counts show how far it got |

An automatic run that failed is due again at the next unlock.

### 6.12 Reading the tree

- **`list(session, path) → [entry]`:** a directory's entries, sorted by name; `[]` is the root. A missing path is `not_found`, and a file is `not_a_directory`.
- **`read(session, ref, { from, to, signal }) → { size, stream }`:** a file's content. `size` is the plaintext's length, and `stream` a `ReadableStream` of the plaintext bytes in `[from, to)`, as they are decrypted. `ref` is an entry from `list`, or an `{ id, salt }` the app kept; its salt pins the read to that blob (§3.2).
  - **All of it** (neither `from` nor `to`): one request. The blob is checked against its ID before the stream closes (§3.2), so whatever must be verified before use is read to the end first.
  - **A range:** `to` past the end is cut to the end, `from` at the end gives nothing, and `from` after it is a `RangeError`. Only the chunks the range touches are fetched, in one `Range` request, plus the 40-byte header if the range starts after the first chunk. A range aligned to `CHUNK_SIZE` fetches nothing it doesn't use. A server that ignores `Range` still works, at the cost of the whole download.
  - **Aborting:** `signal`, or cancelling the stream, aborts the requests, and nothing more comes out of the stream. An abort fails with the signal's reason, unchanged, so the app can tell it from a failure.
  - **Errors:** a blob that doesn't open, a chunk that fails and a range the server answers wrongly are integrity errors, from `read` or from the stream where they are read. A file whose content the server lost is a `BlobLostError` (§6.13).
- **`CHUNK_SIZE`** (64 KiB, from `blobs.js`) is the plaintext in a chunk: the unit worth fetching.
- **Caching:** directories never change, so a session keeps the ones it has read or written in memory, by ID, up to 4096 (`CACHED_DIRS`), dropping the one kept longest. Browsing doesn't fetch a directory twice, and a save that runs again after a conflict doesn't either, while they stay in the cache.

### 6.13 Offloadable files

An app can let the server keep a file's content outside its database (backend/SPEC.md §7.1), e.g. in cheaper storage for large media. That content may read more slowly, and can be lost with that storage: it suits files the app can do without or get back, like a track that is also in the user's music library.

- **Uploading:** `tx.upload(bytes, { offloadable: true })` (§6.4). Only files can be offloadable. Directories and the root never are, so the tree itself always stays readable.
- **Changing:** `setOffloadable(session, ids, offloadable)` sets the flag of the files with these blob IDs, one request each; the tree doesn't change. Flagging a directory listed in one the session has read or written is a `TypeError`, before anything is sent. The server refuses to flag the root (`blob_offloadable`).
- **Entries don't record the flag:** the server keeps it per blob. An app that needs to know keeps it itself, e.g. in the entry's `app`. A copy of a file elsewhere in the tree is the same blob, so it has the same flag.
- **Lost content:** reading a file whose content is lost (`410 blob_lost`) fails with `BlobLostError` from `api.js`: an `ApiError` with code `blob_lost` and the blob's `id`. Its entry stays, and cleanup keeps the blob (§6.11); what to do, e.g. upload the file again, is up to the app.
- **Where the content is** is the server's business (backend/SPEC.md §7.4): its configuration decides which storage backend, if any, offloadable files go to. While the backend can't be reached, reading a file there, or making it not offloadable, fails with `storage_unavailable`. Flagging still works, and so does uploading, as long as the server's database has the room to take the file instead (otherwise `storage_unavailable` too). Making a lost file not offloadable fails with an `ApiError` with code `blob_lost`. Making a file not offloadable brings it into the server's database, and fails with `storage_full` if it hasn't the room.

## 7. Modules

Plain ES modules with no dependencies and no build step. An app copies `src/` into its static files (the Nix package has it at `share/e2ee-store/sdk`) and imports the modules by relative path; the backend's CSP (`script-src 'self'`) rules out import maps.

| Module            | Contents |
|-------------------|----------|
| `labels.js`       | `labels(namespace)` (§2) |
| `flows.js`        | `makeFlows({ labels })` (§6): unlock, create, `save`, `list`, `read`, `setOffloadable`, passkey slots, recovery key, maintenance |
| `tree.js`         | The tree (§5, §6.4): its formats and names, transactions, commits, `TreeError`, `validName`, and what a root reaches |
| `blobs.js`        | Uploading and reading encrypted blobs over the API, and `CHUNK_SIZE` (§6.12) |
| `stream.js`       | The blob format (§3.2): sealing, opening, and its layout |
| `api.js`          | The backend client: errors with fixed messages and `BlobLostError`, hash-checked blobs, ranges, offloadable blobs, compare-and-swap refs, the 401 handler |
| `passkeys.js`     | WebAuthn ceremonies with PRF; `UserFacingError` |
| `crypto.js`       | HKDF, AES-GCM, SHA-256, base64url, hex |
| `envelope.js`     | The content key (§3.1) |
| `keys.js`         | The keys document, wrap/unwrap, operations (§3.3) |
| `save.js`         | `saveWithRetry` (I/O passed in), `RollbackError`, `rollbackCheck` (§6.4, §6.5) |
| `maintenance.js`  | The cleanup plan, report and schedule (§6.11) |
| `recovery-key.js` | Generating, formatting and parsing recovery keys (§3.4) |
| `setup-link.js`   | Parsing and building setup fragments (§6.2) |

Messages shown to the user come from the SDK, never from the server, so a misbehaving server can't put its own text in front of the user (e.g. asking for the recovery key). A code without a message of its own (e.g. `bad_request`, `internal`) gets "The server refused the request (<code>, HTTP <status>)", with the code limited to `[a-z_]`, at most 40 characters.

## 8. Security notes

- **What is protected:**
  - The vault's content, its names and its structure are hidden from the server and from leaked database copies. So are the versions an app keeps.
  - Blob tampering is detected by content addressing plus GCM: in whole reads by both, in range reads by GCM, chunk by chunk (§3.2).
  - A rolled-back vault is detected by the revision check.
- **What is not protected:**
  - A server that serves malicious JavaScript. This is inherent to web apps, and the app is served by the same backend.
  - XSS in the app.
  - Malware on the device.
  - An attacker who already has the MK. Without key rotation, removing a passkey doesn't lock them out.
- **What the server sees:**
  - when and how often the root and the keys blob change
  - every blob's size, padded to 4 KiB steps, and the number of blobs
  - when blobs are uploaded and read. That can group them: an album's tracks are uploaded together and played one after another, and a group of known sizes can identify what it is.
  - from the plaintext keys blob: which credential IDs have slots, and when the recovery key changes
- **Range reads:** `read` always pins a file to the salt its entry lists, so a server can't serve another of the user's files in its place, even for a range (§3.2).
- **Tampering with the keys blob:** the server can delete or replay slots, which can only cause a failed unlock. It can't create a working slot, because that needs a KEK.
- **Recovery key:** it is used whenever a new device is set up, so it gets pasted more often than a pure recovery secret would. Only paste it into the app.
  - The key plus a session gives full access. The key plus a stolen database also gives full access.
  - Replacing it (§6.10) doesn't help against someone who already used it, because there is no key rotation.
- **Memory:** while the vault is unlocked, the MK and all plaintext are in JavaScript memory. Locking should reload the page to drop them.

## 9. Testing

- **Unit tests** (`node --test`; Node has WebCrypto), for the pure modules and, against the stand-ins of `test/fakes.js`, for the API client and the blobs:
  - **API client:** fixed messages, the 401 handler, hash checks of downloaded blobs, blob ID checks, refs with compare-and-swap, deletes that count a missing blob as deleted, and the server's clock.
  - **Crypto:** wrap/unwrap round trips; a tampered nonce, ciphertext or AAD fails; keys of another kind or another namespace fail.
  - **Labels:** derived from the namespace; invalid namespaces are refused.
  - **Tree:** transactions (writes return new ones, reads see earlier writes), commits (only what changed, bottom-up, each directory and upload once, offloadable uploads apart), what `put` accepts back, names, read-only directories, errors, malformed directories, and what a root reaches.
  - **Blobs:** sizes, padding and chunks; round trips across chunk boundaries; damaged, reordered, shortened and lengthened blobs; another writer's padding; ranges and what they fetch, salts, a server that ignores ranges, aborting.
  - **Keys documents:** validation; every operation; `version > 1` is read-only; another app's keys document is refused.
  - **Saving:** retries on conflict, gives up after 5, sync and async operations, rollback.
  - **Recovery key, setup links, maintenance:** parsing, the plan with its grace period, the report, the schedule.
- **Flow tests** (`node --test`) run the flows and the backend client against stand-ins for the browser (`test/fakes.js`): an in-memory backend behind `fetch` and an authenticator with PRF behind `navigator.credentials`. They cover creating and unlocking, setup and recovery, saving (steps run again after a conflict, with uploads reused), progress and abort, rollback, newer versions, step-up, files read whole and in ranges, offloadable and lost files, cleanup by reachability, and a server that misbehaves.
- **Format vectors:** `test/vectors.json` holds a keys blob of version 1, and a root directory listing a file blob of two chunks (the file's recipe and ID). `test/make-vectors.mjs` made them from this spec with `node:crypto` alone (`test/reference.mjs`). The SDK must keep opening them (§2).
- **Browser tests:** real WebAuthn, `fetch` and ranges against the real backend. This repository runs the flows, a file in the tree and an offloadable one with a stand-in app (`test/browser`); each app runs its own UI with `testing/e2ee_store_harness.py`:
  - `harness(run, static_dir, extra_env=None)` starts the backend (`BACKEND_BIN`) serving the app's static files behind `socat`, the way the iroh shim reaches it, and Chromium, then calls `run(browser, backend, port)`.
  - `new_device(browser, base)` is a browser profile with a virtual authenticator that supports PRF (CDP `WebAuthn.addVirtualAuthenticator`, `hasPrf: true`). With `prf_at_create=False` it behaves like authenticators that give the PRF output only at sign-in.
  - `Backend` runs admin commands (`setup_token(...)`) and reads the stored blobs.
- **An app should test:** that data written by its earlier versions still opens with its labels (§2).
