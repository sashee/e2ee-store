# SDK Specification: End-to-End Encrypted Vaults

Status: **Draft v0.1** (2026-10-10)

## 1. Purpose & scope

The browser side of e2ee-store. An app builds on it to keep its data end-to-end encrypted in the backend (`../backend/SPEC.md`), unlocked with passkeys through the WebAuthn PRF extension. The backend sees only opaque blobs and refs; everything here runs in the browser.

The SDK provides:

- the backend client, WebAuthn ceremonies with PRF, and the cryptography
- a master key per user, wrapped once per passkey and once for a recovery key
- the **vault**: one encrypted root document per user, saved by compare-and-swap, with rollback detection
- setup links, adding devices, recovery, and cleanup of unneeded blobs
- a browser-test harness for apps (§9)

The app provides:

- its **namespace** (§2), which separates its keys from every other app's
- its **vault document** (§5): the format, the operations on it, and which other blobs it needs
- the UI. The SDK has no DOM code.

Non-goals for v1:

- More than one vault per user, and sharing between users.
- Rotating the master key.
- Encrypted blobs besides the vault itself. An app that stores more (e.g. a tree of files) encrypts them with the content key and lists them through `keep` (§5).

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
| `content`        | `<ns>/content/v1` |
| `vault`          | `<ns>/vault/v1` |
| `stateId`        | `<ns>/device-state-id/v1` |

- **Fixed forever:** every key and blob of an existing vault is bound to the labels. An app must never change its namespace; a test should pin it against data written by an earlier version.
- **Separation:** a passkey used by two apps on the same host gives each app a different PRF output, and a blob of one app doesn't decrypt in another.

## 3. Cryptography

### 3.1 Keys

All derivations use HKDF-SHA256 with an empty salt.

| Key             | Origin | Purpose |
|-----------------|--------|---------|
| Master key (MK) | 32 random bytes, generated when the vault is created | Root key. It is never stored unwrapped. |
| Content key     | `HKDF(ikm = MK, info = labels.content)` | Encrypts the vault blob |
| Passkey KEK     | `HKDF(ikm = PRF output, info = labels.kek.passkey)` | Wraps the MK for one passkey |
| Recovery KEK    | `HKDF(ikm = recovery key, info = labels.kek.recovery)` | Wraps the MK for the recovery key |

- **Algorithms:** all derived keys are AES-256-GCM `CryptoKey`s and are non-extractable. Every encryption uses a fresh random 12-byte nonce.
- **The MK in memory:** while the vault is unlocked, the MK is held as raw bytes, because it has to be wrapped again whenever a passkey is added. The app drops it by reloading the page.
- **PRF input:** a constant, `prf.eval.first = UTF-8(labels.prf)`. Login uses discoverable credentials, so the client doesn't know which credential will answer and can't choose a different input per credential. The PRF output is still unique to each passkey.
- **No key stretching:** the recovery key is 32 random bytes, so HKDF is enough.
- **Sizes are checked:** a PRF output must be exactly 32 bytes in an `ArrayBuffer` or a view of one, and wrapping refuses any secret or master key that isn't 32 bytes. A client that returned the PRF output in another form (e.g. a base64 string) would otherwise wrap the master key under a key anyone can compute.
- **State ID:** `HKDF(MK, info = labels.stateId)`, 16 bytes in hex. What a device remembers about the vault in `localStorage` is filed under it, so the server can't redirect it (e.g. by reporting another user ID).

### 3.2 Vault blob

```
nonce (12 bytes) ‖ AES-256-GCM ciphertext ‖ tag (16 bytes)
```

- **Encryption:** the content key, with AAD `UTF-8(labels.vault)`. Other encrypted documents of an app use the same format (`sealDocument`) with an AAD of their own.
- **Plaintext:** the UTF-8 JSON vault document (§5), padded with spaces (`0x20`) to a multiple of 4096 bytes. JSON ignores trailing whitespace, and the padding hides small changes in size.
- **Nothing in plaintext:** apart from the nonce, nothing is readable without the MK. That includes the format version and the links to earlier versions. The format of this blob is identified by the keys document's `version` (§3.3).
- **Integrity:** every downloaded blob is checked with `SHA-256(bytes) == blob ID` before use. A mismatch or a failed decryption is an integrity error and is shown to the user; the data is never used.

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
- **Wrong keys:** a wrong key fails GCM authentication. For example, a mistyped recovery key produces "wrong recovery key".
- **Versioning:**
  - `version` covers both this document and the vault blob format.
  - Unknown fields are preserved when the document is rewritten.
  - A `version` greater than 1 makes the SDK refuse to write anything and ask to update the app. The vault opens read-only (`session.vault.writable` is false), and an interrupted creation isn't completed (§6.1, step 5).
  - A session reads the keys' version when it unlocks. Afterwards it checks again only where it finds the keys changed anyway: when a save runs into a conflict, and before cleanup. A save without a conflict doesn't read the keys, so a newer version that changes the vault's format must still read vaults written in the old one until every device has updated.

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
| `vault` | The current vault blob (encrypted, §3.2) | Created with the vault. Updated by compare-and-swap on every save. |

- **Other blobs:** older vault versions and whatever else the vault document lists (`keep`, §5), and replaced keys blobs. Maintenance deletes the ones nothing needs (§6.11).
- **Existence:** the `keys` ref is the sign that a vault exists. It is written first when the vault is created (§6.3).

## 5. The vault document

The app defines its vault document and hands it to `makeFlows({ labels, document })`:

| Function | Contract |
|----------|----------|
| `empty(now) → doc` | The vault of a new account, at revision 1. |
| `read(doc) → { doc, writable }` | Validates a decrypted document; throws if it isn't one. `writable` is false for a newer format version: the vault then opens read-only, as it does with newer keys (§3.3). |
| `commit(doc, operation, now, loadedBlobId) → doc` | Applies an operation (a function `(doc, now) → doc`) as the next revision: the revision grows by exactly 1. May be async, e.g. to upload blobs the new version refers to. |
| `revision(doc) → integer` | The revision, for rollback detection (§6.5). |
| `keep(doc) → [blob id]` | Every blob besides the vault blob itself that the vault still needs: earlier versions it keeps, and anything it refers to. May be async, e.g. to walk a tree of blobs. Cleanup deletes the rest (§6.11). |

- **Operations** are pure functions of the form `(document, now) → document`. A save re-applies the same operation to a newer document after a conflict (§6.4), so operations must make sense on any version.
- **Format:** the app's choice, apart from being JSON. Unknown fields should be preserved when the document is rewritten.

## 6. Flows

`flows.js` implements these on top of the API, WebAuthn and the pure modules; the app drives them from its UI.

### 6.1 Unlock with a passkey

1. `POST /auth/login/start`. The client adds `extensions.prf.eval.first = UTF-8(labels.prf)` to the options and calls `navigator.credentials.get()`. This is the only prompt.
2. It reads the PRF output from `getClientExtensionResults().prf.results.first`. If there is none, it stops: "This passkey can't unlock the vault (no PRF support)".
3. It deletes `clientExtensionResults.prf` from the credential JSON and calls `POST /auth/login/finish`, which creates the session.
4. It loads the keys blob (`GET /refs/keys`, then the blob) and unwraps the MK from `passkeys[credential.id]`.
   - If there is no `keys` ref, the result is `no-vault`, or `keys-missing` if a `vault` ref exists (§6.2, step 3).
   - If there is no such slot, the result is `no-slot`. The app offers to unlock with the recovery key, which then sets the passkey up (§6.9).
5. It loads the vault blob, verifies and decrypts it. The app checks for rollback (§6.5).
   - If `keys` exists but `vault` doesn't, a vault creation was interrupted. The client creates an empty vault with `If-None-Match: *`, unless the keys are from a newer version: then it asks to update the app.

When the app starts, it calls `GET /me`.
- **401:** it shows the unlock screen.
- **Valid session but no MK in memory** (after a reload or an interrupted setup): it shows the unlock screen with a second option, "Use recovery key". A passkey unlock still logs in again, which replaces the session.

### 6.2 Setup links

A setup link has the form `<origin>/#setup=<token>`, where the token is the backend's setup token.

When the app starts with a fragment:

1. It reads the token and immediately removes the fragment with `history.replaceState`, so it doesn't stay in history or on screen.
2. `POST /auth/setup-token`. A 401 means "This link has expired or was already used".
3. `GET /refs/keys`:
   - **No `keys` ref and no `vault` ref:** create the vault (§6.3).
   - **No `keys` ref but a `vault` ref:** stop and tell the user to restore the server's data. A new vault would come with new keys, and the existing vault could never be opened again. `unlockWithPasskey` and `createVault` report this as `keys-missing`.
   - **`keys` exists:** ask for the recovery key and unwrap the MK from `recovery`.
4. With the MK in memory, it registers a passkey on this host and sets it up (§6.6, steps 2–6). The setup-token session is fresh, so no step-up is needed. The user can skip this step, but then the next unlock on this host needs the recovery key again.

### 6.3 Creating the vault

1. Register a passkey on this host and get its PRF output (§6.6, steps 2–5).
2. Generate the MK and the recovery key.
3. Show the recovery key. The user has to confirm they saved it before continuing. Nothing has been stored yet, so closing the tab here leaves no trace.
4. Check that there is a `keys` ref or no `vault` ref. A `vault` ref without a `keys` ref stops the creation before anything is written (`keys-missing`, §6.2).
5. Build the keys document (with the recovery slot and this passkey's slot) and the first vault (`document.empty`). Upload both blobs.
6. `PUT keys` with `If-None-Match: *`. This is the commit.
   - A 412 means another device created a vault in the meantime. The client discards its own and switches to unlocking. Maintenance removes the orphaned blobs.
7. `PUT vault` with `If-None-Match: *`. If the client is interrupted before this step, the next unlock creates the empty vault (§6.1, step 5).

### 6.4 Saving changes

Both documents change only through operations: pure functions of the form `(document, now) → document`.

| Document | Operations |
|----------|------------|
| Vault    | The app's (§5) |
| Keys     | `setPasskey(credentialId, slot)`, `removePasskey(credentialId)`, `setRecovery(slot)`, `prune(existingCredentialIds)` |

A save applies an operation:

1. Apply the operation to the loaded document. For the vault, this goes through `document.commit`.
2. Serialize the result (and encrypt it, for the vault), upload it, then `PUT <ref>` with `If-Match: "<loaded blob id>"`.
3. On 412, fetch the document named in `current`, verify it (and decrypt it, for the vault), then apply the same operation to it and retry. The client tries at most 5 times, then reports an error.
4. On success, the new document becomes the loaded state. `saveVault` also returns the document the operation was finally applied to, so the app can tell the user about changes made on another device in the meantime.

- **When remote changes arrive:** there is no polling. A client sees other devices' changes when it unlocks, and through the 412 when it saves.

### 6.5 Rollback detection

- The app stores the highest vault revision it has seen in `localStorage`, under the state ID (§3.1). `rollbackCheck(highestSeen, revision)` compares the two.
- If a loaded vault has a lower revision, the app shows a warning and blocks saving until the user acknowledges it, which resets the stored value.
- A save that runs into a conflict whose current vault isn't newer than the one being saved over is a rollback too: the save stops with `RollbackError`, and nothing is written on top of the older vault.

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
2. `DELETE /me/passkeys/{id}`. On `reauth_required`, unlock again and retry.
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

0. **Check before deleting anything.** Stop, deleting nothing, if:
   - either ref is missing
   - the server's current vault or keys document is from a newer version
   - the server's vault is older than this session's (the app also doesn't run it while a rollback warning is shown)
   - any listed blob ID isn't 64 hex characters (IDs go into URLs)
1. **Prune the keys document:** remove passkey slots whose credential ID is not in `GET /me/passkeys`. Nothing is saved if nothing changed. Only the slots found stale are removed, also when the save is re-applied after a conflict, so a slot another device just added is never pruned.
2. **Build the keep set:** the current `keys` blob, the current `vault` blob, and `document.keep(vault)`.
3. **Delete old blobs:**
   - List all blobs.
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

## 7. Modules

Plain ES modules with no dependencies and no build step. An app copies `src/` into its static files (the Nix package has it at `share/e2ee-store/sdk`) and imports the modules by relative path; the backend's CSP (`script-src 'self'`) rules out import maps.

| Module            | Contents |
|-------------------|----------|
| `labels.js`       | `labels(namespace)` (§2) |
| `flows.js`        | `makeFlows({ labels, document })` (§5, §6): unlock, create, save, passkey slots, recovery key, maintenance |
| `api.js`          | The backend client: errors with fixed messages, hash-checked blobs, compare-and-swap refs, the 401 handler |
| `passkeys.js`     | WebAuthn ceremonies with PRF; `UserFacingError` |
| `crypto.js`       | HKDF, AES-GCM, SHA-256, base64url, hex |
| `envelope.js`     | The content key; `sealDocument` / `openDocument` (§3.2) |
| `keys.js`         | The keys document, wrap/unwrap, operations (§3.3) |
| `save.js`         | `saveWithRetry` (I/O passed in), `RollbackError`, `rollbackCheck` (§6.4, §6.5) |
| `maintenance.js`  | The cleanup plan, report and schedule (§6.11) |
| `recovery-key.js` | Generating, formatting and parsing recovery keys (§3.4) |
| `setup-link.js`   | Parsing and building setup fragments (§6.2) |

Messages shown to the user come from the SDK, never from the server, so a misbehaving server can't put its own text in front of the user (e.g. asking for the recovery key).

## 8. Security notes

- **What is protected:**
  - The vault's content is hidden from the server and from leaked database copies. So is its history.
  - Blob tampering is detected by content addressing plus GCM.
  - A rolled-back vault is detected by the revision check.
- **What is not protected:**
  - A server that serves malicious JavaScript. This is inherent to web apps, and the app is served by the same backend.
  - XSS in the app.
  - Malware on the device.
  - An attacker who already has the MK. Without key rotation, removing a passkey doesn't lock them out.
- **What the server sees:**
  - when and how often the vault and the keys blob change
  - the vault's size, padded to 4 KiB steps, and the number and sizes of other blobs
  - from the plaintext keys blob: which credential IDs have slots, and when the recovery key changes
- **Tampering with the keys blob:** the server can delete or replay slots, which can only cause a failed unlock. It can't create a working slot, because that needs a KEK.
- **Recovery key:** it is used whenever a new device is set up, so it gets pasted more often than a pure recovery secret would. Only paste it into the app.
  - The key plus a session gives full access. The key plus a stolen database also gives full access.
  - Replacing it (§6.10) doesn't help against someone who already used it, because there is no key rotation.
- **Memory:** while the vault is unlocked, the MK and all plaintext are in JavaScript memory. Locking should reload the page to drop them.

## 9. Testing

- **Unit tests** (`node --test`; Node has WebCrypto) for the pure modules:
  - **Crypto:** wrap/unwrap round trips; a tampered nonce, ciphertext or AAD fails; keys of another kind or another namespace fail.
  - **Labels:** derived from the namespace; invalid namespaces are refused.
  - **Documents:** padding and round trips.
  - **Keys documents:** validation; every operation; `version > 1` is read-only; another app's keys document is refused.
  - **Saving:** retries on conflict, gives up after 5, sync and async operations, rollback.
  - **Recovery key, setup links, maintenance:** parsing, the plan with its grace period, the report, the schedule.
- **Flow tests** (`node --test`) run the flows and the backend client against stand-ins for the browser (`test/fakes.js`): an in-memory backend behind `fetch` and an authenticator with PRF behind `navigator.credentials`. They cover creating and unlocking, setup and recovery, conflicts and rollback, newer versions, step-up, cleanup, and a server that misbehaves.
- **Format vectors:** `test/vectors.json` holds a keys blob and a vault blob of version 1, made from this spec by `test/make-vectors.mjs` with `node:crypto` alone. The SDK must keep opening them (§2).
- **Browser tests:** real WebAuthn against the real backend. This repository runs the flows with a stand-in app (`test/browser`); each app runs its own UI with `testing/e2ee_store_harness.py`:
  - `harness(run, static_dir)` starts the backend (`BACKEND_BIN`) serving the app's static files behind `socat`, the way the iroh shim reaches it, and Chromium.
  - `new_device(browser, base)` is a browser profile with a virtual authenticator that supports PRF (CDP `WebAuthn.addVirtualAuthenticator`, `hasPrf: true`). With `prf_at_create=False` it behaves like authenticators that give the PRF output only at sign-in.
  - `Backend` runs admin commands (`setup_token(...)`) and reads the stored blobs.
- **An app should test:** that data written by its earlier versions still opens with its labels (§2).
