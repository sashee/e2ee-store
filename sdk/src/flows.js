// The flows of SPEC §6, on top of the API, WebAuthn and the pure modules. No DOM here.
//
// `makeFlows({ labels })` configures them for one app, whose data is a tree of files (SPEC §5): `labels` come from
// labels.js.
//
// A session is { masterKey, contentKey, stateId, keys: { doc, blobId, writable }, user, root }, where `root` is the
// loaded root directory: { version, revision, entries, blobId, writable }.

import * as api from "./api.js";
import * as encrypted from "./blobs.js";
import * as passkeys from "./passkeys.js";
import { UserFacingError } from "./passkeys.js";
import { hexEncode, hkdfBytes, randomBytes, td, te } from "./crypto.js";
import { contentKey as deriveContentKey } from "./envelope.js";
import { decodeKeys, emptyKeys, encodeKeys, removePasskey, setPasskey, setRecovery, unwrap, WrongKeyError, wrap } from "./keys.js";
import { makeReport, planBlobs, prunableSlots } from "./maintenance.js";
import { generateRecoveryKey } from "./recovery-key.js";
import { saveWithRetry } from "./save.js";
import * as stream from "./stream.js";
import * as tree from "./tree.js";

const io = { putBlob: api.putBlob, putRef: api.putRef, getBlob: api.getBlob };
const now = () => Date.now();
/** Directories kept in memory per content key; the oldest go first. */
const CACHED_DIRS = 4096;
/** Uploads running at once in a save. */
const PARALLEL_UPLOADS = 3;

/** Runs at most `max` of the tasks given to it at a time. */
function limiter(max) {
  let running = 0;
  const waiting = [];
  const next = () => {
    if (running >= max || waiting.length === 0) return;
    running += 1;
    waiting.shift()();
  };
  return (task) =>
    new Promise((resolve, reject) => {
      waiting.push(() =>
        task()
          .then(resolve, reject)
          .finally(() => {
            running -= 1;
            next();
          }),
      );
      next();
    });
}

/** A save's progress: what is uploaded of `planned` ({ source, offloadable }, from tree.uploads), in files and bytes. */
function progressOf(planned, finished) {
  const size = ({ source }) => (source instanceof Uint8Array ? source.length : source.size);
  const done = planned.filter(({ source, offloadable }) => finished.get(source)?.has(offloadable));
  const sum = (list) => list.reduce((total, upload) => total + size(upload), 0);
  return { files: done.length, bytes: sum(done), totalFiles: planned.length, totalBytes: sum(planned) };
}

const rootDoc = ({ blobId: _blobId, writable: _writable, ...doc }) => doc;

/** All blob metadata, page by page, with the server's clock from the last page. */
async function listAllBlobs() {
  const blobs = [];
  let page = await api.listBlobs();
  blobs.push(...page.blobs);
  while (page.next) {
    page = await api.listBlobs(page.next);
    blobs.push(...page.blobs);
  }
  return { blobs, serverNow: page.serverNow };
}

/** The secrets of a new vault. Nothing is stored until `createVault`. */
export const newSecrets = () => ({ masterKey: randomBytes(32), recoveryKey: generateRecoveryKey() });

export function makeFlows({ labels }) {
  async function loadKeys() {
    const blobId = await api.getRef("keys");
    if (!blobId) return null;
    return { ...decodeKeys(labels, await api.getBlob(blobId)), blobId };
  }

  // ---------------------------------------------------------------- the tree's blobs (SPEC §5)

  const sealDir = (contentKey, doc) => stream.seal(contentKey, labels.dir, te.encode(JSON.stringify(doc)));

  /**
   * Directories never change, so each is read and checked once per content key, while it stays among the last
   * CACHED_DIRS. The entries they list are the ones `put` accepts back (tree.js).
   */
  const caches = new WeakMap();
  const cacheOf = (contentKey) => {
    if (!caches.has(contentKey)) caches.set(contentKey, { dirs: new Map(), known: new Map() });
    return caches.get(contentKey);
  };

  function remember(contentKey, id, doc) {
    const { dirs } = cacheOf(contentKey);
    dirs.delete(id);
    dirs.set(id, doc);
    if (dirs.size > CACHED_DIRS) dirs.delete(dirs.keys().next().value);
    return learn(contentKey, doc);
  }

  /** Makes a directory's entries ones that `put` accepts back (tree.js). */
  function learn(contentKey, doc) {
    const { known } = cacheOf(contentKey);
    doc.entries.forEach((entry) => known.set(entry.id, entry));
    return doc;
  }

  async function loadDir(contentKey, id) {
    const cached = cacheOf(contentKey).dirs.get(id);
    if (cached) return cached;
    const data = await encrypted.openBlob(contentKey, labels.dir, id);
    try {
      return remember(contentKey, id, tree.parseDir(td.decode(data)));
    } catch (error) {
      throw new api.IntegrityError(`directory ${id} isn't one (${error.message})`);
    }
  }

  /**
   * What tree.js needs, for one session. `onUploaded({ source, offloadable })` follows a save's uploads, which
   * `uploads` keeps across its attempts.
   */
  function treeIO(session, { signal, uploads = new Map(), onUploaded = () => {} } = {}) {
    const { contentKey } = session;
    const limit = limiter(PARALLEL_UPLOADS);
    const upload = async (source, offloadable) => {
      const plaintext = source instanceof Uint8Array ? source : new Uint8Array(await source.arrayBuffer());
      const done = await encrypted.putBlob(contentKey, labels.file, plaintext, { offloadable, signal });
      onUploaded({ source, offloadable });
      return done;
    };
    return {
      loadDir: (id) => loadDir(contentKey, id),
      readFile: (entry) => encrypted.openBlob(contentKey, labels.file, entry.id),
      known: (id) => cacheOf(contentKey).known.get(id),
      upload: (source, { offloadable }) => tree.perUpload(uploads, { source, offloadable }, () => limit(() => upload(source, offloadable))),
      writeDir: async (doc) => {
        const sealed = await sealDir(contentKey, doc);
        const id = await api.putBlob(sealed, { signal });
        remember(contentKey, id, doc);
        return { id, salt: hexEncode(sealed.subarray(0, stream.SALT)) };
      },
    };
  }

  /** The vault blob's root directory, decrypted and checked. */
  async function openRoot(contentKey, data) {
    try {
      return tree.parseDir(td.decode(await stream.open(contentKey, labels.dir, data)), { root: true });
    } catch (error) {
      throw new api.IntegrityError(`the vault doesn't decrypt to a directory (${error.message})`);
    }
  }

  /**
   * What this device remembers about the vault (the highest revision seen, the last cleanup) is filed under
   * an ID derived from the master key: the server can't change it, unlike the user ID it reports.
   */
  const deriveStateId = async (masterKey) => hexEncode(await hkdfBytes(masterKey, labels.stateId, 16));

  /**
   * Opens the vault with the master key: loads its root directory, or creates an empty one if a creation was
   * interrupted. The keys' version covers the tree's format too (SPEC §3.3), so keys from a newer version make it
   * read-only.
   */
  async function open(masterKey, keys) {
    const contentKey = await deriveContentKey(labels, masterKey);
    const opened = { masterKey, contentKey, stateId: await deriveStateId(masterKey), keys, user: await api.me() };
    const blobId = await api.getRef("vault");
    if (blobId) {
      const root = remember(contentKey, blobId, await openRoot(contentKey, await api.getBlob(blobId)));
      return { ...opened, root: { ...root, blobId, writable: tree.writable(root) && keys.writable } };
    }
    if (!keys.writable) throw new UserFacingError("This vault was created by a newer version of the app; update this one to open it.");
    const root = tree.emptyRoot(1);
    const created = await api.putBlob(await sealDir(contentKey, root));
    if (!(await api.putRef("vault", created, null)).ok) return open(masterKey, keys);
    remember(contentKey, created, root);
    return { ...opened, root: { ...root, blobId: created, writable: true } };
  }

  /**
   * Whether the keys blob `blobId` is from this version, read only if it isn't the session's: another device may
   * have moved the keys, and with them the vault's format, to a newer version since the unlock (SPEC §3.3).
   */
  const keysWritable = async (session, blobId) =>
    blobId === session.keys.blobId ? session.keys.writable : decodeKeys(labels, await api.getBlob(blobId)).writable;

  /**
   * Step-up (backend/SPEC.md §6.5): a passkey login creates a fresh session. Its PRF output isn't used. The passkey
   * must be the session user's: one of another account on this host would switch the session to that account while
   * this one's master key is in memory, so that login is logged out again, and the app has to unlock again.
   */
  async function reauthenticate(session) {
    const { options } = await api.loginStart();
    const { credential } = await passkeys.get(options, labels.prf);
    const { user } = await api.loginFinish(credential);
    if (user.id !== session.user.id) {
      await api.logout();
      throw new UserFacingError("That passkey belongs to another account. Unlock again with one of yours.");
    }
  }

  /**
   * Without a `keys` ref, there is no vault yet, unless the `vault` ref exists: then its keys are missing, and a new
   * vault would come with new keys and leave the existing one unopenable (SPEC §6.2).
   */
  const keysMissing = async () => (await api.getRef("vault")) !== null;

  /**
   * Logs in with a passkey and unlocks with its PRF output.
   * → { kind: "unlocked", session } | { kind: "no-vault" } | { kind: "keys-missing" } | { kind: "no-slot", credentialId, prfOutput, keys }
   */
  async function unlockWithPasskey() {
    const { options } = await api.loginStart();
    const { credential, credentialId, prfOutput } = await passkeys.get(options, labels.prf);
    if (!prfOutput) throw new UserFacingError("This passkey can't unlock the vault: it doesn't support the PRF extension.");
    await api.loginFinish(credential);
    const keys = await loadKeys();
    if (!keys) return { kind: (await keysMissing()) ? "keys-missing" : "no-vault" };
    const slot = Object.hasOwn(keys.doc.passkeys, credentialId) ? keys.doc.passkeys[credentialId] : null;
    if (!slot) return { kind: "no-slot", credentialId, prfOutput, keys };
    return { kind: "unlocked", session: await open(await unwrap(labels, "passkey", prfOutput, slot), keys) };
  }

  async function unlockWithRecoveryKey(keys, recoveryKey) {
    if (!keys.doc.recovery) throw new UserFacingError("This vault has no recovery key.");
    return open(await unwrap(labels, "recovery", recoveryKey, keys.doc.recovery), keys);
  }

  /**
   * Registers a passkey on this host (SPEC §6.6 steps 1–4).
   * → { credentialId, prfOutput } where prfOutput is null if the browser only gives it at sign-in.
   */
  async function registerPasskey(name) {
    const { options } = await api.registerStart();
    const created = await passkeys.create(options, labels.prf);
    if (!created.prfEnabled) throw new UserFacingError("This authenticator can't unlock the vault: it doesn't support the PRF extension.");
    await api.registerFinish(name, created.credential);
    return { credentialId: created.credentialId, prfOutput: created.prfOutput };
  }

  /** Signs in with one particular passkey to get its PRF output (SPEC §6.6 step 5). */
  async function prfFromPasskey(credentialId) {
    const { options } = await api.loginStart();
    const signed = await passkeys.get(options, labels.prf, credentialId);
    if (!signed.prfOutput) throw new UserFacingError("The passkey didn't return a PRF output.");
    await api.loginFinish(signed.credential);
    return signed.prfOutput;
  }

  const saveKeys = async (session, operation) => {
    if (!session.keys.writable) throw new UserFacingError("The keys were written by a newer version of the app; update it first.");
    const saved = await saveWithRetry(io, {
      ref: "keys",
      loaded: session.keys,
      apply: (doc) => operation(doc, now()),
      encode: async (doc) => encodeKeys(doc),
      decode: async (data) => {
        const conflict = decodeKeys(labels, data);
        if (!conflict.writable) throw new UserFacingError("Another device saved the keys with a newer version of the app; update this one first.");
        return conflict.doc;
      },
    });
    return { ...session, keys: { doc: saved.doc, blobId: saved.blobId, writable: true } };
  };

  const addPasskeySlot = async (session, credentialId, prfOutput) =>
    saveKeys(session, setPasskey(credentialId, await wrap(labels, "passkey", prfOutput, session.masterKey, now())));

  const removePasskeySlot = (session, credentialId) => saveKeys(session, removePasskey(credentialId));

  const replaceRecoveryKey = async (session, recoveryKey) =>
    saveKeys(session, setRecovery(await wrap(labels, "recovery", recoveryKey, session.masterKey, now())));

  /**
   * Cleanup (SPEC §6.11): prunes slots of deleted passkeys, then deletes blobs that neither the current keys nor the
   * current root reach. Never throws: failures end up in the report.
   * → { session, report }
   */
  async function maintain(session, trigger, onProgress = () => {}) {
    const startedAt = now();
    let current = session;
    let slotsRemoved = 0;
    let plan = null;
    const deleted = [];
    const failed = [];
    let error = null;
    try {
      // Check everything before deleting anything: a missing or older document must never lead to deletions.
      onProgress("Reading the current vault");
      const keysId = await api.getRef("keys");
      const vaultId = await api.getRef("vault");
      if (!keysId || !vaultId) throw new Error("The keys or the vault are missing on the server, so nothing was deleted.");
      const vault = vaultId === current.root.blobId ? rootDoc(current.root) : await openRoot(current.contentKey, await api.getBlob(vaultId));
      if (!(await keysWritable(current, keysId)) || !tree.writable(vault)) throw new Error("The vault was written by a newer version of the app, so nothing was deleted.");
      if (vault.revision < current.root.revision) throw new Error("The server returned an older vault than this session's, so nothing was deleted.");

      onProgress("Checking passkeys");
      const passkeyIds = (await api.passkeys()).passkeys.map((p) => p.id);
      const stale = prunableSlots(current.keys.doc, passkeyIds);
      if (stale.length > 0) {
        // Only the slots that were stale now: re-applied after a conflict, a fresh prune could remove a slot that
        // another device just added for a new passkey.
        current = await saveKeys(current, (doc) => stale.reduce((d, id) => removePasskey(id)(d), doc));
        slotsRemoved = stale.length;
      }

      onProgress("Listing blobs");
      const { blobs, serverNow } = await listAllBlobs();
      if (serverNow === null) throw new Error("The server didn't say what time it is, so nothing was deleted.");
      blobs.forEach((b) => api.checkBlobId(b.id));
      onProgress("Walking the tree");
      const reachable = await tree.reachable(vault, (id) => loadDir(current.contentKey, id));
      const keep = [stale.length > 0 ? current.keys.blobId : keysId, vaultId, ...reachable];
      plan = planBlobs({ keep, blobs, now: serverNow });
      for (const [index, blob] of plan.toDelete.entries()) {
        onProgress(`Deleting ${index + 1} of ${plan.toDelete.length}`);
        try {
          await api.deleteBlob(blob.id);
          deleted.push(blob);
        } catch (e) {
          if (e.status === 401) throw e;
          failed.push({ id: blob.id, error: e.message });
        }
      }
    } catch (e) {
      error = e.message ?? String(e);
    }
    return { session: current, report: makeReport({ trigger, startedAt, finishedAt: now(), slotsRemoved, plan, deleted, failed, error }) };
  }

  /**
   * Checks a recovery key against the vault: it must unwrap the current recovery slot to this session's master
   * key. Reads the keys from the server, so a removed or replaced slot shows up.
   * → "ok" | "wrong" | "missing"
   */
  async function testRecoveryKey(session, recoveryKey) {
    const keys = await loadKeys();
    if (!keys?.doc.recovery) return "missing";
    try {
      const masterKey = await unwrap(labels, "recovery", recoveryKey, keys.doc.recovery);
      return masterKey.length === session.masterKey.length && masterKey.every((b, i) => b === session.masterKey[i]) ? "ok" : "wrong";
    } catch (e) {
      if (e instanceof WrongKeyError) return "wrong";
      throw e;
    }
  }

  /**
   * Creates the vault (SPEC §6.3): writing `keys` is the commit.
   * → { kind: "created", session } | { kind: "exists" } when another device got there first
   *   | { kind: "keys-missing" } when a vault exists without keys; nothing is written then.
   */
  async function createVault({ masterKey, recoveryKey, credentialId, prfOutput }) {
    if ((await api.getRef("keys")) === null && (await keysMissing())) return { kind: "keys-missing" };
    const t = now();
    const keysDoc = setRecovery(await wrap(labels, "recovery", recoveryKey, masterKey, t))(
      setPasskey(credentialId, await wrap(labels, "passkey", prfOutput, masterKey, t))(emptyKeys(labels)),
    );
    const contentKey = await deriveContentKey(labels, masterKey);
    const root = tree.emptyRoot(1);
    const keysId = await api.putBlob(encodeKeys(keysDoc));
    const vaultId = await api.putBlob(await sealDir(contentKey, root));
    if (!(await api.putRef("keys", keysId, null)).ok) return { kind: "exists" };
    const vaultWrite = await api.putRef("vault", vaultId, null);
    const keys = { doc: keysDoc, blobId: keysId, writable: true };
    if (!vaultWrite.ok) return { kind: "created", session: await open(masterKey, keys) };
    return {
      kind: "created",
      session: {
        masterKey,
        contentKey,
        stateId: await deriveStateId(masterKey),
        keys,
        user: await api.me(),
        root: { ...root, blobId: vaultId, writable: true },
      },
    };
  }

  const checkSteps = (steps) => {
    if (!Array.isArray(steps) || !steps.every((step) => typeof step === "function")) throw new TypeError("A save takes an array of steps, each (tx) => tx");
  };

  /**
   * Saves changes to the tree (SPEC §6.4): `steps` take a tx and return the next one. Their new files are uploaded,
   * the changed directories written, and the `vault` ref moved by compare-and-swap; after a conflict the steps run
   * again on the newer root, reusing the uploads. `onProgress({ files, bytes, totalFiles, totalBytes })` follows the
   * uploads; `signal` aborts them, and the save, until the ref moves. → { session }
   */
  async function save(session, steps, { signal, onProgress = () => {} } = {}) {
    checkSteps(steps);
    if (!session.root.writable) throw new UserFacingError("This vault was written by a newer version of the app; it's read-only here.");
    signal?.throwIfAborted();
    const finished = new Map();
    let planned = [];
    const report = () => onProgress(progressOf(planned, finished));
    const treeIo = treeIO(session, {
      signal,
      onUploaded: (upload) => {
        tree.perUpload(finished, upload, () => true);
        report();
      },
    });
    const saved = await saveWithRetry(
      { ...io, putBlob: (bytes) => api.putBlob(bytes, { signal }) },
      {
        ref: "vault",
        loaded: { doc: rootDoc(session.root), blobId: session.root.blobId },
        apply: async (root) => {
          // Each step takes a tx and returns the next (SPEC §6.4).
          const final = await steps.reduce(async (tx, step) => step(await tx), Promise.resolve(tree.begin(root, treeIo, now())));
          planned = await tree.uploads(final);
          report();
          const doc = await tree.commit(final, treeIo);
          signal?.throwIfAborted();
          return doc;
        },
        encode: (doc) => sealDir(session.contentKey, doc),
        decode: async (data) => {
          const conflict = await openRoot(session.contentKey, data);
          const keysId = await api.getRef("keys");
          if (!tree.writable(conflict) || (keysId && !(await keysWritable(session, keysId)))) {
            throw new UserFacingError("Another device saved this vault with a newer version of the app; update this one first.");
          }
          // The steps run again on this root, and may put its entries back.
          return learn(session.contentKey, conflict);
        },
        // Another device's save is always a later revision; anything else is the server rolling the vault back.
        accept: (conflict, base) => conflict.revision > base.revision,
      },
    );
    remember(session.contentKey, saved.blobId, saved.doc);
    return { session: { ...session, root: { ...saved.doc, blobId: saved.blobId, writable: true } } };
  }

  /** The entries of the directory at `path` ([] is the root), sorted by name (SPEC §6.12). */
  function list(session, path) {
    return tree.begin(rootDoc(session.root), treeIO(session), now()).list(path);
  }

  /** A file's content, all of it or a range, as a stream; `ref` is an entry or any saved { id, salt } (SPEC §6.12). */
  function read(session, ref, options = {}) {
    if (typeof ref?.id !== "string" || typeof ref?.salt !== "string") throw new TypeError("A file's ref has an id and a salt: an entry from list, or one saved earlier");
    return encrypted.readBlob(session.contentKey, labels.file, ref.id, { ...options, salt: ref.salt });
  }

  /**
   * Sets whether the files with these blob IDs are offloadable (SPEC §6.13), one request each. Entries don't record
   * the flag, so the tree doesn't change. Only files can be: the server refuses the root, and this refuses the
   * directories the session knows.
   */
  async function setOffloadable(session, ids, offloadable) {
    if (!Array.isArray(ids) || typeof offloadable !== "boolean") throw new TypeError("setOffloadable takes an array of blob IDs and true or false");
    const { known } = cacheOf(session.contentKey);
    const dir = offloadable && ids.find((id) => known.get(id)?.kind === "dir");
    if (dir) throw new TypeError(`Only files can be offloadable, and ${dir} is a directory`);
    const limit = limiter(PARALLEL_UPLOADS);
    await Promise.all(ids.map((id) => limit(() => api.setOffloadable(id, offloadable))));
  }

  return {
    loadKeys,
    open,
    reauthenticate,
    unlockWithPasskey,
    unlockWithRecoveryKey,
    registerPasskey,
    prfFromPasskey,
    addPasskeySlot,
    removePasskeySlot,
    replaceRecoveryKey,
    maintain,
    testRecoveryKey,
    newSecrets,
    createVault,
    save,
    list,
    read,
    setOffloadable,
  };
}
