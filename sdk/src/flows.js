// The flows of SPEC §6, on top of the API, WebAuthn and the pure modules. No DOM here.
//
// `makeFlows({ labels, document })` configures them for one app: `labels` come from labels.js, `document` is
// the app's vault document (SPEC §5):
//
//   empty(now) → doc                                   the vault of a new account
//   read(doc) → { doc, writable }                      validates; throws if it isn't one
//   commit(doc, operation, now, loadedBlobId) → doc    applies an operation as the next revision (may be async)
//   revision(doc) → integer                            grows by one with every save
//   keep(doc) → [blob id]                              blobs besides the current one that cleanup keeps (may be async)
//
// A session is { masterKey, contentKey, stateId, keys: { doc, blobId, writable }, user, vault: { doc, blobId, writable, legacy } },
// where `legacy` says the vault blob is in the format before streams (SPEC §3.5), which `upgradeVault` rewrites.

import * as api from "./api.js";
import * as blobs from "./blobs.js";
import * as passkeys from "./passkeys.js";
import { UserFacingError } from "./passkeys.js";
import { DecryptError, hexEncode, hkdfBytes, randomBytes } from "./crypto.js";
import { contentKey as deriveContentKey, legacyContentKey, openDocument, openLegacyDocument, sealDocument } from "./envelope.js";
import { decodeKeys, emptyKeys, encodeKeys, removePasskey, setPasskey, setRecovery, unwrap, WrongKeyError, wrap } from "./keys.js";
import { makeReport, planBlobs, prunableSlots } from "./maintenance.js";
import { generateRecoveryKey } from "./recovery-key.js";
import { saveWithRetry } from "./save.js";

const io = { putBlob: api.putBlob, putRef: api.putRef, getBlob: api.getBlob };
const now = () => Date.now();

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

export function makeFlows({ labels, document }) {
  async function loadKeys() {
    const blobId = await api.getRef("keys");
    if (!blobId) return null;
    return { ...decodeKeys(labels, await api.getBlob(blobId)), blobId };
  }

  /** A vault blob's document: in the stream format, or the one before it (transitional, SPEC §3.5). */
  async function openVaultBlob({ masterKey, contentKey }, data) {
    try {
      return { doc: await openDocument(contentKey, labels.vault, data), legacy: false };
    } catch (error) {
      if (!(error instanceof DecryptError)) throw error;
      return { doc: await openLegacyDocument(await legacyContentKey(labels, masterKey), labels.vault, data), legacy: true };
    }
  }

  /** `keys` are the session's (or { masterKey, contentKey }). → { doc, writable, legacy } */
  async function decryptVault(keys, data) {
    try {
      const { doc, legacy } = await openVaultBlob(keys, data);
      return { ...document.read(doc), legacy };
    } catch (error) {
      throw new api.IntegrityError(`the vault doesn't decrypt (${error.message})`);
    }
  }

  const loadVault = async (keys, blobId) => ({ ...(await decryptVault(keys, await api.getBlob(blobId))), blobId });

  /**
   * What this device remembers about the vault (the highest revision seen, the last cleanup) is filed under
   * an ID derived from the master key: the server can't change it, unlike the user ID it reports.
   */
  const deriveStateId = async (masterKey) => hexEncode(await hkdfBytes(masterKey, labels.stateId, 16));

  /**
   * Opens the vault with the master key; creates the empty vault if a creation was interrupted. The keys' version
   * covers the vault's format too (SPEC §3.3), so keys from a newer version make the vault read-only.
   */
  async function open(masterKey, keys) {
    const contentKey = await deriveContentKey(labels, masterKey);
    const stateId = await deriveStateId(masterKey);
    const user = await api.me();
    const blobId = await api.getRef("vault");
    if (blobId) {
      const vault = await loadVault({ masterKey, contentKey }, blobId);
      return { masterKey, contentKey, stateId, keys, user, vault: { ...vault, writable: vault.writable && keys.writable } };
    }
    if (!keys.writable) throw new UserFacingError("This vault was created by a newer version of the app; update this one to open it.");
    const doc = document.empty(now());
    const created = await api.putBlob(await sealDocument(contentKey, labels.vault, doc));
    const write = await api.putRef("vault", created, null);
    if (!write.ok) return open(masterKey, keys);
    return { masterKey, contentKey, stateId, keys, user, vault: { doc, blobId: created, writable: true, legacy: false } };
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
   * Cleanup (SPEC §6.11): prunes slots of deleted passkeys, then deletes blobs that neither the current keys
   * nor the current vault (with what `document.keep` lists) need. Never throws: failures end up in the report.
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
      const vault = vaultId === current.vault.blobId ? current.vault : await loadVault(current, vaultId);
      if (!(await keysWritable(current, keysId)) || !vault.writable) throw new Error("The vault was written by a newer version of the app, so nothing was deleted.");
      if (document.revision(vault.doc) < document.revision(current.vault.doc)) throw new Error("The server returned an older vault than this session's, so nothing was deleted.");

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
      const keep = [stale.length > 0 ? current.keys.blobId : keysId, vaultId, ...((await document.keep(vault.doc)) ?? [])];
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
    const vaultDoc = document.empty(t);
    const keysId = await api.putBlob(encodeKeys(keysDoc));
    const vaultId = await api.putBlob(await sealDocument(contentKey, labels.vault, vaultDoc));
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
        vault: { doc: vaultDoc, blobId: vaultId, writable: true, legacy: false },
      },
    };
  }

  /**
   * Saves a vault operation (SPEC §6.4); re-applied on top of other devices' changes.
   * → { session, base } where `base` is the vault document the operation was finally applied to.
   */
  async function saveVault(session, operation) {
    if (!session.vault.writable) throw new UserFacingError("This vault was written by a newer version of the app; it's read-only here.");
    const saved = await saveWithRetry(io, {
      ref: "vault",
      loaded: session.vault,
      apply: (doc, blobId) => document.commit(doc, operation, now(), blobId),
      encode: (doc) => sealDocument(session.contentKey, labels.vault, doc),
      decode: async (data) => {
        const conflict = await decryptVault(session, data);
        const keysId = await api.getRef("keys");
        if (!conflict.writable || (keysId && !(await keysWritable(session, keysId)))) {
          throw new UserFacingError("Another device saved this vault with a newer version of the app; update this one first.");
        }
        return conflict.doc;
      },
      // Another device's save is always a later revision; anything else is the server rolling the vault back.
      accept: (conflict, base) => document.revision(conflict) > document.revision(base),
    });
    return { session: { ...session, vault: { doc: saved.doc, blobId: saved.blobId, writable: true, legacy: false } }, base: saved.previous.doc };
  }

  /**
   * Transitional (SPEC §6.13): rewrites a vault from the format before streams in the stream format, as one save.
   * `rewrite(doc, reseal)` returns the document with the blobs it refers to rewritten too, through
   * `reseal(blobId, label = labels.vault) → new blob ID`, which re-encrypts one document of the old format. The loaded
   * blob is resealed as well, and `document.commit` puts the copy where the loaded blob goes (e.g. into a history).
   * The new blob has to open to the same document before the ref moves. No retry: after a conflict nothing has
   * changed, and the next unlock tries again. A vault that isn't legacy, or is read-only, stays as it is.
   * → session
   */
  async function upgradeVault(session, rewrite = (doc) => doc) {
    if (!session.vault.legacy || !session.vault.writable) return session;
    const legacyKey = await legacyContentKey(labels, session.masterKey);
    const reseal = async (blobId, label = labels.vault) =>
      api.putBlob(await sealDocument(session.contentKey, label, await openLegacyDocument(legacyKey, label, await api.getBlob(blobId))));
    const copy = await reseal(session.vault.blobId);
    const doc = await document.commit(await rewrite(session.vault.doc, reseal), (d) => d, now(), copy);
    const sealed = await sealDocument(session.contentKey, labels.vault, doc);
    if (JSON.stringify(await openDocument(session.contentKey, labels.vault, sealed)) !== JSON.stringify(doc)) {
      throw new Error("The upgraded vault doesn't open to the same document; nothing was changed.");
    }
    const blobId = await api.putBlob(sealed);
    if (!(await api.putRef("vault", blobId, session.vault.blobId)).ok) return session;
    return { ...session, vault: { doc, blobId, writable: true, legacy: false } };
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
    saveVault,
    upgradeVault,
    /** Seals `data` as a blob of kind `label` and uploads it (SPEC §6.12). → { id, salt } */
    putBlob: (session, label, data, options) => blobs.putBlob(session.contentKey, label, data, options),
    /** Reads all of a blob or a range of it (SPEC §6.12). → { size, stream } */
    readBlob: (session, label, id, options) => blobs.readBlob(session.contentKey, label, id, options),
  };
}
