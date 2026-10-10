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
// A session is { masterKey, contentKey, stateId, keys: { doc, blobId, writable }, user, vault: { doc, blobId, writable } }.

import * as api from "./api.js";
import * as passkeys from "./passkeys.js";
import { UserFacingError } from "./passkeys.js";
import { hexEncode, hkdfBytes, randomBytes } from "./crypto.js";
import { contentKey as deriveContentKey, openDocument, sealDocument } from "./envelope.js";
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

  async function decryptVault(contentKey, data) {
    try {
      return document.read(await openDocument(contentKey, labels.vault, data));
    } catch (error) {
      throw new api.IntegrityError(`the vault doesn't decrypt (${error.message})`);
    }
  }

  const loadVault = async (contentKey, blobId) => ({ ...(await decryptVault(contentKey, await api.getBlob(blobId))), blobId });

  /**
   * What this device remembers about the vault (the highest revision seen, the last cleanup) is filed under
   * an ID derived from the master key: the server can't change it, unlike the user ID it reports.
   */
  const deriveStateId = async (masterKey) => hexEncode(await hkdfBytes(masterKey, labels.stateId, 16));

  /** Opens the vault with the master key; creates the empty vault if a creation was interrupted. */
  async function open(masterKey, keys) {
    const contentKey = await deriveContentKey(labels, masterKey);
    const stateId = await deriveStateId(masterKey);
    const user = await api.me();
    const blobId = await api.getRef("vault");
    if (blobId) return { masterKey, contentKey, stateId, keys, user, vault: await loadVault(contentKey, blobId) };
    const doc = document.empty(now());
    const created = await api.putBlob(await sealDocument(contentKey, labels.vault, doc));
    const write = await api.putRef("vault", created, null);
    if (!write.ok) return open(masterKey, keys);
    return { masterKey, contentKey, stateId, keys, user, vault: { doc, blobId: created, writable: true } };
  }

  /** Step-up (backend/SPEC.md §6.5): a passkey login creates a fresh session. Its PRF output isn't used. */
  async function reauthenticate() {
    const { options } = await api.loginStart();
    const { credential } = await passkeys.get(options, labels.prf);
    await api.loginFinish(credential);
  }

  /**
   * Logs in with a passkey and unlocks with its PRF output.
   * → { kind: "unlocked", session } | { kind: "no-vault" } | { kind: "no-slot", credentialId, prfOutput, keys }
   */
  async function unlockWithPasskey() {
    const { options } = await api.loginStart();
    const { credential, credentialId, prfOutput } = await passkeys.get(options, labels.prf);
    if (!prfOutput) throw new UserFacingError("This passkey can't unlock the vault: it doesn't support the PRF extension.");
    await api.loginFinish(credential);
    const keys = await loadKeys();
    if (!keys) return { kind: "no-vault" };
    const slot = keys.doc.passkeys[credentialId];
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
      decode: async (data) => decodeKeys(labels, data).doc,
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
      const vault = vaultId === current.vault.blobId ? current.vault : await loadVault(current.contentKey, vaultId);
      if (!current.keys.writable || !vault.writable) throw new Error("The vault was written by a newer version of the app, so nothing was deleted.");
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
   * → { kind: "created", session } | { kind: "exists" } when another device got there first.
   */
  async function createVault({ masterKey, recoveryKey, credentialId, prfOutput }) {
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
      session: { masterKey, contentKey, stateId: await deriveStateId(masterKey), keys, user: await api.me(), vault: { doc: vaultDoc, blobId: vaultId, writable: true } },
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
        const conflict = await decryptVault(session.contentKey, data);
        if (!conflict.writable) throw new UserFacingError("Another device saved this vault with a newer version of the app; update this one first.");
        return conflict.doc;
      },
      // Another device's save is always a later revision; anything else is the server rolling the vault back.
      accept: (conflict, base) => document.revision(conflict) > document.revision(base),
    });
    return { session: { ...session, vault: { doc: saved.doc, blobId: saved.blobId, writable: true } }, base: saved.previous.doc };
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
  };
}
