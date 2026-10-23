// A stand-in app for the browser test: the SDK's flows in a real browser, behind `window.app`. No UI; the test
// calls these and gets JSON back. The SDK is next to it in `sdk/`, as an app ships it.

import * as api from "./sdk/api.js";
import { CHUNK_SIZE } from "./sdk/blobs.js";
import { makeFlows } from "./sdk/flows.js";
import { labels } from "./sdk/labels.js";
import { formatRecoveryKey, parseRecoveryKey } from "./sdk/recovery-key.js";

/** Notes, without history: every earlier version is something for cleanup. */
const notes = {
  empty: () => ({ format: "browser-test/notes", version: 1, revision: 1, notes: [] }),
  read: (doc) => {
    if (doc?.format !== "browser-test/notes") throw new Error("Not a notes document");
    return { doc, writable: doc.version <= 1 };
  },
  commit: (doc, operation, now) => ({ ...operation(doc, now), revision: doc.revision + 1 }),
  revision: (doc) => doc.revision,
  keep: () => [],
};

const flows = makeFlows({ labels: labels("browser-test"), document: notes });
let session = null;

/** Registers a passkey on this device and returns it with its PRF output, prompting again if needed. */
async function newPasskey(name) {
  const registered = await flows.registerPasskey(name);
  return { ...registered, prfOutput: registered.prfOutput ?? (await flows.prfFromPasskey(registered.credentialId)), prfAtCreate: registered.prfOutput !== null };
}

window.app = {
  signup: async (token) => {
    await api.exchangeSetupToken(token);
  },
  async createVault() {
    const passkey = await newPasskey("First device");
    const secrets = flows.newSecrets();
    const created = await flows.createVault({ ...secrets, credentialId: passkey.credentialId, prfOutput: passkey.prfOutput });
    session = created.session;
    return { kind: created.kind, prfAtCreate: passkey.prfAtCreate, recoveryKey: formatRecoveryKey(secrets.recoveryKey) };
  },
  /** A new device: the recovery key opens the vault, then the device gets a passkey of its own. */
  async join(recoveryKey) {
    const unlocked = await flows.unlockWithRecoveryKey(await flows.loadKeys(), parseRecoveryKey(recoveryKey));
    const passkey = await newPasskey("Second device");
    session = await flows.addPasskeySlot(unlocked, passkey.credentialId, passkey.prfOutput);
    return { notes: session.vault.doc.notes, prfAtCreate: passkey.prfAtCreate };
  },
  async unlock() {
    const result = await flows.unlockWithPasskey();
    if (result.kind === "unlocked") session = result.session;
    return result.kind;
  },
  async save(text) {
    ({ session } = await flows.saveVault(session, (doc) => ({ ...doc, notes: [...doc.notes, text] })));
    return session.vault.doc.notes;
  },
  async maintain() {
    const { report } = await flows.maintain(session, "manual");
    return report;
  },
  /** A file through putBlob and readBlob: whole, in ranges, pinned by its salt, and aborted while it streams. */
  async file() {
    const label = "browser-test/file/v1";
    const content = Uint8Array.from({ length: 3 * CHUNK_SIZE + 5000 }, (_, i) => (i * 7 + Math.floor(i / CHUNK_SIZE)) % 256);
    const { id, salt } = await flows.putBlob(session, label, content);
    const read = async (options) => {
      const { size, stream } = await flows.readBlob(session, label, id, options);
      return { size, bytes: new Uint8Array(await new Response(stream).arrayBuffer()) };
    };
    const matches = async (from, to, options = {}) => {
      const { size, bytes } = await read({ ...options, from, to });
      const expected = content.subarray(from ?? 0, Math.min(to ?? content.length, content.length));
      return size === content.length && bytes.length === expected.length && bytes.every((b, i) => b === expected[i]);
    };
    const ranges = [[undefined, undefined], [0, 10], [CHUNK_SIZE - 5, CHUNK_SIZE + 5], [2 * CHUNK_SIZE, undefined], [content.length - 3, content.length + 100]];
    const controller = new AbortController();
    const reader = (await flows.readBlob(session, label, id, { signal: controller.signal })).stream.getReader();
    await reader.read();
    controller.abort(new Error("next track"));
    return {
      ranges: await Promise.all(ranges.map(([from, to]) => matches(from, to))),
      pinned: await matches(CHUNK_SIZE, 2 * CHUNK_SIZE, { salt }),
      aborted: await reader.read().then(
        () => "not aborted",
        (e) => e.message,
      ),
    };
  },
};
