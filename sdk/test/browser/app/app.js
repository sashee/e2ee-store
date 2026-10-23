// A stand-in app for the browser test: the SDK's flows in a real browser, behind `window.app`. No UI; the test
// calls these and gets JSON back. The SDK is next to it in `sdk/`, as an app ships it.

import * as api from "./sdk/api.js";
import { CHUNK_SIZE } from "./sdk/blobs.js";
import { makeFlows } from "./sdk/flows.js";
import { labels } from "./sdk/labels.js";
import { formatRecoveryKey, parseRecoveryKey } from "./sdk/recovery-key.js";

const flows = makeFlows({ labels: labels("browser-test") });
let session = null;

/** Notes in notes.json; every save replaces it, so earlier versions are something for cleanup. */
const NOTES = ["notes.json"];
const encode = (value) => new TextEncoder().encode(JSON.stringify(value));
const decode = (bytes) => (bytes === null ? null : JSON.parse(new TextDecoder().decode(bytes)));
const collect = async (opened) => new Uint8Array(await new Response((await opened).stream).arrayBuffer());

async function notes() {
  const entry = (await flows.list(session, [])).find((e) => e.name === "notes.json");
  return entry ? decode(await collect(flows.read(session, entry))) : [];
}

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
    return { notes: await notes(), prfAtCreate: passkey.prfAtCreate };
  },
  async unlock() {
    const result = await flows.unlockWithPasskey();
    if (result.kind === "unlocked") session = result.session;
    return result.kind;
  },
  async save(text) {
    const add = async (tx) => tx.put(NOTES, tx.upload(encode([...(decode(await tx.read(NOTES)) ?? []), text])));
    ({ session } = await flows.save(session, [add]));
    return notes();
  },
  async maintain() {
    const { report } = await flows.maintain(session, "manual");
    return report;
  },
  /** A file through the tree: whole, in ranges (pinned by its entry's salt), and aborted while it streams. */
  async file() {
    const content = Uint8Array.from({ length: 3 * CHUNK_SIZE + 5000 }, (_, i) => (i * 7 + Math.floor(i / CHUNK_SIZE)) % 256);
    ({ session } = await flows.save(session, [(tx) => tx.put(["Music", "track.bin"], tx.upload(content))]));
    const [entry] = await flows.list(session, ["Music"]);
    const matches = async (from, to) => {
      const { size, stream } = await flows.read(session, entry, { from, to });
      const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
      const expected = content.subarray(from ?? 0, Math.min(to ?? content.length, content.length));
      return size === content.length && bytes.length === expected.length && bytes.every((b, i) => b === expected[i]);
    };
    const ranges = [[undefined, undefined], [0, 10], [CHUNK_SIZE - 5, CHUNK_SIZE + 5], [2 * CHUNK_SIZE, undefined], [content.length - 3, content.length + 100]];
    const controller = new AbortController();
    const reader = (await flows.read(session, entry, { signal: controller.signal })).stream.getReader();
    await reader.read();
    controller.abort(new Error("next track"));
    return {
      ranges: await Promise.all(ranges.map(([from, to]) => matches(from, to))),
      entry: { name: entry.name, size: entry.size, sha256: /^[0-9a-f]{64}$/.test(entry.sha256) },
      aborted: await reader.read().then(
        () => "not aborted",
        (e) => e.message,
      ),
    };
  },
};
