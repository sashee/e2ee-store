// The domain-separation labels (SPEC §2): HKDF infos, AADs, the PRF input and the keys format. Every app has
// its own namespace, so keys and blobs of one app are useless to another. Changing an app's namespace makes
// its existing data unreadable.

export function labels(namespace) {
  if (typeof namespace !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(namespace)) throw new Error(`Invalid namespace: ${namespace}`);
  return {
    prf: `${namespace}/prf/v1`,
    keysFormat: `${namespace}/keys`,
    kek: { passkey: `${namespace}/kek/passkey/v1`, recovery: `${namespace}/kek/recovery/v1` },
    slot: { passkey: `${namespace}/keys/v1/passkey`, recovery: `${namespace}/keys/v1/recovery` },
    stream: `${namespace}/stream/v1`,
    vault: `${namespace}/vault/v1`,
    /** Transitional: the content key of the format before streams (SPEC §3.5). */
    content: `${namespace}/content/v1`,
    stateId: `${namespace}/device-state-id/v1`,
  };
}
