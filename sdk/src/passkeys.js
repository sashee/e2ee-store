// WebAuthn ceremonies with the PRF extension (SPEC §3.1, §6.1, §6.6).
//
// Converts between WebAuthn's JSON (base64url) and the ArrayBuffers the browser API takes by hand, so it
// works where parse*FromJSON doesn't exist. PRF results are secrets: they are removed from the credential
// before it is sent to the server.

import { b64urlDecode, b64urlEncode, te } from "./crypto.js";

export class UserFacingError extends Error {}

const descriptors = (list) => (list ?? []).map((d) => ({ ...d, id: b64urlDecode(d.id) }));

/** The credential as WebAuthn JSON, without any PRF output. */
function credentialJSON(credential, kind) {
  const json = typeof credential.toJSON === "function" ? credential.toJSON() : manualJSON(credential, kind);
  const { prf: _secret, ...clientExtensionResults } = json.clientExtensionResults ?? {};
  return { ...json, clientExtensionResults };
}

function manualJSON(credential, kind) {
  const r = credential.response;
  const common = {
    id: credential.id,
    rawId: b64urlEncode(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    clientExtensionResults: {},
  };
  if (kind === "create") {
    const key = r.getPublicKey ? r.getPublicKey() : null;
    return {
      ...common,
      response: {
        clientDataJSON: b64urlEncode(r.clientDataJSON),
        attestationObject: b64urlEncode(r.attestationObject),
        transports: r.getTransports ? r.getTransports() : [],
        ...(key ? { authenticatorData: b64urlEncode(r.getAuthenticatorData()), publicKey: b64urlEncode(key), publicKeyAlgorithm: r.getPublicKeyAlgorithm() } : {}),
      },
    };
  }
  return {
    ...common,
    response: {
      clientDataJSON: b64urlEncode(r.clientDataJSON),
      authenticatorData: b64urlEncode(r.authenticatorData),
      signature: b64urlEncode(r.signature),
      userHandle: r.userHandle ? b64urlEncode(r.userHandle) : null,
    },
  };
}

/**
 * The PRF output: null when the authenticator gave none. Anything else must be exactly 32 bytes in an
 * ArrayBuffer or a view of one. A string or an empty buffer would otherwise turn into an empty key, and the
 * master key would be wrapped under a key anyone can compute.
 */
export function prfResult(credential) {
  const first = credential.getClientExtensionResults()?.prf?.results?.first;
  if (first === undefined || first === null) return null;
  const output =
    first instanceof ArrayBuffer ? new Uint8Array(first.slice(0))
    : ArrayBuffer.isView(first) ? new Uint8Array(first.buffer.slice(first.byteOffset, first.byteOffset + first.byteLength))
    : null;
  if (output === null || output.length !== 32) throw new UserFacingError("The passkey returned a PRF output in an unexpected form, so it can't be used to unlock the vault.");
  return output;
}

function explain(error, doing) {
  if (error?.name === "NotAllowedError") return new UserFacingError(`${doing} was cancelled or timed out.`);
  if (error?.name === "InvalidStateError") return new UserFacingError("This device already has a passkey for your account here.");
  return new UserFacingError(`${doing} failed: ${error?.message ?? error}`);
}

/**
 * Creates a passkey from the server's creation options, asking for PRF with `prfInput` (`labels.prf`).
 * Returns { credential (JSON for the server), credentialId, prfEnabled, prfOutput (may be null) }.
 */
export async function create(options, prfInput) {
  if (!window.PublicKeyCredential) throw new UserFacingError("This browser doesn't support passkeys.");
  const publicKey = {
    ...options,
    challenge: b64urlDecode(options.challenge),
    user: { ...options.user, id: b64urlDecode(options.user.id) },
    excludeCredentials: descriptors(options.excludeCredentials),
    extensions: { ...options.extensions, prf: { eval: { first: te.encode(prfInput) } } },
  };
  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey });
  } catch (error) {
    throw explain(error, "Creating the passkey");
  }
  const prf = credential.getClientExtensionResults()?.prf;
  const prfOutput = prfResult(credential);
  return { credential: credentialJSON(credential, "create"), credentialId: credential.id, prfEnabled: prf?.enabled === true || prfOutput !== null, prfOutput };
}

/**
 * Signs in with a passkey, evaluating PRF with `prfInput`. `allowCredentialId` limits the prompt to one passkey.
 * Returns { credential (JSON for the server), credentialId, prfOutput (null without PRF support) }.
 */
export async function get(options, prfInput, allowCredentialId = null) {
  if (!window.PublicKeyCredential) throw new UserFacingError("This browser doesn't support passkeys.");
  const allow = allowCredentialId ? [{ type: "public-key", id: allowCredentialId }] : options.allowCredentials;
  const publicKey = {
    ...options,
    challenge: b64urlDecode(options.challenge),
    allowCredentials: descriptors(allow),
    extensions: { ...options.extensions, prf: { eval: { first: te.encode(prfInput) } } },
  };
  let credential;
  try {
    credential = await navigator.credentials.get({ publicKey });
  } catch (error) {
    throw explain(error, "Using the passkey");
  }
  return { credential: credentialJSON(credential, "get"), credentialId: credential.id, prfOutput: prfResult(credential) };
}
