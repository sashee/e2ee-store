// Setup links (SPEC §6.2): `<origin>/#setup=<token>`.

/** The setup token in a URL fragment, or null. */
export function parseSetupFragment(hash) {
  const token = new URLSearchParams(hash.replace(/^#/, "")).get("setup");
  return token ? token : null;
}

export const setupFragment = (token) => `#setup=${encodeURIComponent(token)}`;

/** A pasted setup link (or just its fragment) or a bare token; null if it's neither. */
export function parseSetupInput(text) {
  const trimmed = text.trim();
  if (trimmed.includes("#")) return parseSetupFragment(trimmed.slice(trimmed.indexOf("#")));
  if (trimmed.startsWith("setup=")) return parseSetupFragment(trimmed);
  return /^[A-Za-z0-9_-]{43}$/.test(trimmed) ? trimmed : null;
}
