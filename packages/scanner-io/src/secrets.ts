/**
 * Masking at the boundary. A reader looks at a raw secret only to find a
 * known prefix, then drops it. What leaves is one of the prefixes below,
 * which is Virga's own constant and not a slice of the input, and a fixed
 * mask. The mask does not depend on the secret, not even on its length.
 * No hash is kept: a hash of a weak or short secret can be guessed.
 */

/** Cloudflare token prefixes; a match links to the token inventory by kind. */
export const SECRET_PREFIXES = ["cfat_", "cfut_", "cfk_"] as const;
export type SecretPrefix = (typeof SECRET_PREFIXES)[number];

export const MASK = "********";

export interface MaskedSecret {
  prefix: SecretPrefix | null;
  masked: string;
}

export function maskSecret(secret: string): MaskedSecret {
  const prefix = SECRET_PREFIXES.find((p) => secret.length > p.length && secret.startsWith(p));
  return prefix ? { prefix, masked: `${prefix}${MASK}` } : { prefix: null, masked: MASK };
}

/**
 * The part of a secret that must not show up anywhere else: the secret
 * without its known prefix. Null when it is too short to search for safely.
 */
export function secretBody(secret: string, prefix: SecretPrefix | null): string | null {
  // gitleaks writes this placeholder with `--redact`.
  if (secret === "REDACTED") return null;
  const body = prefix ? secret.slice(prefix.length) : secret;
  return body.length >= 8 ? body : null;
}
