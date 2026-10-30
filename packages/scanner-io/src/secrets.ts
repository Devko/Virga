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
 * The shortest run of a secret that a kept field must not hold: six
 * consecutive characters, the same measure the masking tests use for a leak.
 */
export const SECRET_PIECE = 6;

/** A body shorter than a piece is searched whole, down to this length. */
export const SHORTEST_SEARCHED = 4;

/**
 * PEM armor (`-----BEGIN RSA PRIVATE KEY-----`), which gitleaks keeps in the
 * secret of a private key. It names the kind of key and is no secret; left
 * in, a key in `PRIVATE_KEY.pem` would reject its own report.
 */
const PEM_ARMOR = /-----(?:BEGIN|END)[ A-Z0-9_-]{0,100}-----/g;

/**
 * The part of a secret that must not show up anywhere else: the secret
 * without its known prefix and without PEM armor. A line feed takes the
 * armor's place, so no piece spans it (kept fields have no controls). Null
 * for gitleaks' `--redact` placeholder and for a body under four
 * characters, which would match ordinary paths.
 */
export function secretBody(secret: string, prefix: SecretPrefix | null): string | null {
  if (secret === "REDACTED") return null;
  const body = (prefix ? secret.slice(prefix.length) : secret).replace(PEM_ARMOR, "\n");
  return body.length >= SHORTEST_SEARCHED ? body : null;
}

const HASH_BASE = 0x01000193;
/** `HASH_BASE` to the power `SECRET_PIECE - 1`, modulo 2^32. */
const HASH_HIGH = Array.from({ length: SECRET_PIECE - 1 }).reduce<number>(
  (power) => Math.imul(power, HASH_BASE),
  1,
);

/**
 * Calls `visit` with a rolling hash of each piece of `text` and where the
 * piece starts, until `visit` returns true. No string is made per piece.
 */
function somePiece(text: string, visit: (hash: number, at: number) => boolean): boolean {
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    if (i >= SECRET_PIECE) {
      hash = (hash - Math.imul(text.charCodeAt(i - SECRET_PIECE), HASH_HIGH)) | 0;
    }
    hash = (Math.imul(hash, HASH_BASE) + text.charCodeAt(i)) | 0;
    if (i >= SECRET_PIECE - 1 && visit(hash, i + 1 - SECRET_PIECE)) return true;
  }
  return false;
}

/**
 * True when `kept` holds a piece of `body`: `SECRET_PIECE` consecutive
 * characters of it, or all of it when the body is shorter than a piece.
 * Linear in both lengths: the hashes of the shorter text's pieces find
 * candidates in the longer one, and a candidate counts only if the shorter
 * text has the same piece. Nothing here outlives the call.
 */
export function holdsSecretPiece(kept: string, body: string): boolean {
  if (body.length < SECRET_PIECE) return kept.includes(body);
  if (kept.length < SECRET_PIECE) return false;
  const [short, long] = kept.length <= body.length ? [kept, body] : [body, kept];
  const hashes = new Set<number>();
  somePiece(short, (hash) => {
    hashes.add(hash);
    return false;
  });
  let pieces: Set<string> | null = null;
  return somePiece(long, (hash, at) => {
    if (!hashes.has(hash)) return false;
    if (pieces === null) {
      pieces = new Set();
      for (let i = 0; i + SECRET_PIECE <= short.length; i++) {
        pieces.add(short.slice(i, i + SECRET_PIECE));
      }
    }
    return pieces.has(long.slice(at, at + SECRET_PIECE));
  });
}
