/**
 * Detects values of plain-text variables that look like secrets. Only the
 * verdict leaves this module; the value itself is never stored or logged.
 */

export const SECRET_PATTERNS = [
  "cfat_",
  "cfut_",
  "cfk_",
  "aws_access_key",
  "private_key",
  "high_entropy",
] as const;

export type SecretPattern = (typeof SECRET_PATTERNS)[number];

export interface SecretVerdict {
  looks_secret: boolean;
  secret_pattern: SecretPattern | null;
}

// Cloudflare's scannable formats are a prefix, 40 characters and a checksum
// (developers.cloudflare.com/fundamentals/api/get-started/token-formats/).
const KNOWN: readonly [SecretPattern, RegExp][] = [
  ["cfat_", /(?<![A-Za-z0-9])cfat_[A-Za-z0-9_-]{40,}/],
  ["cfut_", /(?<![A-Za-z0-9])cfut_[A-Za-z0-9_-]{40,}/],
  ["cfk_", /(?<![A-Za-z0-9])cfk_[A-Za-z0-9_-]{40,}/],
  ["aws_access_key", /(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}(?![A-Z0-9])/],
  ["private_key", /-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/],
];

const MIN_LENGTH = 32;
const MAX_INPUT = 16 * 1024;
const CANDIDATE = /[A-Za-z0-9+/=_-]{32,}/g;
const HEX = /^[0-9a-fA-F]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Hex carries at most 4 bits per character, other alphabets up to 6.
const HEX_MIN_BITS = 3;
const MIXED_MIN_BITS = 4;

/** Shannon entropy in bits per character. */
export function entropy(text: string): number {
  if (text.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

function looksRandom(token: string): boolean {
  if (token.length < MIN_LENGTH || UUID.test(token)) return false;
  if (HEX.test(token)) {
    // 32 hex characters is the shape of Cloudflare account, zone and namespace IDs.
    return token.length !== 32 && entropy(token) >= HEX_MIN_BITS;
  }
  if (!/[0-9]/.test(token) || !/[A-Za-z]/.test(token)) return false;
  return entropy(token) >= MIXED_MIN_BITS;
}

export function detectSecret(value: string): SecretVerdict {
  const text = value.length > MAX_INPUT ? value.slice(0, MAX_INPUT) : value;
  for (const [pattern, re] of KNOWN) {
    if (re.test(text)) return { looks_secret: true, secret_pattern: pattern };
  }
  for (const match of text.matchAll(CANDIDATE)) {
    if (looksRandom(match[0])) return { looks_secret: true, secret_pattern: "high_entropy" };
  }
  return { looks_secret: false, secret_pattern: null };
}

const rank = (verdict: SecretVerdict): number =>
  verdict.secret_pattern === null
    ? SECRET_PATTERNS.length
    : SECRET_PATTERNS.indexOf(verdict.secret_pattern);

/**
 * The verdict for a JSON value, such as a `json` binding. Every string in it,
 * object keys included, is tested on its own, and the strongest pattern wins
 * whatever the order. The walk keeps its own stack, so deep nesting cannot
 * overflow the call stack.
 */
export function detectSecretIn(value: unknown): SecretVerdict {
  let best: SecretVerdict = { looks_secret: false, secret_pattern: null };
  const test = (text: string) => {
    const verdict = detectSecret(text);
    if (rank(verdict) < rank(best)) best = verdict;
  };
  const pending: unknown[] = [value];
  while (pending.length > 0) {
    const item = pending.pop();
    if (typeof item === "string") {
      test(item);
    } else if (Array.isArray(item)) {
      for (const v of item) pending.push(v);
    } else if (item !== null && typeof item === "object") {
      for (const [key, v] of Object.entries(item)) {
        test(key);
        pending.push(v);
      }
    }
  }
  return best;
}

/** A verdict, with nulls when there was no value to inspect: unknown, not clean. */
export type ValueVerdict = {
  looks_secret: boolean | null;
  secret_pattern: SecretPattern | null;
};

export const inspectValue = (value: unknown): ValueVerdict =>
  value === undefined ? { looks_secret: null, secret_pattern: null } : detectSecretIn(value);
