/**
 * Checks for strings that leave a reader. Display strings (names, versions,
 * paths) may hold any text except controls; identifiers (advisory IDs, rule
 * IDs, purls) must match a narrow pattern.
 */

/** Maximum lengths of kept strings, in UTF-16 code units. */
export const FIELD_LIMITS = {
  /** Advisory IDs and aliases: CVE, GHSA, PYSEC, RHSA-2024:1234 and the like. */
  id: 128,
  ruleId: 128,
  /** The graph's limit for a native ID; a package node's native ID is its purl. */
  purl: 512,
  /** npm allows 214 characters; Go module paths and Maven coordinates run longer. */
  name: 512,
  version: 256,
  /** The graph's limit for a display name. */
  path: 1024,
  /** OSV ecosystems and Trivy result types. */
  label: 128,
  /** Short free text such as a severity label. */
  severity: 32,
  aliases: 100,
  fixedVersions: 100,
} as const;

export const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
export const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** OSV ecosystems ("npm", "Debian:12", "Red Hat:enterprise_linux:9") and Trivy types. */
export const LABEL = /^[A-Za-z0-9][A-Za-z0-9 ._:+-]*$/;

/**
 * Characters that render as nothing: Unicode's Default_Ignorable_Code_Point
 * (DerivedCoreProperties.txt), written out so that every runtime refuses the
 * same set. Zero-width spaces and joiners, the word joiner, the byte order
 * mark, fillers, variation selectors and tag characters can hide text or
 * make two different names look the same (R9 hardening). The set includes
 * the bidi controls. A test compares it with the engine's
 * `\p{Default_Ignorable_Code_Point}`.
 */
const INVISIBLE: readonly (readonly [number, number])[] = [
  [0x00ad, 0x00ad], // soft hyphen
  [0x034f, 0x034f], // combining grapheme joiner
  [0x061c, 0x061c], // Arabic letter mark
  [0x115f, 0x1160], // Hangul fillers
  [0x17b4, 0x17b5], // Khmer inherent vowels
  [0x180b, 0x180f], // Mongolian variation selectors and vowel separator
  [0x200b, 0x200f], // zero-width space, joiners, direction marks
  [0x202a, 0x202e], // bidi embeddings and overrides
  [0x2060, 0x206f], // word joiner, invisible operators, isolates, deprecated formats
  [0x3164, 0x3164], // Hangul filler
  [0xfe00, 0xfe0f], // variation selectors
  [0xfeff, 0xfeff], // zero-width no-break space, byte order mark
  [0xffa0, 0xffa0], // halfwidth Hangul filler
  [0xfff0, 0xfff8], // unassigned specials
  [0x1bca0, 0x1bca3], // shorthand format controls
  [0x1d173, 0x1d17a], // musical formatting
  [0xe0000, 0xe0fff], // tags and variation selectors supplement
];

/** True when the code point renders as nothing (Default_Ignorable_Code_Point). */
export function isInvisible(cp: number): boolean {
  if (cp < 0x00ad) return false;
  for (const [low, high] of INVISIBLE) {
    if (cp < low) return false;
    if (cp <= high) return true;
  }
  return false;
}

/**
 * True when `text` has no C0 or C1 control character, no lone surrogate, no
 * line or paragraph separator and no invisible character (`INVISIBLE`,
 * which holds the bidi controls of Trojan Source).
 */
export function isCleanText(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) return false;
    if (c === 0x2028 || c === 0x2029) return false;
    if (c >= 0xdc00 && c <= 0xdfff) return false;
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      if (isInvisible(((c - 0xd800) << 10) + (next - 0xdc00) + 0x10000)) return false;
      i++;
    } else if (isInvisible(c)) {
      return false;
    }
  }
  return true;
}

/** Cloudflare token formats: a prefix and at least 40 characters. */
const CLOUDFLARE_TOKEN = /(?:cfat|cfut|cfk)_[A-Za-z0-9_-]{40,}/;

/** True when `text` holds something shaped like a Cloudflare token. */
export const containsCloudflareToken = (text: string): boolean => CLOUDFLARE_TOKEN.test(text);

// Package URL, https://github.com/package-url/purl-spec. Only the characters
// the spec leaves unencoded, no fragment (`#` would make edge IDs ambiguous),
// a version, and qualifiers as key=value pairs.
const PURL_CHARS = /^[A-Za-z0-9.\-_~%!$&'()*+,;=:@/?]+$/;
const PURL_HEAD = /^pkg:[a-z][a-z0-9.+-]*\/(.+)$/;
const QUALIFIERS = /^[a-z][a-z0-9._-]*=[^&=?]+(?:&[a-z][a-z0-9._-]*=[^&=?]+)*$/;
const BAD_PERCENT = /%(?![0-9A-Fa-f]{2})/;

/** True when `text` is a purl with a version, in the character set Virga accepts. */
export function isPurl(text: string): boolean {
  if (text.length > FIELD_LIMITS.purl || !PURL_CHARS.test(text) || BAD_PERCENT.test(text)) {
    return false;
  }
  const rest = PURL_HEAD.exec(text)?.[1];
  if (rest === undefined) return false;
  const q = rest.indexOf("?");
  const main = q === -1 ? rest : rest.slice(0, q);
  if (q !== -1 && !QUALIFIERS.test(rest.slice(q + 1))) return false;
  const at = main.lastIndexOf("@");
  if (at <= 0 || at === main.length - 1) return false;
  const path = main.slice(0, at);
  return !path.startsWith("/") && !path.endsWith("/") && !path.includes("//");
}

/** Percent-encodes everything except unreserved characters (RFC 3986). */
function encode(part: string): string {
  let out = "";
  for (const byte of new TextEncoder().encode(part)) {
    const ch = String.fromCharCode(byte);
    out += /[A-Za-z0-9._~-]/.test(ch) ? ch : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

const NPM_NAME = /^(?:@([a-z0-9][a-z0-9._~-]*)\/)?([a-z0-9][a-z0-9._~-]*)$/;

/**
 * The purl of an npm package: name lowercased (the purl spec's rule for npm),
 * the scope as namespace with `@` encoded, name and version percent-encoded.
 * Null for a name that is no valid npm name or an empty version.
 */
export function npmPurl(name: string, version: string): string | null {
  const match = NPM_NAME.exec(name.toLowerCase());
  if (!match || version === "") return null;
  const [, scope, bare] = match;
  const path = scope ? `%40${encode(scope)}/${encode(bare ?? "")}` : encode(bare ?? "");
  const purl = `pkg:npm/${path}@${encode(version)}`;
  return isPurl(purl) ? purl : null;
}
