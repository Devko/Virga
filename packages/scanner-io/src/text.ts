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
 * True when `text` has no C0 or C1 control character, no lone surrogate, no
 * bidi control (Trojan Source) and no line or paragraph separator.
 */
export function isCleanText(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) return false;
    if (c === 0x061c || c === 0x200e || c === 0x200f) return false;
    if ((c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069)) return false;
    if (c === 0x2028 || c === 0x2029) return false;
    if (c >= 0xdc00 && c <= 0xdfff) return false;
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i++;
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
