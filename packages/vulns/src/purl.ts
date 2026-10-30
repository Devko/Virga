import { parseSemver, type SemVer } from "./semver.ts";

/** Longest purl accepted; the graph limits native IDs to 512 characters. */
export const PURL_MAX_LENGTH = 512;

/** npm limits package names, scope included, to 214 characters. */
export const NPM_NAME_MAX_LENGTH = 214;

export type NpmPurl =
  | {
      ok: true;
      /** The npm package name, `@scope/name` for a scoped package. */
      name: string;
      version: SemVer;
      versionText: string;
    }
  | { ok: false; reason: string };

// Characters encodeURIComponent leaves alone: what npm allows in a name part.
const NAME_PART = /^[A-Za-z0-9._~!*'()-]+$/;
const TYPE = /^pkg:([A-Za-z.+-][A-Za-z0-9.+-]*)\//;

const fail = (reason: string): NpmPurl => ({ ok: false, reason });

function decode(part: string): string | null {
  try {
    return decodeURIComponent(part);
  } catch {
    return null;
  }
}

/**
 * Parses an npm purl as the graph stores it (`pkg:npm/lodash@4.17.20`,
 * `pkg:npm/%40scope/name@1.0.0`). Strict: the type must be `npm` in lower
 * case, and qualifiers or a subpath are refused, because a qualifier such as
 * `repository_url` can name another registry, where the same name is
 * another package. The `@` of a scope may be percent-encoded or not. The
 * version must be SemVer 2.0.0. The name keeps its case: npm names are case
 * sensitive, and matching is exact.
 */
export function parseNpmPurl(purl: string): NpmPurl {
  if (purl.length > PURL_MAX_LENGTH) return fail(`longer than ${PURL_MAX_LENGTH} characters`);
  const type = TYPE.exec(purl);
  if (!type) return fail("not a purl");
  if (type[1] !== "npm") return fail("unsupported purl type");
  const rest = purl.slice(type[0].length);
  if (rest.includes("?") || rest.includes("#")) return fail("qualifiers or subpath");

  const at = rest.lastIndexOf("@");
  if (at === -1) return fail("no version");
  const path = rest.slice(0, at);
  // `@scope/name` without a version: the only @ is the scope's.
  if (path === "" && rest.includes("/")) return fail("no version");

  const segments = path.split("/").map(decode);
  const version = decode(rest.slice(at + 1));
  if (version === null || segments.some((s) => s === null)) {
    return fail("invalid percent-encoding");
  }
  const parts = segments as string[];
  let name: string;
  if (parts.length === 1 && NAME_PART.test(parts[0] as string)) {
    name = parts[0] as string;
  } else if (
    parts.length === 2 &&
    (parts[0] as string).startsWith("@") &&
    NAME_PART.test((parts[0] as string).slice(1)) &&
    NAME_PART.test(parts[1] as string)
  ) {
    name = `${parts[0]}/${parts[1]}`;
  } else {
    return fail("invalid package name");
  }
  if (name.length > NPM_NAME_MAX_LENGTH) return fail("invalid package name");

  const parsed = parseSemver(version);
  if (!parsed) return fail("version is not SemVer 2.0");
  return { ok: true, name, version: parsed, versionText: version };
}
