/**
 * SemVer 2.0.0 (https://semver.org/spec/v2.0.0.html), strict: no leading `v`
 * or `=`, no npm ranges, no loose forms. Numeric parts stay strings, so
 * numbers above 2^53 compare exactly.
 */
export interface SemVer {
  major: string;
  minor: string;
  patch: string;
  prerelease: string[];
  /** Kept for display; precedence ignores it. */
  build: string[];
  /** The text the version was parsed from. */
  text: string;
}

/** Longest version text accepted. */
export const SEMVER_MAX_LENGTH = 256;

// The regular expression suggested by semver.org, with named groups.
const SEMVER =
  /^(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)(?:-(?<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?<build>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

const NUMERIC = /^\d+$/;

/** Parses a SemVer 2.0.0 version, or returns null. */
export function parseSemver(text: string): SemVer | null {
  if (typeof text !== "string" || text.length > SEMVER_MAX_LENGTH) return null;
  const groups = SEMVER.exec(text)?.groups;
  if (!groups) return null;
  return {
    major: groups.major as string,
    minor: groups.minor as string,
    patch: groups.patch as string,
    prerelease: groups.prerelease ? groups.prerelease.split(".") : [],
    build: groups.build ? groups.build.split(".") : [],
    text,
  };
}

/** Compares numbers written without leading zeros. */
function compareNumeric(a: string, b: string): -1 | 0 | 1 {
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  return a === b ? 0 : a < b ? -1 : 1;
}

function compareIdentifier(a: string, b: string): -1 | 0 | 1 {
  const aNumeric = NUMERIC.test(a);
  const bNumeric = NUMERIC.test(b);
  if (aNumeric && bNumeric) return compareNumeric(a, b);
  if (aNumeric) return -1;
  if (bNumeric) return 1;
  return a === b ? 0 : a < b ? -1 : 1;
}

/** SemVer precedence (section 11). Build metadata does not count. */
export function compareSemver(a: SemVer, b: SemVer): -1 | 0 | 1 {
  const core =
    compareNumeric(a.major, b.major) ||
    compareNumeric(a.minor, b.minor) ||
    compareNumeric(a.patch, b.patch);
  if (core !== 0) return core;
  const ap = a.prerelease;
  const bp = b.prerelease;
  if (ap.length === 0 || bp.length === 0) {
    if (ap.length === bp.length) return 0;
    return ap.length === 0 ? 1 : -1;
  }
  for (let i = 0; i < Math.min(ap.length, bp.length); i++) {
    const order = compareIdentifier(ap[i] as string, bp[i] as string);
    if (order !== 0) return order;
  }
  return ap.length === bp.length ? 0 : ap.length < bp.length ? -1 : 1;
}
