/**
 * Limits for one scanner report. A report that exceeds any of them is
 * rejected as a whole. The defaults are first estimates; S-07 and the test
 * range will show real report sizes.
 */
export interface Limits {
  /** Size of the report in UTF-8 bytes. */
  maxBytes: number;
  /** Nesting of arrays and objects; a top-level object is depth 1. */
  maxDepth: number;
  /** JSON values in the whole document, containers included. */
  maxValues: number;
  /** Items in one array. */
  maxArrayItems: number;
  /** Members of one object. */
  maxObjectKeys: number;
  /** Length of one string or key, in UTF-16 code units. */
  maxStringLength: number;
  /** Distinct packages in the normalized result. */
  maxPackages: number;
  /** Distinct vulnerability matches in the normalized result. */
  maxVulnerabilities: number;
  /** Distinct secret findings in the normalized result. */
  maxSecrets: number;
}

export const DEFAULT_LIMITS: Readonly<Limits> = Object.freeze({
  // A large image with every package listed stays below a few MiB; 16 MiB
  // of text plus the parsed tree still fits the 128 MB of a Worker.
  maxBytes: 16 * 1024 * 1024,
  // osv-scanner output nests 13 levels down to `affected[].ranges[].events[]`;
  // free-form members such as `database_specific` get the rest.
  maxDepth: 32,
  maxValues: 500_000,
  // OSV `affected[].versions` can list thousands of versions.
  maxArrayItems: 100_000,
  maxObjectKeys: 1_000,
  // OSV `details` and Trivy `Description` are prose, rarely above 50 KB.
  maxStringLength: 256 * 1024,
  maxPackages: 50_000,
  maxVulnerabilities: 50_000,
  maxSecrets: 10_000,
});

/** The parser recurses once per level; this bound keeps it far from the stack limit. */
const DEPTH_CEILING = 256;

/** Defaults with overrides applied. Overrides must be positive integers. */
export function resolveLimits(overrides: Partial<Limits> = {}): Limits {
  const limits: Limits = { ...DEFAULT_LIMITS };
  for (const key of Object.keys(DEFAULT_LIMITS) as (keyof Limits)[]) {
    const value = overrides[key];
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new RangeError(`limit ${key} must be a positive integer`);
    }
    limits[key] = value;
  }
  if (limits.maxDepth > DEPTH_CEILING) {
    throw new RangeError(`limit maxDepth must not exceed ${DEPTH_CEILING}`);
  }
  return limits;
}
