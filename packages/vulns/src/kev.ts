import { asObject, Invalid, invalid, own, parseObject, readArray, readString } from "./json.ts";

/**
 * Limits for the CISA Known Exploited Vulnerabilities catalog
 * (https://www.cisa.gov/known-exploited-vulnerabilities-catalog). The
 * catalog has a few thousand entries at most; the limits leave room for
 * growth, and a catalog over them is rejected, never cut.
 */
export const KEV_LIMITS = {
  catalogBytes: 32 * 1024 * 1024,
  entries: 100_000,
  versionLength: 64,
  dateLength: 64,
} as const;

/** `cveID` as the catalog schema defines it. */
const CVE_ID = /^CVE-[0-9]{4}-[0-9]{4,19}$/;

export interface KevCatalog {
  /** `catalogVersion`, for provenance. */
  version: string;
  /** `dateReleased`, for provenance and staleness checks. */
  released: string;
  cves: ReadonlySet<string>;
}

export type KevResult =
  | { status: "accepted"; catalog: KevCatalog }
  | { status: "rejected"; reason: string };

/**
 * Reads the KEV catalog JSON strictly: `catalogVersion`, `dateReleased`,
 * `count` and every `cveID`; other fields are not read. `count` must equal
 * the number of entries, which catches a cut catalog. Any violation rejects
 * the whole catalog.
 */
export function readKevCatalog(text: string): KevResult {
  const parsed = parseObject(text, KEV_LIMITS.catalogBytes);
  if (!parsed.ok) return { status: "rejected", reason: parsed.reason };
  const catalog = parsed.value;
  try {
    const version = readString(
      catalog,
      "catalogVersion",
      "catalogVersion",
      KEV_LIMITS.versionLength,
      true,
    ) as string;
    const released = readString(
      catalog,
      "dateReleased",
      "dateReleased",
      KEV_LIMITS.dateLength,
      true,
    ) as string;
    const count = own(catalog, "count");
    if (count === undefined || count === null) invalid("count", "missing");
    if (!Number.isSafeInteger(count)) invalid("count", "not an integer");
    const list = readArray(catalog, "vulnerabilities", "vulnerabilities", KEV_LIMITS.entries);
    if (list === null) return invalid("vulnerabilities", "missing");
    if (count !== list.length) invalid("count", `${count} but ${list.length} vulnerabilities`);
    const cves = new Set<string>();
    for (const [i, item] of list.entries()) {
      const path = `vulnerabilities[${i}]`;
      const cve = readString(asObject(item, path), "cveID", `${path}.cveID`, 64, true) as string;
      if (!CVE_ID.test(cve)) invalid(`${path}.cveID`, "invalid");
      cves.add(cve);
    }
    return { status: "accepted", catalog: { version, released, cves } };
  } catch (error) {
    if (error instanceof Invalid) return { status: "rejected", reason: error.message };
    throw error;
  }
}

/** Whether the advisory ID or one of its aliases is in the catalog. */
export function isKnownExploited(
  catalog: KevCatalog,
  id: string,
  aliases: readonly string[],
): boolean {
  return catalog.cves.has(id) || aliases.some((alias) => catalog.cves.has(alias));
}
