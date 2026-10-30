import type { VulnRecord } from "@virga/graph";
import { isKnownExploited, type KevCatalog } from "./kev.ts";
import { matchAdvisory } from "./match.ts";
import type { AdvisoryFeed, OsvAdvisory } from "./osv.ts";
import { npmNameKey, parseNpmPurl } from "./purl.ts";
import { isMaliciousPackageAdvisory, type SeverityRank, severityRank } from "./severity.ts";

export interface RematchInput {
  /** IDs of the live package nodes (`package:<purl>`). */
  packages: readonly string[];
  /**
   * Whether `packages` lists every live package node, for example because
   * `packages` coverage is complete. Only then is a row whose package is not
   * listed fixed; otherwise it stays, and the result is not complete.
   */
  packagesComplete: boolean;
  feed: AdvisoryFeed;
  /**
   * Whether `feed` was read from the whole advisory mirror, not a part of it
   * after a failed sync. Only then is a row whose advisory is not in the
   * feed fixed; otherwise it stays, and the result is not complete.
   */
  feedComplete: boolean;
  /** The KEV catalog; null when it could not be read, which makes the result incomplete. */
  kev: KevCatalog | null;
  /** The current `vulns` rows, all sources. */
  existing: readonly VulnRecord[];
  /** Epoch milliseconds; `first_seen` of new rows. */
  at: number;
  /** The `source` of the rows this rematch owns. Default `osv`. */
  source?: string;
}

/** An advisory that names a package, where the match cannot be decided or ranked. */
export interface UnknownMatch {
  packageId: string;
  vulnId: string;
  reason: "version not decidable" | "severity unknown";
}

export interface UnparsedPackage {
  packageId: string;
  reason: string;
}

export interface RematchResult {
  source: string;
  /** Rows to write: new, changed, reopened or fixed. Unchanged rows are left out. */
  rows: VulnRecord[];
  /**
   * True when every package parsed, no match is unknown, no record was
   * rejected, KEV was read and both the package set and the feed are complete.
   */
  complete: boolean;
  /** Why the result is not complete, as counts; null when complete. */
  detail: string | null;
  unknown: UnknownMatch[];
  unparsed: UnparsedPackage[];
  counts: {
    /** Decided matches, open or ignored. */
    matched: number;
    opened: number;
    reopened: number;
    updated: number;
    fixed: number;
    /** Rows of this source left as they are. */
    unchanged: number;
  };
}

const PACKAGE_PREFIX = "package:";

/** Rows by package ID, then vuln ID. Nested maps: IDs are data, never joined into one key. */
class Keyed<T> {
  private readonly map = new Map<string, Map<string, T>>();
  get(packageId: string, vulnId: string): T | undefined {
    return this.map.get(packageId)?.get(vulnId);
  }
  set(packageId: string, vulnId: string, value: T): void {
    let inner = this.map.get(packageId);
    if (!inner) {
      inner = new Map();
      this.map.set(packageId, inner);
    }
    inner.set(vulnId, value);
  }
  has(packageId: string, vulnId: string): boolean {
    return this.map.get(packageId)?.has(vulnId) ?? false;
  }
}

const byKey = (
  a: { packageId: string; vulnId: string },
  b: { packageId: string; vulnId: string },
) =>
  a.packageId < b.packageId
    ? -1
    : a.packageId > b.packageId
      ? 1
      : a.vulnId < b.vulnId
        ? -1
        : a.vulnId > b.vulnId
          ? 1
          : 0;

const sameRow = (a: VulnRecord, b: VulnRecord): boolean =>
  a.severityRank === b.severityRank &&
  a.kev === b.kev &&
  a.fixedIn === b.fixedIn &&
  a.status === b.status &&
  a.source === b.source &&
  a.firstSeen === b.firstSeen &&
  JSON.stringify(a.aliases) === JSON.stringify(b.aliases);

/**
 * The rank over the entries that matched: critical decides, otherwise one
 * unknown makes it unknown. A `MAL-` record is critical (decision 0008).
 */
function rankOf(
  advisory: OsvAdvisory,
  entries: ReturnType<typeof matchAdvisory>["entries"],
): SeverityRank | null {
  if (isMaliciousPackageAdvisory(advisory.id)) return 4;
  let best: SeverityRank = 0;
  let unknown = false;
  for (const entry of entries) {
    const rank = severityRank(entry.severity ?? advisory.severity, advisory.databaseSeverity);
    if (rank === null) unknown = true;
    else if (rank > best) best = rank;
  }
  return unknown && best < 4 ? null : best;
}

/**
 * Matches package nodes against advisories and returns the `vulns` rows to
 * write. Pure: it reads only its input.
 *
 * - A decided match with a known severity is a row: new rows open with
 *   `first_seen = at`; an existing row keeps `first_seen`, a fixed one
 *   reopens, an ignored one stays ignored.
 * - A match on a `MAL-` record (malware) ranks critical, whatever its
 *   severity fields hold (decision 0008).
 * - A match that cannot be decided (a range or version that does not parse)
 *   or ranked (no CVSS v3 vector and no database severity) is reported in
 *   `unknown` and not written; an existing row for it stays as it is.
 * - Existing rows of this source that no longer match become `fixed`: the
 *   version is outside the advisory, the advisory is withdrawn or no longer
 *   in the feed, or the package is gone. Rows stay as they are where that
 *   cannot be known: the package does not parse, the advisory's record was
 *   rejected, the package is missing from a package set that is not
 *   complete, or the advisory is missing from a feed that is not complete
 *   or had a record rejected without a readable ID. Ignored rows stay
 *   ignored.
 * - Rows of other sources are not touched, except one with the key of a
 *   match, which this source takes over with its `first_seen` and an ignored
 *   status kept.
 */
export function rematch(input: RematchInput): RematchResult {
  const { feed, kev, at } = input;
  const source = input.source ?? "osv";

  // Advisories by npm name key: names match without regard to ASCII case (R9-05).
  const byName = new Map<string, OsvAdvisory[]>();
  const wildcard: OsvAdvisory[] = [];
  for (const advisory of feed.advisories) {
    for (const name of new Set(advisory.affected.map((e) => npmNameKey(e.name)))) {
      if (name === "*") wildcard.push(advisory);
      else {
        const list = byName.get(name);
        if (list) list.push(advisory);
        else byName.set(name, [advisory]);
      }
    }
  }
  const rejectedIds = new Set(feed.rejected.flatMap((r) => (r.id === null ? [] : [r.id])));
  // Whether an advisory missing from the feed may still exist.
  const missingMayExist = !input.feedComplete || feed.rejected.some((r) => r.id === null);
  const readIds = new Set([
    ...feed.advisories.map((a) => a.id),
    ...feed.withdrawn,
    ...feed.skipped,
  ]);

  // The table's key is (package_id, vuln_id), so a key has one row, of any source.
  const existing = new Keyed<VulnRecord>();
  for (const row of input.existing) existing.set(row.packageId, row.vulnId, row);

  const result: RematchResult = {
    source,
    rows: [],
    complete: false,
    detail: null,
    unknown: [],
    unparsed: [],
    counts: { matched: 0, opened: 0, reopened: 0, updated: 0, fixed: 0, unchanged: 0 },
  };
  const { counts } = result;
  const decided = new Keyed<true>();
  const undecided = new Keyed<true>();
  const listed = new Set(input.packages);
  const unparsed = new Set<string>();

  for (const packageId of listed) {
    if (!packageId.startsWith(PACKAGE_PREFIX)) {
      result.unparsed.push({ packageId, reason: "not a package node ID" });
      unparsed.add(packageId);
      continue;
    }
    const purl = parseNpmPurl(packageId.slice(PACKAGE_PREFIX.length));
    if (!purl.ok) {
      result.unparsed.push({ packageId, reason: purl.reason });
      unparsed.add(packageId);
      continue;
    }
    const candidates = new Set([...(byName.get(npmNameKey(purl.name)) ?? []), ...wildcard]);
    for (const advisory of candidates) {
      const match = matchAdvisory(advisory, purl.name, purl.version);
      if (match.decision === "not_affected") continue;
      const vulnId = advisory.id;
      if (match.decision === "unknown") {
        result.unknown.push({ packageId, vulnId, reason: "version not decidable" });
        undecided.set(packageId, vulnId, true);
        continue;
      }
      const rank = rankOf(advisory, match.entries);
      if (rank === null) {
        result.unknown.push({ packageId, vulnId, reason: "severity unknown" });
        undecided.set(packageId, vulnId, true);
        continue;
      }
      const old = existing.get(packageId, vulnId);
      const row: VulnRecord = {
        packageId,
        vulnId,
        aliases: [...advisory.aliases],
        severityRank: rank,
        kev: kev ? isKnownExploited(kev, vulnId, advisory.aliases) : (old?.kev ?? false),
        fixedIn: match.fixedIn,
        status: old?.status === "ignored" ? "ignored" : "open",
        source,
        firstSeen: old?.firstSeen ?? at,
      };
      decided.set(packageId, vulnId, true);
      counts.matched++;
      if (!old) counts.opened++;
      else if (sameRow(old, row)) {
        counts.unchanged++;
        continue;
      } else if (old.status === "fixed") counts.reopened++;
      else counts.updated++;
      result.rows.push(row);
    }
  }

  for (const row of input.existing) {
    const { packageId, vulnId } = row;
    if (row.source !== source || decided.has(packageId, vulnId)) continue;
    // A gone package fixes its rows; otherwise the advisory must be known to no longer match.
    const keep =
      row.status !== "open" ||
      undecided.has(packageId, vulnId) ||
      unparsed.has(packageId) ||
      (listed.has(packageId)
        ? rejectedIds.has(vulnId) || (!readIds.has(vulnId) && missingMayExist)
        : !input.packagesComplete);
    if (keep) counts.unchanged++;
    else {
      result.rows.push({ ...row, status: "fixed" });
      counts.fixed++;
    }
  }

  result.rows.sort(byKey);
  result.unknown.sort(byKey);
  result.unparsed.sort((a, b) =>
    a.packageId < b.packageId ? -1 : a.packageId > b.packageId ? 1 : 0,
  );

  const reasons: string[] = [];
  if (result.unknown.length > 0) reasons.push(`unknown matches: ${result.unknown.length}`);
  if (result.unparsed.length > 0) reasons.push(`unparsed packages: ${result.unparsed.length}`);
  if (feed.rejected.length > 0) reasons.push(`rejected advisories: ${feed.rejected.length}`);
  if (kev === null) reasons.push("no KEV catalog");
  if (!input.packagesComplete) reasons.push("package set not complete");
  if (!input.feedComplete) reasons.push("advisory feed not complete");
  result.complete = reasons.length === 0;
  result.detail = result.complete ? null : reasons.join("; ");
  return result;
}
