import { applyVulnRematch, listVulns, type SqlRunner, VULN_LIMITS } from "@virga/graph";
import { type AdvisoryFeed, type KevCatalog, rematch } from "@virga/vulns";
import type { VulnCounters } from "../scan/types.ts";

/** What an advisory source returns for one rematch. */
export type AdvisoryRead =
  | {
      configured: true;
      /** The advisories that can name the packages, read with `readOsvFeed`. */
      feed: AdvisoryFeed;
      /**
       * Whether `feed` holds every advisory of the mirror that can name the
       * packages: false after a failed, partial or stale sync (decision 0009).
       * Only when it is true are rows whose advisory is missing fixed.
       */
      complete: boolean;
      /** The KEV catalog, null when it could not be read. */
      kev: KevCatalog | null;
    }
  | {
      configured: false;
      /** Why there is no feed, in fixed words; it leads the `vulns` coverage detail. */
      reason: string;
    };

/**
 * Where the scan's vulns step reads advisories. Everything it returns is
 * untrusted and comes through the strict readers of `@virga/vulns`. The
 * advisory mirror does not exist yet (decision 0009 waits for a spike), so
 * the default source reports that no feed is configured. A source that
 * throws ends the step `error`, without retries, like the exposure step.
 */
export interface AdvisorySource {
  /** Gets the live package node IDs (`package:<purl>`), which come from the scanned account. */
  read(packages: readonly string[]): AdvisoryRead | Promise<AdvisoryRead>;
}

export const NO_ADVISORY_FEED: AdvisorySource = {
  read: () => ({ configured: false, reason: "no advisory feed configured" }),
};

const EMPTY_FEED: AdvisoryFeed = {
  advisories: [],
  withdrawn: [],
  skipped: [],
  skippedEntries: 0,
  rejected: [],
};

/** The reason of a source without a feed, bounded. */
const MAX_REASON = 200;

/** Counters of a vulns step that ended `error`: nothing matched or written. */
export const noVulns = (packages: number): VulnCounters => ({
  status: "error",
  packages,
  matched: 0,
  opened: 0,
  reopened: 0,
  updated: 0,
  fixed: 0,
  unchanged: 0,
  unknown: 0,
  unparsed: 0,
  written: 0,
});

/** The IDs of the live package nodes, in ID order. */
export function livePackages(db: SqlRunner): string[] {
  return db
    .query<{ id: string }>(
      "SELECT id FROM nodes WHERE type = 'package' AND deleted_at IS NULL ORDER BY id",
    )
    .map((row) => row.id);
}

/**
 * Matches `packages` against what the source read and writes the result
 * with applyVulnRematch, which records the scan's `vulns` coverage:
 * `complete` only when every package parsed, every match was decided and
 * ranked, the KEV catalog was read, the feed is complete and so is the
 * package set (`packages` coverage `complete` in this scan). Without a feed
 * the rematch still runs on an empty feed that is not complete: it fixes
 * only rows of packages that are gone from a complete package set, and the
 * detail starts with the source's reason.
 *
 * Returns counts only. The rematch's lists of unknown matches and unparsed
 * packages hold IDs from the scanned account; its detail holds counts and
 * fixed words.
 */
export function matchVulns(
  db: SqlRunner,
  scanId: string,
  packages: readonly string[],
  read: AdvisoryRead,
  at: number,
): VulnCounters {
  const packagesComplete =
    db.query(
      `SELECT 1 FROM coverage
       WHERE scan_id = ? AND resource_class = 'packages' AND status = 'complete'`,
      scanId,
    ).length > 0;
  const result = rematch({
    packages,
    packagesComplete,
    feed: read.configured ? read.feed : EMPTY_FEED,
    feedComplete: read.configured && read.complete === true,
    kev: read.configured ? read.kev : null,
    existing: listVulns(db),
    at,
  });
  const reasons = read.configured ? [] : [String(read.reason).slice(0, MAX_REASON)];
  if (result.detail) reasons.push(result.detail);
  const detail = reasons.length > 0 ? reasons.join("; ").slice(0, VULN_LIMITS.detail) : null;
  const applied = applyVulnRematch(db, scanId, {
    source: result.source,
    rows: result.rows,
    complete: result.complete && read.configured,
    detail,
  });
  const counters: VulnCounters = {
    status: applied.complete ? "complete" : "partial",
    packages: packages.length,
    ...result.counts,
    unknown: result.unknown.length,
    unparsed: result.unparsed.length,
    written: applied.written,
  };
  return detail && !applied.complete ? { ...counters, detail } : counters;
}
