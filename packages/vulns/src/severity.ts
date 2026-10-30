import { cvss3BaseScore, rankOfScore } from "./cvss.ts";
import type { OsvSeverity } from "./osv.ts";

/** 0 none, 1 low, 2 medium, 3 high, 4 critical, as in the `vulns` table. */
export type SeverityRank = 0 | 1 | 2 | 3 | 4;

/** GitHub advisory severities in `database_specific.severity`. */
const DATABASE_RANKS: ReadonlyMap<string, SeverityRank> = new Map([
  ["LOW", 1],
  ["MODERATE", 2],
  ["HIGH", 3],
  ["CRITICAL", 4],
]);

/**
 * The severity rank of an advisory, or null when it cannot be determined.
 *
 * - CVSS v3 vectors decide when there is at least one: the highest base
 *   score. A vector that does not parse makes the rank unknown, unless a
 *   valid one is already critical.
 * - Without a v3 vector, `database_specific.severity` decides (`LOW`,
 *   `MODERATE`, `HIGH`, `CRITICAL`); any other value is unknown.
 * - Otherwise, for example with only a CVSS v4 or v2 vector, the rank is
 *   unknown. Null is never 0: a rank of 0 would read as harmless.
 */
export function severityRank(
  severity: readonly OsvSeverity[],
  databaseSeverity: string | null,
): SeverityRank | null {
  const vectors = severity.filter((s) => s.type === "CVSS_V3");
  if (vectors.length > 0) {
    let best: SeverityRank = 0;
    let broken = false;
    for (const { score } of vectors) {
      const value = cvss3BaseScore(score);
      if (value === null) broken = true;
      else best = Math.max(best, rankOfScore(value)) as SeverityRank;
    }
    return broken && best < 4 ? null : best;
  }
  return databaseSeverity === null ? null : (DATABASE_RANKS.get(databaseSeverity) ?? null);
}
