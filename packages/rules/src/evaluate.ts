import type { SqlRunner } from "@virga/graph";
import type { CompiledRule } from "./types.ts";

export interface RuleRunSummary {
  ruleId: string;
  status: "evaluated" | "not_evaluated" | "error";
  hits: number;
  /** Resource classes or derived tables without complete coverage. */
  missing: string[];
  opened: number;
  resolved: number;
  error?: string;
}

/**
 * Runs rules for a scan and maintains the findings lifecycle
 * (docs/architecture/data-model.md, "Findings lifecycle"):
 *
 * - A rule whose `requires` includes a resource class without `complete`
 *   coverage in this scan is `not_evaluated` and changes no finding.
 *   Derived inputs (`exposure`, `vulns`, `packages`) count as complete once
 *   their producing step marked them complete in `coverage`.
 * - Hits upsert findings by fingerprint (open, last_seen, evidence,
 *   finding_nodes); a resolved finding that reappears is reopened.
 * - Open findings of an evaluated rule that are no longer returned are
 *   resolved.
 * - Expired suppressions return to open; suppressed findings stay
 *   suppressed while the suppression lasts unless their severity rises.
 * - One row per rule in `rule_runs`.
 */
export function evaluateRules(
  _db: SqlRunner,
  _rules: readonly CompiledRule[],
  _scanId: string,
  _at?: number,
): RuleRunSummary[] {
  throw new Error("evaluateRules: implemented by the rules work package");
}
