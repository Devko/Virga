import type { CollectorOutput } from "@virga/collectors";
import type { CoverageStatus, SweepResult } from "@virga/graph";
import type { Untrusted } from "../untrusted.ts";

export type Awaitable<T> = T | Promise<T>;

/** What a collect step wrote. Steps return counters like this, never graph rows. */
export interface ChunkCounters {
  nodes: number;
  edges: number;
  /** Rows created, changed or restored. */
  changed: number;
  signals: number;
  insights: number;
  /**
   * Set when the chunk left resources of its class out, one reason per unit
   * (decision 0005); bounded by TRUNCATED_LIMITS. Reasons can name IDs from
   * the scanned account.
   */
  truncated?: Untrusted<string>[];
}

export interface ExposureCounters {
  status: "complete" | "error";
  entries: number;
  /** Rows per decision (`public`, `access`, ..., `unknown`). */
  decisions: Record<string, number>;
  detail?: string;
}

export interface RulesCounters {
  status: "complete" | "error";
  rules: number;
  evaluated: number;
  notEvaluated: number;
  errors: number;
  /** Decided rows of all rules. */
  hits: number;
  /** Rows the rules could not decide, for example because exposure is `unknown`. */
  undecided: number;
  opened: number;
  resolved: number;
  /**
   * IDs of the rules whose run ended `error`, in run order, at most
   * RULE_ERRORS_LISTED (policy.ts); set only when `errors` is above 0
   * (TM-11). Rule IDs come from the compiled rules, not the scanned account.
   */
  errored?: string[];
  detail?: string;
}

/**
 * What the vulns step wrote: counts only, since the rematch's lists of
 * unknown matches and unparsed packages hold IDs from the scanned account.
 */
export interface VulnCounters {
  /** The `vulns` coverage the step recorded. */
  status: "complete" | "partial" | "error";
  /** Live package nodes matched. */
  packages: number;
  /** Decided matches, open or ignored. */
  matched: number;
  opened: number;
  reopened: number;
  updated: number;
  fixed: number;
  /** Rows left as they are. */
  unchanged: number;
  /** Matches that could not be decided or ranked. */
  unknown: number;
  /** Package IDs that did not parse. */
  unparsed: number;
  /** Rows written. */
  written: number;
  /**
   * Why `vulns` is not complete: counts and fixed words, such as `no advisory
   * feed configured`, or the error, which may quote the advisory source.
   */
  detail?: string;
}

/**
 * `running`: another scan of the account runs. `removed`: the account was
 * removed or is being removed (Admin.removeAccount) and not added again.
 */
export type BeginResult =
  | { started: true }
  | { started: false; running: string }
  | { started: false; removed: true };

/** How a scan ends in the graph's `scans` table. */
export type ScanEnd = "complete" | "failed";

/**
 * The calls the scan makes on the account's graph object (AccountGraph).
 * Every call but `beginScan` throws `StaleScanError` once the scan is no
 * longer the running scan of the account.
 */
export interface ScanGraph {
  beginScan(scanId: string, kind: "full", at: number): Awaitable<BeginResult>;
  writeChunk(
    scanId: string,
    resourceClass: string,
    output: CollectorOutput,
    options: { singleChunk: boolean },
  ): Awaitable<ChunkCounters>;
  recordCoverage(
    scanId: string,
    resourceClass: string,
    status: CoverageStatus,
    chunks?: { total: number; done: number },
    detail?: string | null,
  ): Awaitable<void>;
  sweep(scanId: string, resourceClass: string): Awaitable<SweepResult>;
  computeExposure(scanId: string): Awaitable<ExposureCounters>;
  matchVulns(scanId: string): Awaitable<VulnCounters>;
  evaluateRules(scanId: string): Awaitable<RulesCounters>;
  /** Returns the status the scan ended with, which is `failed` if it was ended as stale. */
  finishScan(scanId: string, status: ScanEnd, at: number): Awaitable<ScanEnd>;
}

/** Per-class result of a scan. */
export interface ClassSummary {
  status: CoverageStatus;
  /** Chunks planned; 0 when the plan step failed. */
  chunks: number;
  done: number;
  nodes: number;
  edges: number;
  changed: number;
  signals: number;
  insights: number;
  /**
   * Reasons the written chunks gave for resources they left out (decision
   * 0005). Any makes the class `partial`, even when every chunk was written.
   */
  truncated?: number;
  /**
   * Why the class is not complete: the error of the chunk that failed, and
   * the first truncated reasons. May quote API error messages and IDs from
   * the scanned account: untrusted.
   */
  detail?: string;
  swept?: { nodes: number; edges: number } | { error: string };
}

/**
 * `complete`: every class, exposure and every rule ran fully. `partial`:
 * rules ran, but some input was not complete or single rules ended `error`
 * (TM-11). `failed`: rules did not run. `skipped`: another scan of the
 * account was still running, or the account is not in the index.
 *
 * The vulns step counts when it ended `error`. `vulns` coverage `partial`
 * does not make a scan partial: no advisory feed exists yet, so it is
 * partial in every scan, and the rules that require it (CF-001) are
 * `not_evaluated`, which their runs show.
 */
export type ScanStatus = "complete" | "partial" | "failed" | "skipped";

/** Output of a scan Workflow instance and the `summary` of its `scan_runs` row. */
export interface ScanSummary {
  scanId: string;
  accountId: string;
  status: ScanStatus;
  startedAt: number;
  finishedAt: number | null;
  classes: Record<string, ClassSummary>;
  exposure: ExposureCounters | null;
  vulns: VulnCounters | null;
  rules: RulesCounters | null;
  /** Set when status is `skipped` because another scan of the account runs. */
  running?: string;
  /**
   * Why the scan was skipped or stopped: the account is not in the index or
   * is being removed, or the scan is no longer the running scan of the
   * account. For a `partial` scan in which rules ended `error`, which ones:
   * `rules ended error (<count>): <IDs>`, at most RULE_ERRORS_LISTED IDs
   * (TM-11).
   */
  detail?: string;
}

export interface ScanRunStart {
  id: string;
  accountId: string;
  startedAt: number;
}

export interface ScanRunEnd extends ScanRunStart {
  finishedAt: number;
  status: "complete" | "partial" | "failed";
  summary: ScanSummary;
}

/** The scan's reads and writes of the account index (D1). */
export interface ScanIndex {
  /**
   * Whether the account is in the index and not being removed. A removed
   * account, or one being removed, is not scanned (R4-03, R5-08).
   */
  hasAccount(accountId: string): Promise<boolean>;
  /** Adds the scan's running row, but only while hasAccount would be true. */
  beginRun(run: ScanRunStart): Promise<void>;
  finishRun(run: ScanRunEnd): Promise<void>;
}
