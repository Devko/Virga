import type { CollectorOutput } from "@virga/collectors";
import type { CoverageStatus, SweepResult } from "@virga/graph";

export type Awaitable<T> = T | Promise<T>;

/** What a collect step wrote. Steps return counters like this, never graph rows. */
export interface ChunkCounters {
  nodes: number;
  edges: number;
  /** Rows created, changed or restored. */
  changed: number;
  signals: number;
  insights: number;
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
  /** Why the class is not complete. May quote API error messages: untrusted. */
  detail?: string;
  swept?: { nodes: number; edges: number } | { error: string };
}

/**
 * `complete`: every class, exposure and rules ran fully. `partial`: rules
 * ran, but some input was not complete. `failed`: rules did not run.
 * `skipped`: another scan of the account was still running.
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
  rules: RulesCounters | null;
  /** Set when status is `skipped` because another scan of the account runs. */
  running?: string;
  /**
   * Why the scan was skipped or stopped: the account is not in the index or
   * is being removed, or the scan is no longer the running scan of the account.
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
