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
  hits: number;
  opened: number;
  resolved: number;
  detail?: string;
}

export type BeginResult = { started: true } | { started: false; running: string };

/** The calls the scan makes on the account's graph object (AccountGraph). */
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
  finishScan(scanId: string, status: "complete" | "failed", at: number): Awaitable<void>;
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
  /** Set when status is `skipped`. */
  running?: string;
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

/** The scan's writes to the account index (D1). */
export interface ScanIndex {
  beginRun(run: ScanRunStart): Promise<void>;
  finishRun(run: ScanRunEnd): Promise<void>;
}
