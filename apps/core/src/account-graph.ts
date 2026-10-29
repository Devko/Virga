import { DurableObject } from "cloudflare:workers";
import type { CollectorOutput } from "@virga/collectors";
import {
  applyBatch,
  type Batch,
  type BatchResult,
  beginScan,
  type CoverageStatus,
  finishScan,
  fromDurableObjectStorage,
  migrate,
  prepareBatch,
  recordCoverage,
  replaceExposure,
  replaceInsights,
  type SqlRunner,
  type SweepResult,
  setSignals,
  sweep,
} from "@virga/graph";
import { RULES, type RuleHit, runRule } from "@virga/rules";
import { describe } from "./errors.ts";
import { checkOutput } from "./graph/chunk.ts";
import { DEFAULT_EVALUATORS, type Evaluators } from "./graph/evaluators.ts";
import { getFinding, graphSummary, listFindings, neighborhood } from "./graph/read.ts";
import type {
  FindingDetail,
  FindingFilters,
  FindingPage,
  GraphSummary,
  Neighborhood,
} from "./graph/views.ts";
import { STALE_SCAN_MS } from "./scan/policy.ts";
import type {
  BeginResult,
  ChunkCounters,
  ExposureCounters,
  RulesCounters,
  ScanGraph,
} from "./scan/types.ts";

/**
 * The security graph of one scanned account. One instance per account, named
 * by the account ID; tenant isolation is the object boundary.
 */
export class AccountGraph extends DurableObject<Env> implements ScanGraph {
  private readonly db: SqlRunner;
  /**
   * Exposure evaluator and rules for the scan's derived steps. An instance
   * field, so it is not reachable over RPC; tests replace it in place.
   */
  evaluators: Evaluators = DEFAULT_EVALUATORS;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.db = fromDurableObjectStorage(ctx.storage);
    void ctx.blockConcurrencyWhile(async () => {
      migrate(this.db);
    });
  }

  /**
   * Starts a scan. Idempotent for a retried step. Refuses while another scan
   * is running, because its sweep would tombstone what this one writes; a
   * scan running longer than STALE_SCAN_MS is marked failed instead.
   */
  beginScan(id: string, kind: "full" | "partial" | "event" = "full", at = Date.now()): BeginResult {
    if (this.db.query("SELECT 1 FROM scans WHERE id = ?", id).length > 0) return { started: true };
    for (const other of this.db.query<{ id: string; started_at: number }>(
      "SELECT id, started_at FROM scans WHERE status = 'running' ORDER BY started_at DESC",
    )) {
      if (other.started_at > at - STALE_SCAN_MS) return { started: false, running: other.id };
      finishScan(this.db, other.id, "failed", at);
    }
    beginScan(this.db, { id, kind, at });
    return { started: true };
  }

  async applyBatch(batch: Batch): Promise<BatchResult> {
    return applyBatch(this.db, await prepareBatch(batch));
  }

  /** Writes one collector chunk: nodes and edges, signals, and (single chunk only) insights. */
  async writeChunk(
    scanId: string,
    resourceClass: string,
    output: CollectorOutput,
    options: { singleChunk: boolean },
  ): Promise<ChunkCounters> {
    const { signals, insights } = checkOutput(output, options.singleChunk);
    const batch = await prepareBatch({
      scanId,
      resourceClass,
      nodes: output.nodes,
      edges: output.edges,
    });
    const written = applyBatch(this.db, batch);
    if (signals.length > 0) setSignals(this.db, signals, batch.at);
    if (insights) replaceInsights(this.db, insights, batch.at);
    return { ...written, signals: signals.length, insights: insights?.length ?? 0 };
  }

  recordCoverage(
    scanId: string,
    resourceClass: string,
    status: CoverageStatus,
    chunks?: { total: number; done: number },
    detail?: string | null,
  ): void {
    recordCoverage(this.db, {
      scanId,
      resourceClass,
      status,
      chunksTotal: chunks?.total ?? 0,
      chunksDone: chunks?.done ?? 0,
      detail: detail ?? null,
    });
  }

  sweep(scanId: string, resourceClass: string): SweepResult {
    return sweep(this.db, scanId, resourceClass);
  }

  /**
   * Runs the exposure evaluator, replaces the exposure table and records
   * coverage `exposure`. An evaluator failure is a result, not an exception:
   * retrying a deterministic evaluator would not help.
   */
  computeExposure(scanId: string): ExposureCounters {
    try {
      const rows = this.evaluators.exposure(this.db);
      replaceExposure(this.db, rows);
      recordCoverage(this.db, { scanId, resourceClass: "exposure", status: "complete" });
      const decisions: Record<string, number> = {};
      for (const row of rows) decisions[row.decision] = (decisions[row.decision] ?? 0) + 1;
      return { status: "complete", entries: rows.length, decisions };
    } catch (error) {
      const detail = describe(error);
      recordCoverage(this.db, { scanId, resourceClass: "exposure", status: "error", detail });
      return { status: "error", entries: 0, decisions: {}, detail };
    }
  }

  /** Runs every rule with the findings lifecycle and returns counters. */
  evaluateRules(scanId: string): RulesCounters {
    const counters: RulesCounters = {
      status: "complete",
      rules: 0,
      evaluated: 0,
      notEvaluated: 0,
      errors: 0,
      hits: 0,
      opened: 0,
      resolved: 0,
    };
    try {
      for (const run of this.evaluators.rules(this.db, this.evaluators.ruleSet, scanId)) {
        counters.rules++;
        if (run.status === "evaluated") counters.evaluated++;
        else if (run.status === "not_evaluated") counters.notEvaluated++;
        else counters.errors++;
        counters.hits += run.hits;
        counters.opened += run.opened;
        counters.resolved += run.resolved;
      }
      return counters;
    } catch (error) {
      return { ...counters, status: "error", detail: describe(error) };
    }
  }

  finishScan(scanId: string, status: "complete" | "failed", at = Date.now()): void {
    finishScan(this.db, scanId, status, at);
  }

  /** Runs one compiled rule. One call per rule keeps each request well below the CPU limit. */
  runRule(ruleId: string, overrides?: Record<string, number | string>): RuleHit[] {
    const rule = RULES.find((r) => r.id === ruleId);
    if (!rule) throw new Error(`unknown rule ${ruleId}`);
    return runRule(this.db, rule, overrides);
  }

  // Reads for GraphReader.

  scanSummary(): GraphSummary {
    return graphSummary(this.db);
  }

  listFindings(filters?: FindingFilters): FindingPage {
    return listFindings(this.db, filters);
  }

  getFinding(fingerprint: string): FindingDetail | null {
    return getFinding(this.db, fingerprint);
  }

  getNeighborhood(
    nodeId: string,
    options?: { depth?: number; limit?: number },
  ): Neighborhood | null {
    return neighborhood(this.db, nodeId, options);
  }
}
