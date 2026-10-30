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
import { type AccountChanges, addAccount, removeAccount, Serial } from "./accounts.ts";
import { describe, StaleScanError } from "./errors.ts";
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
import type { AccountRow, NewAccount } from "./index-db.ts";
import { assertAccountId } from "./scan/ids.ts";
import { RULE_ERRORS_LISTED, STALE_SCAN_MS } from "./scan/policy.ts";
import type {
  BeginResult,
  ChunkCounters,
  ExposureCounters,
  RulesCounters,
  ScanEnd,
  ScanGraph,
} from "./scan/types.ts";

/** A scan's status, and the scan that is current in the graph. */
const scanRow = (db: SqlRunner, scanId: string) =>
  db.query<{ status: ScanEnd | "running"; current: string | null }>(
    `SELECT status, (SELECT value FROM meta WHERE key = 'current_scan') AS current
     FROM scans WHERE id = ?`,
    scanId,
  )[0];

/**
 * Scan-scoped writes come only from the running scan that is current in the
 * graph (R2-07). A scan marked failed as stale, or one a newer scan took
 * over, may still have a Workflow instance that retries steps: its chunks
 * would mark nodes as seen by it, and the newer scan's sweep would tombstone
 * them. Call it synchronously before the write, after any await.
 */
function assertCurrent(db: SqlRunner, scanId: string): void {
  const row = scanRow(db, scanId);
  if (row?.status !== "running" || row.current !== scanId) throw new StaleScanError(scanId);
}

/**
 * Deletes the account's whole graph, for offboarding (removeAccount runs it
 * after marking the index row and before deleting it). The object is
 * migrated again, so it stays an empty, valid graph: a scan that still runs
 * is refused like any scan that is not current, and an account that is
 * added again starts from nothing. The `removed` marker in meta makes
 * beginScan refuse new scans, for example from an instance that was queued
 * before the removal (R4-03), until clearRemoved. A module function, not a
 * method, so it is not reachable over RPC and runs only inside an account
 * change (TM-09).
 */
async function deleteAll(ctx: DurableObjectState, db: SqlRunner): Promise<void> {
  await ctx.blockConcurrencyWhile(async () => {
    await ctx.storage.deleteAll();
    migrate(db);
    db.run("INSERT INTO meta (key, value) VALUES ('removed', ?)", String(Date.now()));
  });
}

/** Lets scans begin again after deleteAll, for an account that is added again. */
function clearRemoved(db: SqlRunner): void {
  db.run("DELETE FROM meta WHERE key = 'removed'");
}

/** An account change names the account whose graph object this is, or it is refused. */
function assertOwnAccount(ctx: DurableObjectState, env: Env, accountId: unknown): void {
  assertAccountId(accountId);
  if (!ctx.id.equals(env.ACCOUNT_GRAPH.idFromName(accountId))) {
    throw new TypeError("the account ID does not name this graph object");
  }
}

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
  /**
   * The account index and this graph, for addAccount and removeAccount. An
   * instance field, so it is not reachable over RPC; tests replace it in place.
   */
  accounts: AccountChanges;
  /** Additions and removals of the account, one at a time (TM-09). */
  private readonly changes = new Serial();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.db = fromDurableObjectStorage(ctx.storage);
    this.accounts = {
      index: env.INDEX,
      deleteGraph: () => deleteAll(ctx, this.db),
      clearRemoved: () => clearRemoved(this.db),
    };
    void ctx.blockConcurrencyWhile(async () => {
      migrate(this.db);
    });
  }

  /**
   * Starts a scan. Idempotent for a retried step. Refuses while another scan
   * is running, because its sweep would tombstone what this one writes; a
   * scan running longer than STALE_SCAN_MS is marked failed instead, and is
   * refused if its instance comes back (a restart). Refuses after
   * removeAccount until addAccount.
   */
  beginScan(id: string, kind: "full" | "partial" | "event" = "full", at = Date.now()): BeginResult {
    if (this.db.query("SELECT 1 FROM meta WHERE key = 'removed'").length > 0) {
      return { started: false, removed: true };
    }
    for (const other of this.db.query<{ id: string; started_at: number }>(
      "SELECT id, started_at FROM scans WHERE status = 'running' AND id != ? ORDER BY started_at DESC",
      id,
    )) {
      if (other.started_at > at - STALE_SCAN_MS) return { started: false, running: other.id };
      finishScan(this.db, other.id, "failed", at);
    }
    if (this.db.query("SELECT 1 FROM scans WHERE id = ?", id).length > 0) return { started: true };
    beginScan(this.db, { id, kind, at });
    return { started: true };
  }

  async applyBatch(batch: Batch): Promise<BatchResult> {
    const prepared = await prepareBatch(batch);
    assertCurrent(this.db, batch.scanId);
    return applyBatch(this.db, prepared);
  }

  /**
   * Writes one collector chunk: nodes and edges, signals, and (single chunk
   * only) insights. Returns the chunk's reasons for resources it left out,
   * checked, so the scan can record the class `partial` (decision 0005).
   */
  async writeChunk(
    scanId: string,
    resourceClass: string,
    output: CollectorOutput,
    options: { singleChunk: boolean },
  ): Promise<ChunkCounters> {
    const { signals, insights, truncated } = checkOutput(output, options.singleChunk);
    const batch = await prepareBatch({
      scanId,
      resourceClass,
      nodes: output.nodes,
      edges: output.edges,
    });
    assertCurrent(this.db, scanId);
    const written = applyBatch(this.db, batch);
    if (signals.length > 0) setSignals(this.db, signals, batch.at);
    if (insights) replaceInsights(this.db, insights, batch.at);
    const counters = { ...written, signals: signals.length, insights: insights?.length ?? 0 };
    return truncated.length > 0 ? { ...counters, truncated } : counters;
  }

  recordCoverage(
    scanId: string,
    resourceClass: string,
    status: CoverageStatus,
    chunks?: { total: number; done: number },
    detail?: string | null,
  ): void {
    assertCurrent(this.db, scanId);
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
    assertCurrent(this.db, scanId);
    return sweep(this.db, scanId, resourceClass);
  }

  /**
   * Runs the exposure evaluator, replaces the exposure table and records
   * coverage `exposure`. An evaluator failure is a result, not an exception:
   * retrying a deterministic evaluator would not help.
   */
  computeExposure(scanId: string): ExposureCounters {
    assertCurrent(this.db, scanId);
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

  /**
   * Runs every rule with the findings lifecycle and returns counters, with
   * the IDs of the first RULE_ERRORS_LISTED rules that ended `error`.
   */
  evaluateRules(scanId: string): RulesCounters {
    const counters: RulesCounters = {
      status: "complete",
      rules: 0,
      evaluated: 0,
      notEvaluated: 0,
      errors: 0,
      hits: 0,
      undecided: 0,
      opened: 0,
      resolved: 0,
    };
    assertCurrent(this.db, scanId);
    try {
      for (const run of this.evaluators.rules(this.db, this.evaluators.ruleSet, scanId)) {
        counters.rules++;
        if (run.status === "evaluated") counters.evaluated++;
        else if (run.status === "not_evaluated") counters.notEvaluated++;
        else {
          counters.errors++;
          // The scan reports itself partial and names these (TM-11).
          if (counters.errors <= RULE_ERRORS_LISTED) {
            counters.errored = [...(counters.errored ?? []), run.ruleId];
          }
        }
        counters.hits += run.hits;
        counters.undecided += run.undecided;
        counters.opened += run.opened;
        counters.resolved += run.resolved;
      }
      return counters;
    } catch (error) {
      return { ...counters, status: "error", detail: describe(error) };
    }
  }

  /**
   * Ends a running scan and returns the status it ended with; a running scan
   * that is no longer current ends `failed`. A scan that already ended keeps
   * its status, so a retried step changes nothing and a scan marked failed
   * as stale stays failed.
   */
  finishScan(scanId: string, status: ScanEnd, at = Date.now()): ScanEnd {
    const row = scanRow(this.db, scanId);
    if (!row) throw new StaleScanError(scanId);
    if (row.status !== "running") return row.status;
    const end = row.current === scanId ? status : "failed";
    finishScan(this.db, scanId, end, at);
    return end;
  }

  /**
   * Admin.addAccount: adds the account to the index or updates it, finishing
   * a removal that did not finish first, then clears the `removed` marker.
   * Runs after any addition or removal of the account that is under way, so
   * the last call decides the end state (TM-09).
   */
  addAccount(input: NewAccount): Promise<AccountRow> {
    assertOwnAccount(this.ctx, this.env, input?.id);
    return this.changes.run(() => addAccount(this.accounts, input));
  }

  /**
   * Admin.removeAccount: marks the index row `removing`, deletes this graph,
   * then deletes the index rows (R5-08). Returns whether the account was in
   * the index. Runs after any addition or removal of the account that is
   * under way, so the last call decides the end state (TM-09).
   */
  removeAccount(accountId: string): Promise<boolean> {
    assertOwnAccount(this.ctx, this.env, accountId);
    return this.changes.run(() => removeAccount(this.accounts, accountId));
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
