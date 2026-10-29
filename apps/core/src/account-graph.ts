import { DurableObject } from "cloudflare:workers";
import {
  applyBatch,
  type Batch,
  type BatchResult,
  beginScan,
  type CoverageStatus,
  fromDurableObjectStorage,
  migrate,
  prepareBatch,
  recordCoverage,
  type SqlRunner,
  type SweepResult,
  sweep,
} from "@virga/graph";
import { RULES, type RuleHit, runRule } from "@virga/rules";

/**
 * The security graph of one scanned account. One instance per account, named
 * by the account ID; tenant isolation is the object boundary.
 */
export class AccountGraph extends DurableObject<Env> {
  private readonly db: SqlRunner;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.db = fromDurableObjectStorage(ctx.storage);
    void ctx.blockConcurrencyWhile(async () => {
      migrate(this.db);
    });
  }

  beginScan(id: string, kind: "full" | "partial" | "event"): void {
    beginScan(this.db, { id, kind });
  }

  async applyBatch(batch: Batch): Promise<BatchResult> {
    return applyBatch(this.db, await prepareBatch(batch));
  }

  recordCoverage(
    scanId: string,
    resourceClass: string,
    status: CoverageStatus,
    chunks?: { total: number; done: number },
  ): void {
    recordCoverage(this.db, {
      scanId,
      resourceClass,
      status,
      chunksTotal: chunks?.total ?? 0,
      chunksDone: chunks?.done ?? 0,
    });
  }

  sweep(scanId: string, resourceClass: string): SweepResult {
    return sweep(this.db, scanId, resourceClass);
  }

  /** Runs one compiled rule. One call per rule keeps each request well below the CPU limit. */
  runRule(ruleId: string, overrides?: Record<string, number | string>): RuleHit[] {
    const rule = RULES.find((r) => r.id === ruleId);
    if (!rule) throw new Error(`unknown rule ${ruleId}`);
    return runRule(this.db, rule, overrides);
  }
}
