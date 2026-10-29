import type { CfReader } from "@virga/cf-api";
import { COLLECTORS, type Collector, type CollectorContext } from "@virga/collectors";
import { describe } from "../errors.ts";
import { orderCollectors } from "./order.ts";
import { API_STEP, type Failure, type ScanStep, STORE_STEP, settle } from "./step.ts";
import type {
  ChunkCounters,
  ClassSummary,
  ScanGraph,
  ScanIndex,
  ScanStatus,
  ScanSummary,
} from "./types.ts";

export interface ScanDeps {
  step: ScanStep;
  /** The account's graph object. Called once per step, so a broken stub is not reused. */
  graph: () => ScanGraph;
  index: ScanIndex;
  /** Read-only API access for the account, through the broker in production. */
  reader: (accountId: string) => CfReader;
  collectors?: readonly Collector[];
  clock?: () => number;
}

export interface ScanParams {
  accountId: string;
  /** The Workflow instance ID; also the scan ID in the graph and the index. */
  scanId: string;
  /** Scan start (epoch ms), the same on every replay. */
  now: number;
}

type PlanResult = { status: "ok"; chunks: unknown[][] } | Failure;
type CollectResult = ({ status: "ok" } & ChunkCounters) | Failure;

const emptyClass = (): ClassSummary => ({
  status: "error",
  chunks: 0,
  done: 0,
  nodes: 0,
  edges: 0,
  changed: 0,
  signals: 0,
  insights: 0,
});

/** Runs a step and turns an exhausted retry into a failure result. */
async function attempt<T>(run: () => Promise<T | Failure>): Promise<T | Failure> {
  try {
    return await run();
  } catch (error) {
    return { status: "error", detail: describe(error) };
  }
}

// The plan is the one step result that carries data (chunk units such as zone
// IDs); keep it well below the 1 MiB step result limit.
const MAX_PLAN_BYTES = 512 * 1024;
const encoder = new TextEncoder();

function checkPlan(chunks: unknown): unknown[][] {
  if (!Array.isArray(chunks) || !chunks.every(Array.isArray)) {
    throw new TypeError("plan must return an array of chunks");
  }
  if (encoder.encode(JSON.stringify(chunks)).length > MAX_PLAN_BYTES) {
    throw new RangeError(`plan larger than ${MAX_PLAN_BYTES} bytes`);
  }
  return chunks;
}

/**
 * One full scan of one account. Every effect happens inside a step, and steps
 * return only counters: collectors write to the graph object directly, so
 * Workflow state stays far below the 1 MiB step limit and never holds API data.
 *
 * Per class: plan, one step per chunk, then coverage. A class whose chunks all
 * succeed is `complete` and swept; a missing permission is `no_permission`
 * without retries; any other failure is retried by the step config and then
 * recorded as `error` (or `partial` if earlier chunks were written). Then
 * exposure, rules, and the end of the scan in the graph and the index.
 */
export async function runScan(deps: ScanDeps, params: ScanParams): Promise<ScanSummary> {
  const { step, index } = deps;
  const { accountId, scanId, now } = params;
  const graph = deps.graph;
  const clock = deps.clock ?? Date.now;
  const collectors = orderCollectors(deps.collectors ?? COLLECTORS);
  const summary: ScanSummary = {
    scanId,
    accountId,
    status: "failed",
    startedAt: now,
    finishedAt: null,
    classes: {},
    exposure: null,
    rules: null,
  };

  const begin = await step.do("begin", STORE_STEP, async () => {
    const result = await graph().beginScan(scanId, "full", now);
    if (result.started) await index.beginRun({ id: scanId, accountId, startedAt: now });
    return result;
  });
  if (!begin.started) return { ...summary, status: "skipped", running: begin.running };

  const context = (): CollectorContext => ({
    accountId,
    scanId,
    api: deps.reader(accountId),
    now,
  });

  for (const collector of collectors) {
    const cls = collector.resourceClass;
    const result = emptyClass();
    summary.classes[cls] = result;

    const plan = await attempt<PlanResult>(() =>
      step.do(`plan:${cls}`, API_STEP, async (): Promise<PlanResult> => {
        try {
          return { status: "ok", chunks: checkPlan(await collector.plan(context())) };
        } catch (error) {
          return settle(error);
        }
      }),
    );

    let failure: Failure | null = plan.status === "ok" ? null : plan;
    if (plan.status === "ok") {
      result.chunks = plan.chunks.length;
      const singleChunk = plan.chunks.length === 1;
      for (const [i, chunk] of plan.chunks.entries()) {
        const outcome = await attempt<CollectResult>(() =>
          step.do(`collect:${cls}:${i + 1}`, API_STEP, async (): Promise<CollectResult> => {
            try {
              const output = await collector.collect(context(), chunk);
              const written = await graph().writeChunk(scanId, cls, output, { singleChunk });
              return { status: "ok", ...written };
            } catch (error) {
              return settle(error);
            }
          }),
        );
        if (outcome.status !== "ok") {
          failure = outcome;
          break;
        }
        result.done++;
        result.nodes += outcome.nodes;
        result.edges += outcome.edges;
        result.changed += outcome.changed;
        result.signals += outcome.signals;
        result.insights += outcome.insights;
      }
    }

    if (failure === null) result.status = "complete";
    else if (result.done > 0) result.status = "partial";
    else result.status = failure.status;
    if (failure) result.detail = failure.detail;

    await step.do(`coverage:${cls}`, STORE_STEP, async () => {
      await graph().recordCoverage(
        scanId,
        cls,
        result.status,
        { total: result.chunks, done: result.done },
        result.detail ?? null,
      );
      return { status: result.status };
    });
  }

  // Sweep only classes this scan saw completely; anything else keeps its rows.
  for (const [cls, result] of Object.entries(summary.classes)) {
    if (result.status !== "complete") continue;
    try {
      const swept = await step.do(`sweep:${cls}`, STORE_STEP, async () => {
        const { nodes, edges } = await graph().sweep(scanId, cls);
        return { nodes, edges };
      });
      result.swept = swept;
    } catch (error) {
      result.swept = { error: describe(error) };
    }
  }

  try {
    summary.exposure = await step.do("exposure", STORE_STEP, async () =>
      graph().computeExposure(scanId),
    );
  } catch (error) {
    summary.exposure = { status: "error", entries: 0, decisions: {}, detail: describe(error) };
  }

  try {
    summary.rules = await step.do("rules", STORE_STEP, async () => graph().evaluateRules(scanId));
  } catch (error) {
    summary.rules = {
      status: "error",
      rules: 0,
      evaluated: 0,
      notEvaluated: 0,
      errors: 0,
      hits: 0,
      opened: 0,
      resolved: 0,
      detail: describe(error),
    };
  }

  const status = scanStatus(summary);
  const finishedAt = await step.do("finish", STORE_STEP, async () => {
    const at = clock();
    await graph().finishScan(scanId, status === "failed" ? "failed" : "complete", at);
    await index.finishRun({
      id: scanId,
      accountId,
      startedAt: now,
      finishedAt: at,
      status,
      summary: { ...summary, status, finishedAt: at },
    });
    return at;
  });
  return { ...summary, status, finishedAt };
}

function scanStatus(summary: ScanSummary): Exclude<ScanStatus, "skipped"> {
  if (summary.rules?.status !== "complete") return "failed";
  const classesComplete = Object.values(summary.classes).every((c) => c.status === "complete");
  return classesComplete && summary.exposure?.status === "complete" ? "complete" : "partial";
}
