import { DurableObject } from "cloudflare:workers";
import {
  applyBatch,
  beginScan,
  guardRead,
  migrate,
  prepareBatch,
  type Row,
  recordCoverage,
  replaceExposure,
  type SqlRunner,
  sweep,
  upsertVulns,
} from "@virga/graph";
import { RULES, runRule } from "@virga/rules";
import { syntheticGraph } from "../../../apps/core/test/synthetic.ts";

interface Env {
  SPIKE_GRAPH: DurableObjectNamespace<SpikeGraph>;
}

interface Counted {
  rowsRead: number;
  rowsWritten: number;
}

/** Wraps Durable Object storage and sums rowsRead and rowsWritten of every statement. */
function countingRunner(storage: DurableObjectStorage, counter: Counted): SqlRunner {
  const exec = (sql: string, params: unknown[]) => {
    const cursor = storage.sql.exec(sql, ...params);
    const rows = cursor.toArray();
    counter.rowsRead += cursor.rowsRead;
    counter.rowsWritten += cursor.rowsWritten;
    return rows;
  };
  const runner: SqlRunner = {
    query: (sql, ...params) => exec(sql, params) as never,
    queryReadOnly: (sql, ...params) =>
      guardRead(runner, () => {
        const cursor = storage.sql.exec(sql, ...params);
        const rows = cursor.toArray() as Row[];
        counter.rowsRead += cursor.rowsRead;
        counter.rowsWritten += cursor.rowsWritten;
        return { rows, rowsWritten: cursor.rowsWritten };
      }) as never,
    run: (sql, ...params) => {
      exec(sql, params);
    },
    script: (sql) => {
      exec(sql, []);
    },
    transaction: (fn) => storage.transactionSync(fn),
  };
  return runner;
}

export class SpikeGraph extends DurableObject<Env> {
  private readonly counter: Counted = { rowsRead: 0, rowsWritten: 0 };
  private readonly db: SqlRunner;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.db = countingRunner(ctx.storage, this.counter);
    void ctx.blockConcurrencyWhile(async () => {
      migrate(this.db);
    });
  }

  private take(): Counted {
    const snapshot = { ...this.counter };
    this.counter.rowsRead = 0;
    this.counter.rowsWritten = 0;
    return snapshot;
  }

  /** Generates the synthetic account and writes it in batches, all inside the object. */
  async scan(scanId: string, workers: number): Promise<Record<string, unknown>> {
    beginScan(this.db, { id: scanId, kind: "full" });
    const graph = syntheticGraph(workers, scanId);
    let changed = 0;
    for (const batch of graph.batches) {
      changed += applyBatch(this.db, await prepareBatch(batch)).changed;
    }
    return {
      nodes: graph.nodeCount,
      edges: graph.edgeCount,
      batches: graph.batches.length,
      changed,
      expectedHits: graph.expectedHits,
      ...this.take(),
    };
  }

  loadDerived(workers: number, scanId: string): Counted {
    const graph = syntheticGraph(workers, scanId);
    replaceExposure(this.db, graph.exposure);
    upsertVulns(this.db, graph.vulns);
    return this.take();
  }

  completeAndSweep(scanId: string): Counted & { nodes: number; edges: number } {
    recordCoverage(this.db, { scanId, resourceClass: "workers", status: "complete" });
    const result = sweep(this.db, scanId, "workers");
    return { ...this.take(), nodes: result.nodes, edges: result.edges };
  }

  runCf001(): Counted & { hits: string[] } {
    const rule = RULES.find((r) => r.id === "CF-001");
    if (!rule) throw new Error("CF-001 missing");
    const hits = runRule(this.db, rule).map((h) => h.fingerprint);
    return { ...this.take(), hits };
  }

  probes(): Record<string, unknown> {
    const sql = this.ctx.storage.sql;
    const probe = (query: string, ...params: unknown[]) => {
      try {
        return sql.exec(query, ...params).toArray();
      } catch (error) {
        return `error: ${(error as Error).message}`;
      }
    };
    return {
      sqliteVersion: probe("SELECT sqlite_version() AS v"),
      triggers: probe("SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name"),
      recursiveCte: probe(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 10) SELECT count(*) AS c FROM n",
      ),
      namedParam: probe("SELECT :a AS v", 1),
      numberedParam: probe("SELECT ?1 AS v", 1),
      databaseSize: sql.databaseSize,
      counts: probe(
        "SELECT (SELECT count(*) FROM nodes) AS nodes, (SELECT count(*) FROM edges) AS edges, (SELECT count(*) FROM changes) AS changes",
      ),
    };
  }
}

async function timed<T>(fn: () => Promise<T>): Promise<{ ms: number; result: T }> {
  const start = Date.now();
  const result = await fn();
  return { ms: Date.now() - start, result };
}

async function run(env: Env, workers: number): Promise<Record<string, unknown>> {
  const stub = env.SPIKE_GRAPH.get(env.SPIKE_GRAPH.newUniqueId());
  const report: Record<string, unknown> = { workers, ranAt: new Date().toISOString() };

  const scan = async (scanId: string) => {
    const { ms, result } = await timed(() => stub.scan(scanId, workers));
    return { writeMs: ms, ...result } as Record<string, unknown> & { expectedHits: string[] };
  };

  const first = await scan("scan-1");
  report.firstScan = { ...first, expectedHits: first.expectedHits.length };
  report.derived = await stub.loadDerived(workers, "scan-1");
  report.sweepFirst = await stub.completeAndSweep("scan-1");

  const rule = await timed(() => stub.runCf001());
  report.cf001 = {
    ms: rule.ms,
    rowsRead: rule.result.rowsRead,
    hits: rule.result.hits.length,
    matchesExpected:
      JSON.stringify([...rule.result.hits].sort()) === JSON.stringify(first.expectedHits),
  };

  const second = await scan("scan-2");
  report.unchangedRescan = { ...second, expectedHits: undefined };
  report.sweepSecond = await stub.completeAndSweep("scan-2");
  report.probes = await stub.probes();
  return report;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/run")
      return new Response("spike s03: GET /run?workers=N", { status: 404 });
    const workers = Math.min(Number(url.searchParams.get("workers") ?? "6500"), 20000);
    return Response.json(await run(env, workers));
  },
};
