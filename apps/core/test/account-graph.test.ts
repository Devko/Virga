import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import {
  fromDurableObjectStorage,
  migrate,
  replaceExposure,
  SCHEMA_VERSION,
  schemaVersion,
  upsertVulns,
} from "@virga/graph";
import { evaluateFixture, loadFixture, RULES } from "@virga/rules";
import { FIXTURES } from "@virga/rules/fixtures";
import { describe, expect, it } from "vitest";
import type { AccountGraph } from "../src/account-graph.ts";
import { DEFAULT_EVALUATORS, type Evaluators } from "../src/graph/evaluators.ts";
import { syntheticGraph } from "./synthetic.ts";

const freshGraph = () => env.ACCOUNT_GRAPH.get(env.ACCOUNT_GRAPH.newUniqueId());

describe("AccountGraph in Durable Object SQLite", () => {
  it("migrates on construction", async () => {
    const stub = freshGraph();
    const version = await runInDurableObject(stub, (_: AccountGraph, state) =>
      schemaVersion(fromDurableObjectStorage(state.storage)),
    );
    expect(version).toBe(SCHEMA_VERSION);
  });

  it("writes through RPC with history and sweep", async () => {
    const stub = freshGraph();
    const batch = (scanId: string, withB: boolean) => ({
      scanId,
      resourceClass: "workers",
      nodes: [
        { type: "worker_script" as const, nativeId: "a", name: "a" },
        ...(withB ? [{ type: "worker_script" as const, nativeId: "b", name: "b" }] : []),
      ],
      edges: withB
        ? [{ type: "BINDS" as const, src: "worker_script:a", dst: "worker_script:b", key: "SVC" }]
        : [],
    });
    await stub.beginScan("s1", "full");
    expect(await stub.applyBatch(batch("s1", true))).toEqual({ nodes: 2, edges: 1, changed: 3 });
    await stub.beginScan("s2", "full");
    expect((await stub.applyBatch(batch("s2", false))).changed).toBe(0);
    await stub.recordCoverage("s2", "workers", "complete");
    expect(await stub.sweep("s2", "workers")).toEqual({ swept: true, nodes: 1, edges: 1 });
  });
});

type Stub = ReturnType<typeof freshGraph>;

const rows = (stub: Stub, query: string) =>
  runInDurableObject(stub, (_: AccountGraph, state) => state.storage.sql.exec(query).toArray());

const useEvaluators = (stub: Stub, evaluators: Partial<Evaluators>) =>
  runInDurableObject(stub, (graph: AccountGraph) => {
    graph.evaluators = { ...DEFAULT_EVALUATORS, ...evaluators };
  });

// RPC rejections are awaited through then(), not expect().rejects (see test/helpers.ts).
const failure = (call: Promise<unknown>) =>
  call.then(
    () => "resolved",
    (error: unknown) => String(error),
  );

describe("scan steps in AccountGraph", () => {
  it("starts a scan once and refuses a second while one is running", async () => {
    const stub = freshGraph();
    expect(await stub.beginScan("s1", "full", 1_000)).toEqual({ started: true });
    expect(await stub.beginScan("s1", "full", 1_000)).toEqual({ started: true });
    expect(await stub.beginScan("s2", "full", 2_000)).toEqual({ started: false, running: "s1" });
    // A scan running for more than 12 hours is taken for dead.
    expect(await stub.beginScan("s3", "full", 1_000 + 12 * 3_600_000 + 1)).toEqual({
      started: true,
    });
    expect(await rows(stub, "SELECT id, status FROM scans ORDER BY started_at")).toEqual([
      { id: "s1", status: "failed" },
      { id: "s3", status: "running" },
    ]);
    // The instance of the dead scan comes back, e.g. restarted by hand: refused.
    expect(await stub.beginScan("s1", "full", 1_000)).toEqual({ started: false, running: "s3" });
  });

  it("writes a collector chunk with its signals and insights", async () => {
    const stub = freshGraph();
    await stub.beginScan("s1", "full", 1);
    const written = await stub.writeChunk(
      "s1",
      "traffic",
      {
        nodes: [{ type: "worker_script", nativeId: "api", name: "api" }],
        edges: [],
        signals: [{ nodeId: "worker_script:api", name: "invocations_30d", value: 42 }],
        insights: [
          {
            id: "i-1",
            type: "exposed_infrastructure",
            severity: "Moderate",
            subjectId: "worker_script:api",
            payload: { issue_type: "exposed_infrastructure" },
          },
        ],
      },
      { singleChunk: true },
    );
    expect(written).toEqual({ nodes: 1, edges: 0, changed: 1, signals: 1, insights: 1 });
    expect(await rows(stub, "SELECT node_id, name, value FROM signals")).toEqual([
      { node_id: "worker_script:api", name: "invocations_30d", value: 42 },
    ]);
    expect(await rows(stub, "SELECT id, subject_id, deleted_at FROM insights")).toEqual([
      { id: "i-1", subject_id: "worker_script:api", deleted_at: null },
    ]);
  });

  it("rejects collector output it cannot store safely", async () => {
    const stub = freshGraph();
    await stub.beginScan("s1", "full", 1);
    const write = (output: object, singleChunk = true) =>
      failure(stub.writeChunk("s1", "x", { nodes: [], edges: [], ...output }, { singleChunk }));
    expect(await write({ insights: [] }, false)).toMatch(/TypeError: .*single chunk/);
    expect(await write({ signals: [{ nodeId: "a", name: "Bad Name", value: 1 }] })).toMatch(
      /invalid signal name/,
    );
    expect(await write({ signals: [{ nodeId: "a", name: "n", value: "x".repeat(2000) }] })).toMatch(
      /RangeError: signal value longer/,
    );
    expect(await write({ nodes: [{ type: "zone", nativeId: "x".repeat(600) }] })).toMatch(
      /RangeError: nativeId longer/,
    );
    expect(await rows(stub, "SELECT count(*) AS n FROM nodes")).toEqual([{ n: 0 }]);
  });

  it("computes exposure and records its coverage, also when the evaluator fails", async () => {
    const stub = freshGraph();
    await stub.beginScan("s1", "full", 1);
    await useEvaluators(stub, {
      exposure: () => [
        { entryId: "worker_route:r1", decision: "public", confidence: 2 },
        { entryId: "workers_dev:api.x.workers.dev", decision: "unknown", confidence: 0 },
      ],
    });
    expect(await stub.computeExposure("s1")).toEqual({
      status: "complete",
      entries: 2,
      decisions: { public: 1, unknown: 1 },
    });
    expect(await rows(stub, "SELECT count(*) AS n FROM exposure")).toEqual([{ n: 2 }]);

    await stub.finishScan("s1", "complete", 2);
    expect(await stub.beginScan("s2", "full", 3)).toEqual({ started: true });
    await useEvaluators(stub, {
      exposure: () => {
        throw new Error("unsupported expression");
      },
    });
    expect(await stub.computeExposure("s2")).toEqual({
      status: "error",
      entries: 0,
      decisions: {},
      detail: "Error: unsupported expression",
    });
    expect(
      await rows(stub, "SELECT scan_id, status FROM coverage WHERE resource_class = 'exposure'"),
    ).toEqual([
      { scan_id: "s1", status: "complete" },
      { scan_id: "s2", status: "error" },
    ]);
  });

  it("counts rule runs and turns a failing lifecycle into a result", async () => {
    const stub = freshGraph();
    await stub.beginScan("s1", "full", 1);
    const run = (ruleId: string, status: "evaluated" | "not_evaluated" | "error", hits = 0) => ({
      ruleId,
      status,
      hits,
      missing: [],
      opened: hits,
      resolved: status === "evaluated" ? 1 : 0,
    });
    await useEvaluators(stub, {
      rules: () => [
        run("CF-001", "evaluated", 2),
        run("CF-002", "not_evaluated"),
        run("CF-003", "error"),
      ],
    });
    expect(await stub.evaluateRules("s1")).toEqual({
      status: "complete",
      rules: 3,
      evaluated: 1,
      notEvaluated: 1,
      errors: 1,
      hits: 2,
      opened: 2,
      resolved: 1,
    });
    await useEvaluators(stub, {
      rules: () => {
        throw new Error("lifecycle broke");
      },
    });
    expect(await stub.evaluateRules("s1")).toMatchObject({
      status: "error",
      rules: 0,
      detail: "Error: lifecycle broke",
    });
  });
});

describe("rule fixtures (Durable Object SQLite)", () => {
  it.each(FIXTURES.map((f) => [`${f.rule}/${f.name}`, f] as const))("%s", async (_, fixture) => {
    const rule = RULES.find((r) => r.id === fixture.rule);
    if (!rule) throw new Error(`missing rule ${fixture.rule}`);
    const result = await runInDurableObject(freshGraph(), async (_: AccountGraph, state) => {
      const db = fromDurableObjectStorage(state.storage);
      migrate(db);
      await loadFixture(db, fixture);
      return evaluateFixture(db, rule, fixture);
    });
    expect(result.actual).toEqual(result.expected);
  });
});

describe("synthetic account", () => {
  it("loads about 20,000 nodes and runs CF-001 with the expected hits", async () => {
    const stub = freshGraph();
    const graph = syntheticGraph(6500, "synthetic");
    await stub.beginScan("synthetic", "full");

    const writeStart = Date.now();
    for (const batch of graph.batches) await stub.applyBatch(batch);
    const writeMs = Date.now() - writeStart;

    await runInDurableObject(stub, (_: AccountGraph, state) => {
      const db = fromDurableObjectStorage(state.storage);
      replaceExposure(db, graph.exposure);
      upsertVulns(db, graph.vulns);
    });

    const ruleStart = Date.now();
    const hits = await stub.runRule("CF-001");
    const ruleMs = Date.now() - ruleStart;

    expect(hits.map((h) => h.fingerprint).sort()).toEqual(graph.expectedHits);
    console.log(
      `synthetic: ${graph.nodeCount} nodes, ${graph.edgeCount} edges in ${graph.batches.length} batches; ` +
        `write ${writeMs} ms, CF-001 ${ruleMs} ms, ${hits.length} hits`,
    );
  }, 120_000);
});
