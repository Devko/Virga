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
import { STALE_SCAN_MS } from "../src/scan/policy.ts";
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
    await stub.finishScan("s1", "complete");
    expect(await stub.beginScan("s2", "full")).toEqual({ started: true });
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

  it("0005: returns the reasons a chunk gives for resources it left out", async () => {
    const stub = freshGraph();
    await stub.beginScan("s1", "full", 1);
    const tunnel = { type: "tunnel" as const, nativeId: "t1", name: "edge" };
    const reasons = ["tunnel t1: ingress has more than 1000 entry points"];
    expect(
      await stub.writeChunk(
        "s1",
        "tunnels",
        { nodes: [tunnel], edges: [], truncated: reasons },
        { singleChunk: false },
      ),
    ).toEqual({ nodes: 1, edges: 0, changed: 1, signals: 0, insights: 0, truncated: reasons });
    // Nothing left out: the counters stay as they were.
    expect(
      await stub.writeChunk(
        "s1",
        "tunnels",
        { nodes: [tunnel], edges: [], truncated: [] },
        { singleChunk: false },
      ),
    ).toEqual({ nodes: 1, edges: 0, changed: 0, signals: 0, insights: 0 });
  });

  it("0005: rejects truncated reasons that are not short strings, or too many", async () => {
    const stub = freshGraph();
    await stub.beginScan("s1", "full", 1);
    const write = (truncated: unknown) =>
      failure(
        stub.writeChunk(
          "s1",
          "tunnels",
          { nodes: [{ type: "tunnel", nativeId: "t1" }], edges: [], truncated } as never,
          { singleChunk: true },
        ),
      );
    expect(await write("tunnel t1")).toMatch(/TypeError: truncated must be an array/);
    expect(await write([42])).toMatch(/TypeError: truncated reason must be a string/);
    expect(await write([""])).toMatch(/TypeError: truncated reason must be a string/);
    expect(await write(["x".repeat(1025)])).toMatch(
      /RangeError: truncated reason longer than 1024 characters/,
    );
    expect(await write(Array.from({ length: 101 }, (_, i) => `tunnel t${i}`))).toMatch(
      /RangeError: more than 100 truncated reasons/,
    );
    // A refused chunk writes nothing.
    expect(await rows(stub, "SELECT count(*) AS n FROM nodes")).toEqual([{ n: 0 }]);
    // At the limits it is accepted.
    const most = Array.from({ length: 100 }, (_, i) => `${i}`.padEnd(1024, "x"));
    expect(await write(most)).toBe("resolved");
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
    const run = (
      ruleId: string,
      status: "evaluated" | "not_evaluated" | "error",
      hits = 0,
      undecided = 0,
    ) => ({
      ruleId,
      status,
      hits,
      undecided,
      missing: [],
      opened: hits,
      resolved: status === "evaluated" ? 1 : 0,
    });
    await useEvaluators(stub, {
      rules: () => [
        run("CF-001", "evaluated", 2, 1),
        run("CF-002", "not_evaluated"),
        run("CF-003", "error"),
        run("CF-004", "evaluated", 0, 3),
      ],
    });
    expect(await stub.evaluateRules("s1")).toEqual({
      status: "complete",
      rules: 4,
      evaluated: 2,
      notEvaluated: 1,
      errors: 1,
      hits: 2,
      undecided: 4,
      opened: 2,
      resolved: 2,
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

describe("writes from a scan that is not the running scan", () => {
  const hostname = {
    type: "tunnel_hostname" as const,
    nativeId: "t1:ssh.example.com",
    name: "ssh.example.com",
  };
  const chunk = { nodes: [hostname], edges: [] };
  const once = { singleChunk: true };
  const refused = /StaleScanError: scan A is not the running scan/;

  /** Every scan-scoped write of scan A, each expected to be refused. */
  const writesOfA = (stub: Stub) => [
    failure(stub.writeChunk("A", "tunnels", chunk, once)),
    failure(stub.applyBatch({ scanId: "A", resourceClass: "tunnels", ...chunk })),
    failure(stub.recordCoverage("A", "tunnels", "complete")),
    failure(stub.sweep("A", "tunnels")),
    failure(stub.computeExposure("A")),
    failure(stub.evaluateRules("A")),
  ];

  it("R2-07: refuses every write of a scan marked failed as stale, so the newer scan's sweep keeps live nodes", async () => {
    const stub = freshGraph();
    await stub.beginScan("A", "full", 1_000);
    // A runs for more than 12 hours; the next scan marks it failed and takes over.
    expect(await stub.beginScan("B", "full", 1_000 + STALE_SCAN_MS + 1)).toEqual({ started: true });
    await stub.writeChunk("B", "tunnels", chunk, once);

    // A's instance is still running and retries a chunk, then goes on.
    for (const write of writesOfA(stub)) expect(await write).toMatch(refused);

    await stub.recordCoverage("B", "tunnels", "complete");
    expect(await stub.sweep("B", "tunnels")).toEqual({ swept: true, nodes: 0, edges: 0 });
    expect(await rows(stub, "SELECT id, seen_scan, deleted_at FROM nodes")).toEqual([
      { id: "tunnel_hostname:t1:ssh.example.com", seen_scan: "B", deleted_at: null },
    ]);
    expect(await rows(stub, "SELECT DISTINCT scan_id FROM coverage")).toEqual([{ scan_id: "B" }]);
    expect(await rows(stub, "SELECT count(*) AS n FROM rule_runs")).toEqual([{ n: 0 }]);
    expect(await rows(stub, "SELECT value FROM meta WHERE key = 'current_scan'")).toEqual([
      { value: "B" },
    ]);
    // Finishing A changes nothing: it stays failed.
    expect(await stub.finishScan("A", "complete", 2_000)).toBe("failed");
    expect(await rows(stub, "SELECT id, status FROM scans ORDER BY started_at")).toEqual([
      { id: "A", status: "failed" },
      { id: "B", status: "running" },
    ]);
  });

  it("R2-07: refuses writes of a scan that a newer scan superseded, ended or still marked running", async () => {
    const stub = freshGraph();
    await stub.beginScan("A", "full", 1_000);
    await stub.writeChunk("A", "tunnels", chunk, once);
    expect(await stub.finishScan("A", "complete", 2_000)).toBe("complete");
    await stub.beginScan("B", "full", 3_000);
    await stub.writeChunk("B", "tunnels", chunk, once);

    // A's instance runs again, for example restarted by hand.
    for (const write of writesOfA(stub)) expect(await write).toMatch(refused);
    expect(await stub.finishScan("A", "failed", 4_000)).toBe("complete");

    // A row still marked running while another scan is current, as the sweep
    // of the round 1 write path could leave it.
    await rows(stub, "UPDATE scans SET status = 'running', finished_at = NULL WHERE id = 'A'");
    for (const write of writesOfA(stub)) expect(await write).toMatch(refused);
    expect(await stub.finishScan("A", "complete", 4_000)).toBe("failed");

    // A scan the graph has never seen is refused as well.
    expect(await failure(stub.recordCoverage("Z", "tunnels", "complete"))).toMatch(
      /StaleScanError: scan Z/,
    );
    expect(await rows(stub, "SELECT id, seen_scan, deleted_at FROM nodes")).toEqual([
      { id: "tunnel_hostname:t1:ssh.example.com", seen_scan: "B", deleted_at: null },
    ]);
    expect(await rows(stub, "SELECT id, status FROM scans ORDER BY started_at")).toEqual([
      { id: "A", status: "failed" },
      { id: "B", status: "running" },
    ]);
  });

  it("finishes the current scan once and answers a retried finish with its status", async () => {
    const stub = freshGraph();
    await stub.beginScan("A", "full", 1_000);
    expect(await stub.finishScan("A", "complete", 2_000)).toBe("complete");
    expect(await stub.finishScan("A", "failed", 3_000)).toBe("complete");
    expect(await rows(stub, "SELECT status, finished_at FROM scans")).toEqual([
      { status: "complete", finished_at: 2_000 },
    ]);
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
