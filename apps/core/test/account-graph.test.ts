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
