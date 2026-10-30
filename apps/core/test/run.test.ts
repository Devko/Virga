import { env } from "cloudflare:workers";
import { createReader } from "@virga/cf-api";
import { type FixtureTransport, fixtureTransport } from "@virga/cf-api/testing";
import type { Collector } from "@virga/collectors";
import { evaluateExposure } from "@virga/exposure";
import { evaluateRules, RULES } from "@virga/rules";
import { describe, expect, it } from "vitest";
import { DEFAULT_EVALUATORS } from "../src/graph/evaluators.ts";
import { d1ScanIndex } from "../src/index-db.ts";
import { STALE_SCAN_MS } from "../src/scan/policy.ts";
import { runScan } from "../src/scan/run.ts";
import { fakeStep } from "./fake-step.ts";
import { type ApiState, apiRoutes, bucket, initialState, record, ZONE_A } from "./fixtures/api.ts";
import {
  type FakeEvaluators,
  fakeEvaluators,
  lastScanAt,
  newAccountId,
  scanRun,
  setupAccount,
  sql,
} from "./helpers.ts";
import { dnsStub, scriptedStub, serverError, storageStub } from "./stubs.ts";

const NOW = Date.UTC(2026, 9, 29, 7, 17);

interface Harness {
  accountId: string;
  state: ApiState;
  transports: FixtureTransport[];
  stub: Awaited<ReturnType<typeof setupAccount>>["stub"];
  evaluators: FakeEvaluators;
  /** Scan IDs are unique per test, since the tests in a file share the index. */
  id(name: string): string;
  scan(
    name: string,
    options?: {
      collectors?: readonly Collector[];
      now?: number;
      replay?: Map<string, unknown>;
      /** Runs before the step of that name. */
      before?: Record<string, () => Promise<unknown>>;
    },
  ): Promise<{
    summary: Awaited<ReturnType<typeof runScan>>;
    steps: ReturnType<typeof fakeStep>;
  }>;
}

async function harness(evaluators = fakeEvaluators()): Promise<Harness> {
  const accountId = newAccountId();
  const { stub } = await setupAccount(accountId, evaluators);
  const state = initialState();
  const transports: FixtureTransport[] = [];
  const id = (name: string) => `${name}-${accountId}`;
  return {
    accountId,
    state,
    transports,
    stub,
    evaluators,
    id,
    async scan(name, options = {}) {
      const scanId = id(name);
      const steps = fakeStep(options.replay);
      const now = options.now ?? NOW;
      const before = options.before ?? {};
      const summary = await runScan(
        {
          step: {
            async do(name, config, callback) {
              await before[name]?.();
              return steps.step.do(name, config, callback);
            },
          },
          graph: () => stub,
          index: d1ScanIndex(env.INDEX),
          reader: (id) => {
            const transport = fixtureTransport(apiRoutes(id, state));
            transports.push(transport);
            return createReader(transport);
          },
          collectors: options.collectors ?? [dnsStub, storageStub],
          clock: () => now + 60_000,
        },
        { accountId, scanId, now },
      );
      return { summary, steps };
    },
  };
}

const coverage = (h: Harness, name: string) =>
  sql<{ resource_class: string; status: string; chunks_total: number; chunks_done: number }>(
    h.stub,
    `SELECT resource_class, status, chunks_total, chunks_done FROM coverage
     WHERE scan_id = ? ORDER BY resource_class`,
    h.id(name),
  );

const liveNodes = (h: Harness, type: string) =>
  sql<{ id: string }>(
    h.stub,
    "SELECT id FROM nodes WHERE type = ? AND deleted_at IS NULL ORDER BY id",
    type,
  ).then((rows) => rows.map((r) => r.id));

describe("runScan", () => {
  it("collects in chunks, records coverage per class and sweeps only complete classes", async () => {
    const h = await harness();
    const { summary, steps } = await h.scan("s1");

    // storage first: dns lists it in `after`.
    expect(steps.names()).toEqual([
      "begin",
      "plan:storage",
      "collect:storage:1",
      "coverage:storage",
      "plan:dns",
      "collect:dns:1",
      "collect:dns:2",
      "coverage:dns",
      "sweep:dns",
      "exposure",
      "rules",
      "finish",
    ]);
    expect(steps.record("collect:storage:1")?.attempts).toBe(1);

    expect(summary.status).toBe("partial");
    expect(summary.classes.dns).toMatchObject({
      status: "complete",
      chunks: 2,
      done: 2,
      nodes: 3,
      changed: 3,
      swept: { nodes: 0, edges: 0 },
    });
    expect(summary.classes.storage).toMatchObject({ status: "no_permission", chunks: 1, done: 0 });
    expect(summary.classes.storage?.detail).toMatch(/NoPermissionError: 403/);
    expect(summary.classes.storage?.swept).toBeUndefined();
    expect(summary.exposure).toEqual({ status: "complete", entries: 0, decisions: {} });
    expect(summary.rules).toMatchObject({
      status: "complete",
      rules: 2,
      evaluated: 1,
      hits: 2,
      undecided: 1,
    });
    expect(h.evaluators.calls).toEqual({ exposure: 1, rules: [h.id("s1")] });

    expect(await coverage(h, "s1")).toEqual([
      { resource_class: "dns", status: "complete", chunks_total: 2, chunks_done: 2 },
      { resource_class: "exposure", status: "complete", chunks_total: 0, chunks_done: 0 },
      { resource_class: "storage", status: "no_permission", chunks_total: 1, chunks_done: 0 },
    ]);
    expect(await liveNodes(h, "dns_record")).toEqual([
      "dns_record:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "dns_record:a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
      "dns_record:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
    ]);
    const scans = await sql(h.stub, "SELECT status, started_at, finished_at FROM scans");
    expect(scans).toEqual([{ status: "complete", started_at: NOW, finished_at: NOW + 60_000 }]);

    const run = await scanRun(h.id("s1"));
    expect(run).toMatchObject({ status: "partial", started_at: NOW, finished_at: NOW + 60_000 });
    expect(JSON.parse(run?.summary ?? "{}")).toMatchObject({
      status: "partial",
      scanId: h.id("s1"),
    });
    expect(await lastScanAt(h.accountId)).toBe(NOW);
  });

  it("returns only counters from steps", async () => {
    const h = await harness();
    const { steps } = await h.scan("s1");
    for (const record of steps.records) {
      // The plan carries chunk units (here zone IDs); everything else is counters.
      const max = record.name.startsWith("plan:") ? 4096 : 1024;
      expect(record.bytes, record.name).toBeLessThan(max);
      expect(JSON.stringify(record.result ?? null)).not.toContain("198.51.100");
    }
    expect(steps.record("plan:dns")?.result).toEqual({
      status: "ok",
      chunks: [["023e105f4ecef8ad9ca31a8372d0c353"], ["372e67954025e0ba6aaa6d586b9e0b59"]],
    });
    expect(steps.record("collect:dns:1")?.result).toEqual({
      status: "ok",
      nodes: 2,
      edges: 0,
      changed: 2,
      signals: 0,
      insights: 0,
    });
  });

  it("keeps rows of classes that were not complete and tombstones what a complete class lost", async () => {
    const h = await harness();
    h.state.buckets = [bucket("logs"), bucket("assets")];
    const first = await h.scan("s1");
    expect(first.summary.status).toBe("complete");
    expect(await liveNodes(h, "r2_bucket")).toEqual(["r2_bucket:assets", "r2_bucket:logs"]);

    // The token loses R2 read, and a DNS record is deleted.
    h.state.buckets = "forbidden";
    h.state.records[ZONE_A] = h.state.records[ZONE_A]?.slice(0, 1) ?? [];
    const second = await h.scan("s2", { now: NOW + 3_600_000 });

    expect(second.steps.names()).toContain("sweep:dns");
    expect(second.steps.names()).not.toContain("sweep:storage");
    expect(second.summary.classes.dns?.swept).toEqual({ nodes: 1, edges: 0 });
    expect(await liveNodes(h, "r2_bucket")).toEqual(["r2_bucket:assets", "r2_bucket:logs"]);
    expect(await liveNodes(h, "dns_record")).toEqual([
      "dns_record:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "dns_record:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
    ]);
    expect(await lastScanAt(h.accountId)).toBe(NOW + 3_600_000);
  });

  it("retries other errors, then records error or partial coverage without a sweep", async () => {
    const h = await harness();
    const node = { type: "worker_script" as const, nativeId: "api", name: "api" };
    const workers = scriptedStub("workers", [{ nodes: [node], edges: [] }, serverError("/x")]);
    const pages = scriptedStub("pages", [serverError("/y")]);
    const { summary, steps } = await h.scan("s1", { collectors: [workers, pages] });

    // API_STEP allows 3 retries: 4 attempts in all.
    expect(steps.record("collect:workers:2")?.attempts).toBe(4);
    expect(steps.record("collect:pages:1")?.attempts).toBe(4);
    expect(workers.calls).toEqual([0, 1, 1, 1, 1]);
    expect(summary.classes.workers).toMatchObject({ status: "partial", chunks: 2, done: 1 });
    expect(summary.classes.workers?.detail).toMatch(/500/);
    expect(summary.classes.pages).toMatchObject({ status: "error", chunks: 1, done: 0 });
    expect(steps.names().filter((n) => n.startsWith("sweep:"))).toEqual([]);
    expect(await coverage(h, "s1")).toEqual([
      { resource_class: "exposure", status: "complete", chunks_total: 0, chunks_done: 0 },
      { resource_class: "pages", status: "error", chunks_total: 1, chunks_done: 0 },
      { resource_class: "workers", status: "partial", chunks_total: 2, chunks_done: 1 },
    ]);
    expect(await liveNodes(h, "worker_script")).toEqual(["worker_script:api"]);
  });

  it("does not retry errors a retry cannot fix", async () => {
    const h = await harness();
    // Unknown node type: rejected by the write path inside the graph object.
    const invalid = scriptedStub("zones", [
      { nodes: [{ type: "no_such_type" as "zone", nativeId: "x" }], edges: [] },
    ]);
    // A path that is not on the read allowlist: the broker (here the fixture) refuses it.
    const offList: Collector<never> = {
      resourceClass: "members",
      permissions: [],
      plan: async () => [[]],
      collect: async (ctx) => {
        await ctx.api.get(`/accounts/${ctx.accountId}/members/x/roles`);
        return { nodes: [], edges: [] };
      },
    };
    const { summary, steps } = await h.scan("s1", { collectors: [invalid, offList] });
    expect(steps.record("collect:zones:1")?.attempts).toBe(1);
    expect(steps.record("collect:members:1")?.attempts).toBe(1);
    expect(summary.classes.zones).toMatchObject({ status: "error" });
    expect(summary.classes.zones?.detail).toMatch(/TypeError: unknown node type/);
    expect(summary.classes.members?.detail).toMatch(/NotAllowedError/);
  });

  it("writes signals, and insights only from a single-chunk class", async () => {
    const h = await harness();
    const insight = {
      id: "i-1",
      type: "exposed_infrastructure",
      severity: "Moderate",
      subjectId: null,
      payload: { issue_type: "exposed_infrastructure" },
    };
    const traffic = scriptedStub("traffic", [
      {
        nodes: [],
        edges: [],
        signals: [{ nodeId: "worker_script:api", name: "invocations_30d", value: 42 }],
      },
    ]);
    const insights = scriptedStub("insights", [{ nodes: [], edges: [], insights: [insight] }]);
    const first = await h.scan("s1", { collectors: [traffic, insights] });
    expect(first.summary.classes.traffic).toMatchObject({ status: "complete", signals: 1 });
    expect(first.summary.classes.insights).toMatchObject({ status: "complete", insights: 1 });
    expect(await sql(h.stub, "SELECT node_id, name, value FROM signals")).toEqual([
      { node_id: "worker_script:api", name: "invocations_30d", value: 42 },
    ]);
    expect(await sql(h.stub, "SELECT id, deleted_at FROM insights")).toEqual([
      { id: "i-1", deleted_at: null },
    ]);

    const split = scriptedStub("insights", [
      { nodes: [], edges: [], insights: [insight] },
      { nodes: [], edges: [], insights: [] },
    ]);
    const second = await h.scan("s2", { collectors: [split], now: NOW + 1 });
    expect(second.summary.classes.insights).toMatchObject({ status: "error", done: 0 });
    expect(second.summary.classes.insights?.detail).toMatch(/single chunk/);
    expect(await sql(h.stub, "SELECT id, deleted_at FROM insights")).toEqual([
      { id: "i-1", deleted_at: null },
    ]);
  });

  it("records an exposure failure as coverage error and still runs the rules", async () => {
    const h = await harness(
      fakeEvaluators({
        exposure: () => {
          throw new Error("unsupported expression");
        },
      }),
    );
    const { summary, steps } = await h.scan("s1");
    expect(steps.record("exposure")?.attempts).toBe(1);
    expect(summary.exposure).toMatchObject({
      status: "error",
      detail: "Error: unsupported expression",
    });
    expect(summary.rules?.status).toBe("complete");
    expect(summary.status).toBe("partial");
    const rows = await coverage(h, "s1");
    expect(rows.find((r) => r.resource_class === "exposure")?.status).toBe("error");
  });

  it("fails the scan when the rules cannot run", async () => {
    const h = await harness(
      fakeEvaluators({
        rules: () => {
          throw new Error("rules broke");
        },
      }),
    );
    const { summary } = await h.scan("s1");
    expect(summary.status).toBe("failed");
    expect(summary.rules).toMatchObject({ status: "error", detail: "Error: rules broke" });
    expect(await sql(h.stub, "SELECT status FROM scans")).toEqual([{ status: "failed" }]);
    expect((await scanRun(h.id("s1")))?.status).toBe("failed");
  });

  it("skips while another scan of the account runs, and takes over a stale one", async () => {
    const h = await harness();
    await h.stub.beginScan("other", "full", NOW - 60_000);
    const skipped = await h.scan("s1");
    expect(skipped.summary).toMatchObject({ status: "skipped", running: "other" });
    expect(skipped.steps.names()).toEqual(["begin"]);
    expect(await scanRun(h.id("s1"))).toBeNull();

    const later = await h.scan("s2", { now: NOW - 60_000 + STALE_SCAN_MS + 1 });
    expect(later.summary.status).toBe("partial");
    expect(await sql(h.stub, "SELECT id, status FROM scans ORDER BY started_at")).toEqual([
      { id: "other", status: "failed" },
      { id: h.id("s2"), status: "complete" },
    ]);
  });

  it("R2-07: a scan marked failed as stale stops at its next write, without coverage, sweep, exposure or rules", async () => {
    const h = await harness();
    // While A collects its second chunk, it has run for more than 12 hours
    // and the next scan of the account takes over.
    const workers: Collector<number> = {
      resourceClass: "workers",
      permissions: [],
      plan: async () => [[1], [2]],
      async collect(_ctx, [i]) {
        if (i === 2) {
          expect(await h.stub.beginScan(h.id("B"), "full", NOW + STALE_SCAN_MS + 1)).toEqual({
            started: true,
          });
        }
        return { nodes: [{ type: "worker_script", nativeId: `w${i}`, name: `w${i}` }], edges: [] };
      },
    };
    const { summary, steps } = await h.scan("A", { collectors: [workers, dnsStub] });

    expect(steps.names()).toEqual([
      "begin",
      "plan:workers",
      "collect:workers:1",
      "collect:workers:2",
      "finish",
    ]);
    expect(steps.record("collect:workers:2")?.attempts).toBe(1);
    expect(summary).toMatchObject({ status: "failed", finishedAt: NOW + 60_000 });
    expect(summary.detail).toMatch(/StaleScanError: scan A-[0-9a-f]+ is not the running scan/);
    expect(summary.classes.workers).toMatchObject({ chunks: 2, done: 1 });
    expect(summary.classes.dns).toBeUndefined();
    expect(h.evaluators.calls).toEqual({ exposure: 0, rules: [] });
    expect(await sql(h.stub, "SELECT id, seen_scan FROM nodes")).toEqual([
      { id: "worker_script:w1", seen_scan: h.id("A") },
    ]);
    expect(await sql(h.stub, "SELECT count(*) AS n FROM coverage")).toEqual([{ n: 0 }]);
    expect(await sql(h.stub, "SELECT id, status FROM scans ORDER BY started_at")).toEqual([
      { id: h.id("A"), status: "failed" },
      { id: h.id("B"), status: "running" },
    ]);
    const run = await scanRun(h.id("A"));
    expect(run).toMatchObject({ status: "failed", finished_at: NOW + 60_000 });
    expect(JSON.parse(run?.summary ?? "{}")).toMatchObject({ status: "failed" });
  });

  it("R2-07: a scan marked failed as stale before its finish step ends failed in the index too", async () => {
    const h = await harness();
    const takeover = () => h.stub.beginScan(h.id("B"), "full", NOW + STALE_SCAN_MS + 1);
    const { summary } = await h.scan("A", { before: { finish: takeover } });
    expect(summary.rules?.status).toBe("complete");
    expect(summary.status).toBe("failed");
    expect(summary.detail).toMatch(/marked failed as stale/);
    expect(await sql(h.stub, "SELECT id, status FROM scans ORDER BY started_at")).toEqual([
      { id: h.id("A"), status: "failed" },
      { id: h.id("B"), status: "running" },
    ]);
    expect((await scanRun(h.id("A")))?.status).toBe("failed");
  });

  it("R2-07: a superseded scan that runs again writes nothing and keeps its index row", async () => {
    const h = await harness();
    const first = await h.scan("A");
    expect(first.summary.status).toBe("partial");
    // B sees a record that A did not.
    const extra = record("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3", "new.example.com", "198.51.100.6");
    h.state.records[ZONE_A]?.push(extra);
    await h.scan("B", { now: NOW + 3_600_000 });

    // A's instance runs again from the start, for example restarted by hand.
    const again = await h.scan("A");
    expect(again.steps.names()).toEqual([
      "begin",
      "plan:storage",
      "collect:storage:1",
      "coverage:storage",
      "finish",
    ]);
    expect(again.summary.status).toBe("failed");
    expect(again.summary.detail).toMatch(/StaleScanError/);
    expect(await liveNodes(h, "dns_record")).toEqual([
      "dns_record:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
      "dns_record:a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
      "dns_record:a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
      "dns_record:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
    ]);
    expect(await sql(h.stub, "SELECT id, status FROM scans ORDER BY started_at")).toEqual([
      { id: h.id("A"), status: "complete" },
      { id: h.id("B"), status: "complete" },
    ]);
    expect(await scanRun(h.id("A"))).toMatchObject({
      status: "partial",
      finished_at: NOW + 60_000,
    });
    expect(JSON.parse((await scanRun(h.id("A")))?.summary ?? "{}").status).toBe("partial");
    expect(await lastScanAt(h.accountId)).toBe(NOW + 3_600_000);
  });

  it("replays to the same steps without repeating work", async () => {
    const h = await harness();
    const first = await h.scan("s1");
    const calls = h.transports.length;
    const replay = await h.scan("s1", { replay: first.steps.results });
    expect(replay.steps.names()).toEqual(first.steps.names());
    expect(replay.summary).toEqual(first.summary);
    expect(h.transports.length).toBe(calls);
  });

  it("is retry-safe when a step runs twice", async () => {
    const h = await harness();
    await h.scan("s1");
    // As if the begin and finish steps of s1 ran again after a lost result.
    expect(await h.stub.beginScan(h.id("s1"), "full", NOW)).toEqual({ started: true });
    await d1ScanIndex(env.INDEX).beginRun({
      id: h.id("s1"),
      accountId: h.accountId,
      startedAt: NOW,
    });
    expect((await scanRun(h.id("s1")))?.status).toBe("partial");
  });
});

describe("default wiring", () => {
  it("uses the real exposure evaluator and findings lifecycle over all rules", () => {
    expect(DEFAULT_EVALUATORS.exposure).toBe(evaluateExposure);
    expect(DEFAULT_EVALUATORS.rules).toBe(evaluateRules);
    expect(DEFAULT_EVALUATORS.ruleSet).toBe(RULES);
  });
});
