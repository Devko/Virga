import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { fromDurableObjectStorage, replaceExposure } from "@virga/graph";
import { beforeAll, describe, expect, it } from "vitest";
import type { AdminRpc, GraphReaderRpc } from "../../web/src/rpc.ts";
import type { AccountGraph } from "../src/account-graph.ts";
import { Admin } from "../src/admin.ts";
import { GraphReader } from "../src/graph-reader.ts";
import { d1ScanIndex } from "../src/index-db.ts";
import { type graphOf, newAccountId, rejection, setupAccount } from "./helpers.ts";

const reader = exports.GraphReader;
const accountId = newAccountId();
const SCAN = `scan-${accountId}-2026102907`;
const AT = Date.UTC(2026, 9, 29, 7, 17);

const finding = (fingerprint: string, severity: string, status: string, lastSeen = AT) => ({
  fingerprint,
  rule_id: fingerprint.split(":")[0],
  severity,
  status,
  last_seen: lastSeen,
});

// A small graph written through the regular write path, plus finding rows
// as the findings lifecycle (rules work package) would write them.
beforeAll(async () => {
  const { stub } = await setupAccount(accountId);
  await stub.beginScan(SCAN, "full", AT);
  await stub.writeChunk(
    SCAN,
    "workers",
    {
      nodes: [
        { type: "worker_route", nativeId: "r1", name: "api.example.com/*" },
        { type: "worker_script", nativeId: "api", name: "api", props: { workers_dev: false } },
        { type: "worker_script", nativeId: "web", name: "web" },
        { type: "worker_version", nativeId: "v1", props: { script_node_id: "worker_script:api" } },
        { type: "worker_version", nativeId: "v2", props: { script_node_id: "worker_script:web" } },
      ],
      edges: [
        { type: "ROUTES_TO", src: "worker_route:r1", dst: "worker_script:api" },
        {
          type: "DEPLOYS",
          src: "worker_script:api",
          dst: "worker_version:v1",
          props: { percentage: 100 },
        },
        {
          type: "DEPLOYS",
          src: "worker_script:web",
          dst: "worker_version:v2",
          props: { percentage: 100 },
        },
        {
          type: "BINDS",
          src: "worker_version:v1",
          dst: "d1_database:db1",
          key: "DB",
          props: { binding_type: "d1" },
        },
        {
          type: "BINDS",
          src: "worker_version:v1",
          dst: "kv_namespace:kv1",
          key: "CACHE",
          props: { binding_type: "kv_namespace" },
        },
        {
          type: "BINDS",
          src: "worker_version:v2",
          dst: "worker_script:api",
          key: "API",
          props: { binding_type: "service" },
        },
        {
          type: "BINDS",
          src: "worker_version:v1",
          dst: "r2_bucket:old",
          key: "OLD",
          props: { binding_type: "r2_bucket" },
        },
      ],
    },
    { singleChunk: true },
  );
  await stub.writeChunk(
    SCAN,
    "storage",
    { nodes: [{ type: "d1_database", nativeId: "db1", name: "main" }], edges: [] },
    { singleChunk: true },
  );
  await stub.recordCoverage(SCAN, "workers", "complete", { total: 1, done: 1 });
  await stub.recordCoverage(SCAN, "storage", "no_permission", { total: 1, done: 0 }, "403");

  await runInDurableObject(stub, (_: AccountGraph, state) => {
    const db = fromDurableObjectStorage(state.storage);
    db.run("UPDATE edges SET deleted_at = ? WHERE dst = 'r2_bucket:old'", AT);
    replaceExposure(db, [
      { entryId: "worker_route:r1", decision: "public", confidence: 2 },
      { entryId: "workers_dev:api.x.workers.dev", decision: "unknown", confidence: 0 },
    ]);
    const rows = [
      finding("CF-001:worker_script:api", "critical", "open"),
      finding("CF-002:worker_script:web", "high", "open"),
      finding("CF-003:r2_bucket:logs", "medium", "resolved"),
      finding("CF-010:access_app:x", "high", "suppressed"),
      finding("CF-002:worker_script:api", "high", "open"),
    ];
    for (const f of rows) {
      db.run(
        `INSERT INTO findings (fingerprint, rule_id, rule_version, severity, status, title, evidence,
           first_seen, last_seen, resolved_at)
         VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?)`,
        f.fingerprint,
        f.rule_id ?? "",
        f.severity,
        f.status,
        `title of ${f.rule_id}`,
        JSON.stringify({ hosts: ["api.example.com"] }),
        AT,
        f.last_seen,
        f.status === "resolved" ? AT : null,
      );
    }
    for (const [node, role] of [
      ["worker_script:api", "subject"],
      ["worker_route:r1", "entry"],
      ["d1_database:db1", "data"],
      ["kv_namespace:kv1", "data"],
    ] as const) {
      db.run(
        "INSERT INTO finding_nodes (fingerprint, node_id, role) VALUES (?, ?, ?)",
        "CF-001:worker_script:api",
        node,
        role,
      );
    }
    db.run(
      "INSERT INTO rule_runs (scan_id, rule_id, status, hits) VALUES (?, 'CF-001', 'evaluated', 1)",
      SCAN,
    );
  });
  await d1ScanIndex(env.INDEX).beginRun({ id: SCAN, accountId, startedAt: AT });
});

// The web Worker calls these entrypoints through mirrored types, because its
// service bindings are typed only as `Service`. This fails to compile when
// core's signatures drift from the mirror.
const WEB_MIRROR: [GraphReaderRpc, AdminRpc] = [reader, exports.Admin];

// RPC types turn a result that is not serializable for them into `never`,
// which callers would not notice. These fail to compile if that happens.
type Typed<T> = [T] extends [never] ? false : true;
type Stub = ReturnType<typeof graphOf>;
const RPC_TYPES: true[] = [
  true as Typed<Awaited<ReturnType<typeof reader.listAccounts>>>,
  true as Typed<Awaited<ReturnType<typeof reader.getScanSummary>>>,
  true as Typed<Awaited<ReturnType<typeof reader.listFindings>>>,
  true as Typed<Awaited<ReturnType<typeof reader.getFinding>>>,
  true as Typed<Awaited<ReturnType<typeof reader.getNeighborhood>>>,
  true as Typed<Awaited<ReturnType<typeof exports.Admin.addAccount>>>,
  true as Typed<Awaited<ReturnType<typeof exports.Admin.triggerScan>>>,
  true as Typed<Awaited<ReturnType<typeof exports.Admin.removeAccount>>>,
  true as Typed<Awaited<ReturnType<Stub["beginScan"]>>>,
  true as Typed<Awaited<ReturnType<Stub["writeChunk"]>>>,
  true as Typed<Awaited<ReturnType<Stub["sweep"]>>>,
  true as Typed<Awaited<ReturnType<Stub["computeExposure"]>>>,
  true as Typed<Awaited<ReturnType<Stub["evaluateRules"]>>>,
  true as Typed<Awaited<ReturnType<Stub["finishScan"]>>>,
  true as Typed<Awaited<ReturnType<Stub["scanSummary"]>>>,
];

describe("GraphReader", () => {
  it("has typed RPC results", () => {
    expect(RPC_TYPES.every(Boolean)).toBe(true);
    expect(WEB_MIRROR).toHaveLength(2);
  });

  it("exposes only its read methods over RPC", () => {
    // Every prototype method is callable over RPC, whatever its TypeScript visibility.
    expect(Object.getOwnPropertyNames(GraphReader.prototype).sort()).toEqual([
      "constructor",
      "getFinding",
      "getNeighborhood",
      "getScanSummary",
      "listAccounts",
      "listFindings",
    ]);
    expect(Object.getOwnPropertyNames(Admin.prototype).sort()).toEqual([
      "addAccount",
      "constructor",
      "removeAccount",
      "triggerScan",
    ]);
  });

  it("lists the accounts in the index in the shape the web Worker reads", async () => {
    const accounts = await reader.listAccounts();
    expect(accounts.find((a) => a.id === accountId)).toEqual({
      id: accountId,
      name: "Example Account Name",
      status: "active",
      cadenceHours: 24,
      profile: "inventory",
      createdAt: 1,
      lastScanAt: null,
    });
  });

  it("answers null for accounts that are not in the index, without creating a graph", async () => {
    const unknown = newAccountId();
    expect(await reader.getScanSummary(unknown)).toBeNull();
    expect(await reader.listFindings(unknown)).toBeNull();
    expect(await reader.getFinding(unknown, "CF-001:x")).toBeNull();
    expect(await reader.getNeighborhood(unknown, "worker_script:api")).toBeNull();
    expect(await rejection(reader.getScanSummary("not-an-account"))).toMatch(/invalid account ID/);
  });

  it("summarizes the latest scan, coverage, nodes, findings, exposure and rules", async () => {
    const summary = await reader.getScanSummary(accountId);
    expect(summary?.account).toMatchObject({ id: accountId, status: "active", cadenceHours: 24 });
    expect(summary?.lastRun).toMatchObject({ id: SCAN, status: "running", startedAt: AT });
    expect(summary?.graph).toEqual({
      scan: { id: SCAN, kind: "full", status: "running", startedAt: AT, finishedAt: null },
      coverage: [
        {
          resourceClass: "storage",
          status: "no_permission",
          chunksTotal: 1,
          chunksDone: 0,
          detail: "403",
        },
        {
          resourceClass: "workers",
          status: "complete",
          chunksTotal: 1,
          chunksDone: 1,
          detail: null,
        },
      ],
      nodes: { storage: 1, workers: 5 },
      findings: {
        open: { critical: 1, high: 2 },
        resolved: { medium: 1 },
        suppressed: { high: 1 },
      },
      exposure: { public: 1, unknown: 1 },
      rules: { evaluated: 1 },
    });
  });

  it("lists findings by severity in keyset pages", async () => {
    const pages: string[][] = [];
    let cursor: string | undefined;
    do {
      const page = await reader.listFindings(accountId, { limit: 2, cursor });
      pages.push(page?.findings.map((f) => f.fingerprint) ?? []);
      cursor = page?.cursor ?? undefined;
    } while (cursor);
    expect(pages).toEqual([
      ["CF-001:worker_script:api", "CF-002:worker_script:api"],
      ["CF-002:worker_script:web", "CF-010:access_app:x"],
      ["CF-003:r2_bucket:logs"],
    ]);

    const first = (await reader.listFindings(accountId, { limit: 1 }))?.findings[0];
    expect(first).toEqual({
      fingerprint: "CF-001:worker_script:api",
      ruleId: "CF-001",
      ruleVersion: 1,
      severity: "critical",
      status: "open",
      title: "title of CF-001",
      evidence: { hosts: ["api.example.com"] },
      insightId: null,
      firstSeen: AT,
      lastSeen: AT,
      resolvedAt: null,
      suppressedUntil: null,
    });
  });

  it("filters findings by status and severity", async () => {
    const fingerprints = async (filters: Parameters<typeof reader.listFindings>[1]) =>
      (await reader.listFindings(accountId, filters))?.findings.map((f) => f.fingerprint);
    expect(await fingerprints({ status: "open" })).toEqual([
      "CF-001:worker_script:api",
      "CF-002:worker_script:api",
      "CF-002:worker_script:web",
    ]);
    expect(
      await fingerprints({ severity: ["high", "medium"], status: ["resolved", "suppressed"] }),
    ).toEqual(["CF-010:access_app:x", "CF-003:r2_bucket:logs"]);
    const invalid = (filters: Parameters<typeof reader.listFindings>[1]) =>
      rejection(reader.listFindings(accountId, filters));
    expect(await invalid({ status: "closed" as "open" })).toMatch(/invalid status/);
    expect(await invalid({ severity: "urgent" as "high" })).toMatch(/invalid severity/);
    expect(await invalid({ limit: 201 })).toMatch(/limit/);
    expect(await invalid({ cursor: "9:x" })).toMatch(/cursor/);
  });

  it("returns a finding with its subject nodes", async () => {
    const detail = await reader.getFinding(accountId, "CF-001:worker_script:api");
    expect(detail?.subjects).toEqual([
      { nodeId: "d1_database:db1", role: "data" },
      { nodeId: "kv_namespace:kv1", role: "data" },
      { nodeId: "worker_route:r1", role: "entry" },
      { nodeId: "worker_script:api", role: "subject" },
    ]);
    // kv_namespace:kv1 has no node: its class has no coverage.
    expect(detail?.nodes.map((n) => n.id)).toEqual([
      "d1_database:db1",
      "worker_route:r1",
      "worker_script:api",
    ]);
    expect(detail?.nodes.find((n) => n.id === "worker_script:api")).toMatchObject({
      type: "worker_script",
      nativeId: "api",
      class: "workers",
      name: "api",
      props: { workers_dev: false },
      deletedAt: null,
    });
    expect(await reader.getFinding(accountId, "CF-999:none")).toBeNull();
  });

  it("returns the neighborhood of a node up to two hops", async () => {
    const one = await reader.getNeighborhood(accountId, "worker_script:api");
    expect(one?.nodes.map((n) => n.id)).toEqual([
      "worker_route:r1",
      "worker_script:api",
      "worker_version:v1",
      "worker_version:v2",
    ]);
    expect(one?.edges.map((e) => e.id)).toEqual([
      "BINDS:worker_version:v2->worker_script:api#API",
      "DEPLOYS:worker_script:api->worker_version:v1",
      "ROUTES_TO:worker_route:r1->worker_script:api",
    ]);
    expect(one).toMatchObject({
      root: "worker_script:api",
      depth: 1,
      missing: [],
      truncated: false,
    });

    const two = await reader.getNeighborhood(accountId, "worker_script:api", { depth: 2 });
    expect(two?.nodes.map((n) => n.id)).toEqual([
      "d1_database:db1",
      "worker_route:r1",
      "worker_script:api",
      "worker_script:web",
      "worker_version:v1",
      "worker_version:v2",
    ]);
    // The tombstoned binding to r2_bucket:old is not part of the live graph.
    expect(two?.missing).toEqual(["kv_namespace:kv1"]);
    expect(two?.edges).toHaveLength(6);
    expect(two?.edges.find((e) => e.key === "DB")).toMatchObject({
      type: "BINDS",
      src: "worker_version:v1",
      dst: "d1_database:db1",
      class: "workers",
      props: { binding_type: "d1" },
    });
  });

  it("cuts the neighborhood at the node limit and validates its options", async () => {
    const cut = await reader.getNeighborhood(accountId, "worker_script:api", {
      depth: 2,
      limit: 3,
    });
    expect(cut?.nodes).toHaveLength(3);
    expect(cut?.truncated).toBe(true);
    for (const edge of cut?.edges ?? []) {
      expect(cut?.nodes.some((n) => n.id === edge.src)).toBe(true);
      expect(cut?.nodes.some((n) => n.id === edge.dst)).toBe(true);
    }
    expect(await reader.getNeighborhood(accountId, "worker_script:nope")).toBeNull();
    const invalid = (options: { depth?: number; limit?: number }) =>
      rejection(reader.getNeighborhood(accountId, "worker_script:api", options));
    expect(await invalid({ depth: 3 })).toMatch(/depth/);
    expect(await invalid({ limit: 10_000 })).toMatch(/limit/);
  });
});
