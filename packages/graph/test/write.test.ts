import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  applyBatch,
  type Batch,
  beginScan,
  migrate,
  prepareBatch,
  recordCoverage,
  SCHEMA_VERSION,
  schemaVersion,
  sweep,
} from "../src/index.ts";
import { type NodeSqlRunner, openNodeDatabase } from "../src/node.ts";

let db: NodeSqlRunner;

beforeEach(() => {
  db = openNodeDatabase();
  migrate(db);
});
afterEach(() => db.close());

const batch = (scanId: string, x: number, withB = true): Batch => ({
  scanId,
  resourceClass: "workers",
  nodes: [
    { type: "worker_script", nativeId: "a", name: "a", props: { x } },
    ...(withB ? [{ type: "worker_script" as const, nativeId: "b", name: "b" }] : []),
  ],
  edges: withB
    ? [{ type: "BINDS", src: "worker_script:a", dst: "worker_script:b", key: "SVC" }]
    : [],
});

const write = async (b: Batch, at: number) => applyBatch(db, await prepareBatch(b, at));
const currentScan = () =>
  db.query<{ value: string }>("SELECT value FROM meta WHERE key = 'current_scan'")[0]?.value;
const count = (sql: string) => db.query<{ n: number }>(sql)[0]?.n;

describe("migrate", () => {
  it("is idempotent", () => {
    expect(schemaVersion(db)).toBe(SCHEMA_VERSION);
    expect(migrate(db)).toBe(SCHEMA_VERSION);
  });
});

describe("applyBatch", () => {
  it("creates rows and history", async () => {
    beginScan(db, { id: "s1", kind: "full", at: 1 });
    const result = await write(batch("s1", 1), 1000);
    expect(result).toEqual({ nodes: 2, edges: 1, changed: 3 });
    const ops = db.query("SELECT object_id, op FROM changes ORDER BY seq");
    expect(ops.map((r) => r.op)).toEqual(["create", "create", "create"]);
  });

  it("writes history only when content changes", async () => {
    beginScan(db, { id: "s1", kind: "full" });
    await write(batch("s1", 1), 1000);
    beginScan(db, { id: "s2", kind: "full" });
    const same = await write(batch("s2", 1), 2000);
    expect(same.changed).toBe(0);
    const a = db.query("SELECT changed_at, seen_scan FROM nodes WHERE id = 'worker_script:a'")[0];
    expect(a).toEqual({ changed_at: 1000, seen_scan: "s2" });

    beginScan(db, { id: "s3", kind: "full" });
    const changed = await write(batch("s3", 2), 3000);
    expect(changed.changed).toBe(1);
    const last = db.query(
      "SELECT op, scan_id, before, after FROM changes ORDER BY seq DESC LIMIT 1",
    )[0];
    expect(last?.op).toBe("update");
    expect(last?.scan_id).toBe("s3");
    expect(JSON.parse(String(last?.before)).props).toEqual({ x: 1 });
    expect(JSON.parse(String(last?.after)).props).toEqual({ x: 2 });
  });

  it("rejects unknown types and oversized values", async () => {
    await expect(
      prepareBatch({ ...batch("s", 1), nodes: [{ type: "nope" as never, nativeId: "x" }] }),
    ).rejects.toThrow(/unknown node type/);
    await expect(
      prepareBatch({ ...batch("s", 1), nodes: [{ type: "zone", nativeId: "z".repeat(600) }] }),
    ).rejects.toThrow(/nativeId/);
  });

  it("splits large batches into several statements", async () => {
    beginScan(db, { id: "s1", kind: "full" });
    const nodes = Array.from({ length: 3000 }, (_, i) => ({
      type: "dns_record" as const,
      nativeId: `r${i}`,
      props: { content: "x".repeat(800) },
    }));
    const result = await write({ scanId: "s1", resourceClass: "dns", nodes, edges: [] }, 1);
    expect(result.nodes).toBe(3000);
    expect(db.query("SELECT count(*) AS n FROM nodes")[0]?.n).toBe(3000);
  });
});

describe("sweep", () => {
  it("does nothing without complete coverage", async () => {
    beginScan(db, { id: "s1", kind: "full" });
    await write(batch("s1", 1), 1000);
    beginScan(db, { id: "s2", kind: "full" });
    await write(batch("s2", 1, false), 2000);
    recordCoverage(db, { scanId: "s2", resourceClass: "workers", status: "partial" });
    expect(sweep(db, "s2", "workers", 2500)).toEqual({ swept: false, nodes: 0, edges: 0 });
  });

  it("tombstones unseen rows and dangling edges, and restores them", async () => {
    beginScan(db, { id: "s1", kind: "full" });
    await write(batch("s1", 1), 1000);
    beginScan(db, { id: "s2", kind: "full" });
    await write(batch("s2", 1, false), 2000);
    recordCoverage(db, { scanId: "s2", resourceClass: "workers", status: "complete" });
    expect(sweep(db, "s2", "workers", 2500)).toEqual({ swept: true, nodes: 1, edges: 1 });
    expect(currentScan()).toBe("s2");

    const deleted = db.query(
      "SELECT object_id, scan_id FROM changes WHERE op = 'delete' ORDER BY object_id",
    );
    expect(deleted).toEqual([
      { object_id: "BINDS:worker_script:a->worker_script:b#SVC", scan_id: "s2" },
      { object_id: "worker_script:b", scan_id: "s2" },
    ]);

    beginScan(db, { id: "s3", kind: "full" });
    const back = await write(batch("s3", 1), 3000);
    expect(back.changed).toBe(2);
    expect(count("SELECT count(*) AS n FROM nodes WHERE deleted_at IS NOT NULL")).toBe(0);
    expect(db.query("SELECT op FROM changes ORDER BY seq DESC LIMIT 2").map((r) => r.op)).toEqual([
      "restore",
      "restore",
    ]);
  });

  it("never moves current_scan: a sweep of a scan that is not current is refused", async () => {
    beginScan(db, { id: "s1", kind: "full" });
    await write(batch("s1", 1), 1000);
    recordCoverage(db, { scanId: "s1", resourceClass: "workers", status: "complete" });
    beginScan(db, { id: "s2", kind: "full" });
    await write(batch("s2", 1, false), 2000);
    const changes = count("SELECT count(*) AS n FROM changes");

    // s1's sweep arrives late, for example from a retried step. It would
    // tombstone what s2 saw and attribute the deletes to s1.
    expect(() => sweep(db, "s1", "workers", 2500)).toThrow(/scan s1 is not the current scan/);
    expect(currentScan()).toBe("s2");
    expect(count("SELECT count(*) AS n FROM nodes WHERE deleted_at IS NOT NULL")).toBe(0);
    expect(count("SELECT count(*) AS n FROM changes")).toBe(changes);

    // s2's own sweep still attributes its deletes to s2.
    recordCoverage(db, { scanId: "s2", resourceClass: "workers", status: "complete" });
    expect(sweep(db, "s2", "workers", 3000)).toEqual({ swept: true, nodes: 1, edges: 1 });
    expect(db.query("SELECT DISTINCT scan_id FROM changes WHERE op = 'delete'")).toEqual([
      { scan_id: "s2" },
    ]);
    expect(currentScan()).toBe("s2");
  });

  it("refuses a sweep before any scan began", () => {
    recordCoverage(db, { scanId: "s1", resourceClass: "workers", status: "complete" });
    expect(() => sweep(db, "s1", "workers", 1000)).toThrow(/scan s1 is not the current scan/);
    expect(currentScan()).toBeUndefined();
  });
});

describe("replaceInsights", () => {
  it("upserts current insights and tombstones the rest", async () => {
    const { replaceInsights } = await import("../src/index.ts");
    const row = (id: string) => ({ id, type: "t", severity: "high", subjectId: null, payload: {} });
    replaceInsights(db, [row("i1"), row("i2")], 1);
    replaceInsights(db, [row("i2")], 2);
    const rows = db.query("SELECT id, first_seen, deleted_at FROM insights ORDER BY id");
    expect(rows).toEqual([
      { id: "i1", first_seen: 1, deleted_at: 2 },
      { id: "i2", first_seen: 1, deleted_at: null },
    ]);
  });
});
