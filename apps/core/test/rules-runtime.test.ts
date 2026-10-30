import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import {
  applyBatch,
  beginScan,
  fromDurableObjectStorage,
  prepareBatch,
  recordCoverage,
  type SqlRunner,
  sweep,
} from "@virga/graph";
import { type CompiledRule, evaluateRules } from "@virga/rules";
import { describe, expect, it } from "vitest";
import type { AccountGraph } from "../src/account-graph.ts";
import { DEFAULT_EVALUATORS } from "../src/graph/evaluators.ts";

/**
 * Rule runs on the Durable Object's SqlRunner (R6-02, run-time half). Durable
 * Object SQL runs every statement of a query, and the cursor's rowsWritten
 * counts only the last one, so a hidden statement must not reach the graph
 * in any position.
 */

const HIT_A =
  "SELECT 'CF-900' AS rule_id, 'CF-900:worker_script:a' AS fingerprint, 'high' AS severity, 'worker_script:a' AS subject_id";
const NO_HIT = `${HIT_A} WHERE 0`;

const rule = (sql: string): CompiledRule => ({
  id: "CF-900",
  version: 1,
  title: "Worker a",
  severity: "high",
  kind: "posture",
  requires: ["workers"],
  params: {},
  enriches: null,
  sql,
  paramOrder: [],
});

/** Scan s1 with Worker a and complete `workers` coverage, and the finding of Worker a open. */
async function seed(db: SqlRunner): Promise<void> {
  beginScan(db, { id: "s1", kind: "full", at: 1000 });
  const batch = await prepareBatch(
    {
      scanId: "s1",
      resourceClass: "workers",
      nodes: [{ type: "worker_script", nativeId: "a", name: "a" }],
      edges: [],
    },
    1000,
  );
  applyBatch(db, batch);
  recordCoverage(db, { scanId: "s1", resourceClass: "workers", status: "complete" });
  sweep(db, "s1", "workers", 1000);
  expect(evaluateRules(db, [rule(HIT_A)], "s1", 1000)[0]).toMatchObject({ opened: 1 });
}

/** What a rule run must leave as it was. */
const state = (db: SqlRunner) => ({
  meta: db.query("SELECT key, value FROM meta ORDER BY key"),
  schema: db.query("SELECT type, name FROM sqlite_schema ORDER BY type, name"),
  findings: db.query("SELECT fingerprint, status, last_seen, resolved_at FROM findings"),
  links: db.query("SELECT fingerprint, node_id, role FROM finding_nodes ORDER BY node_id"),
  settings: db.query("SELECT ignore_check_constraints AS icc FROM pragma_ignore_check_constraints"),
});

const freshGraph = () => env.ACCOUNT_GRAPH.get(env.ACCOUNT_GRAPH.newUniqueId());

describe("rule runs on Durable Object SQL (R6-02)", () => {
  it.each([
    [
      "the review's UPDATE after the SELECT",
      `${HIT_A} FROM (SELECT 1) AS [z--]; UPDATE meta SET value = 'forged' WHERE key = 'current_scan'`,
    ],
    [
      "an UPDATE before the SELECT, which rowsWritten does not count",
      `UPDATE meta SET value = 'forged' WHERE key = 'current_scan'; ${HIT_A}`,
    ],
    ["a DELETE of every finding", `DELETE FROM findings; ${NO_HIT}`],
    ["a new table", `CREATE TABLE planted (x); ${HIT_A}`],
    [
      "a trigger",
      `CREATE TRIGGER planted AFTER UPDATE ON findings BEGIN DELETE FROM finding_nodes; END; ${HIT_A}`,
    ],
    ["a connection setting", `PRAGMA ignore_check_constraints = 1; ${HIT_A}`],
    [
      "an UPDATE before a statement that fails",
      `UPDATE meta SET value = 'forged' WHERE key = 'current_scan'; SELECT * FROM no_such_table`,
    ],
  ])("R6-02: a two-statement rule with %s ends error and changes nothing", async (_, sql) => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      const before = state(db);
      const [run] = evaluateRules(db, [rule(sql)], "s1", 2000);
      expect(run).toMatchObject({ status: "error", hits: 0, opened: 0, resolved: 0 });
      expect(state(db)).toEqual(before);
      // Control: a rule that only reads still changes findings.
      expect(evaluateRules(db, [rule(NO_HIT)], "s1", 3000)[0]).toMatchObject({
        status: "evaluated",
        resolved: 1,
      });
    });
  });

  it("R6-02: the scan's rules step counts a writing rule as an error and keeps current_scan", async () => {
    await runInDurableObject(freshGraph(), async (graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      const before = state(db);
      graph.evaluators = {
        ...DEFAULT_EVALUATORS,
        ruleSet: [rule(`UPDATE meta SET value = 'forged' WHERE key = 'current_scan'; ${NO_HIT}`)],
      };
      expect(graph.evaluateRules("s1")).toMatchObject({
        status: "complete",
        rules: 1,
        evaluated: 0,
        errors: 1,
        resolved: 0,
      });
      expect(state(db)).toEqual(before);
      expect(db.query("SELECT status, error FROM rule_runs WHERE rule_id = 'CF-900'")).toEqual([
        { status: "error", error: expect.stringMatching(/^a read-only query changed rows/) },
      ]);
    });
  });
});

/**
 * The platform facts decision 0006 relies on. If a workerd upgrade changes
 * one, re-check the guard in packages/graph/src/sql.ts.
 */
describe("Durable Object SQL facts behind decision 0006", () => {
  it("runs every statement, counts rowsWritten for the last only, and total_changes() for all", async () => {
    await runInDurableObject(freshGraph(), (_graph: AccountGraph, durable) => {
      const sql = durable.storage.sql;
      const changes = () => sql.exec("SELECT total_changes() AS n").one().n as number;
      sql.exec("INSERT INTO meta (key, value) VALUES ('probe', 'a')");
      const before = changes();
      const cursor = sql.exec("UPDATE meta SET value = 'b' WHERE key = 'probe'; SELECT 1 AS one");
      expect(cursor.toArray()).toEqual([{ one: 1 }]);
      expect(cursor.rowsWritten).toBe(0);
      expect(changes() - before).toBe(1);
      expect(sql.exec("SELECT value FROM meta WHERE key = 'probe'").one()).toEqual({ value: "b" });
    });
  });

  it("refuses query_only, and keeps a changed setting through a rollback", async () => {
    await runInDurableObject(freshGraph(), (_graph: AccountGraph, durable) => {
      const { sql } = durable.storage;
      expect(() => sql.exec("PRAGMA query_only = 1")).toThrow(/not authorized/);
      const read = () =>
        sql.exec("SELECT ignore_check_constraints AS v FROM pragma_ignore_check_constraints").one();
      expect(read()).toEqual({ v: 0 });
      expect(() =>
        durable.storage.transactionSync(() => {
          sql.exec("PRAGMA ignore_check_constraints = 1");
          throw new Error("rollback");
        }),
      ).toThrow("rollback");
      expect(read()).toEqual({ v: 1 });
    });
  });
});
