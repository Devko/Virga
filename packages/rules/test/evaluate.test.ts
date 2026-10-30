import {
  applyBatch,
  beginScan,
  type CoverageStatus,
  migrate,
  prepareBatch,
  recordCoverage,
  replaceInsights,
  type SqlRunner,
  sweep,
} from "@virga/graph";
import { type NodeSqlRunner, openNodeDatabase } from "@virga/graph/node";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evaluateRules } from "../src/evaluate.ts";
import type { CompiledRule, RuleSeverity } from "../src/types.ts";

/**
 * Flags every Worker script with `bad: true`; severity, a store and a note come
 * from props. A script with `unknown: true` is undecided.
 */
const RULE: CompiledRule = {
  id: "CF-900",
  version: 1,
  title: "Worker flagged as bad",
  severity: "high",
  kind: "posture",
  requires: ["workers"],
  params: {},
  enriches: null,
  sql: `SELECT 'CF-900' AS rule_id, 'CF-900:' || s.id AS fingerprint,
               COALESCE(s.props ->> '$.severity', 'high') AS severity, s.id AS subject_id,
               CASE WHEN s.props ->> '$.unknown' = 1 THEN 0 ELSE 1 END AS decided,
               json_array(s.props ->> '$.store') AS stores, s.props ->> '$.note' AS note,
               json_array(s.name) AS names
        FROM nodes s
        WHERE s.type = 'worker_script' AND s.deleted_at IS NULL AND s.props ->> '$.bad' = 1`,
  paramOrder: [],
};

const ruleWith = (id: string, sql: string, extra: Partial<CompiledRule> = {}): CompiledRule => ({
  ...RULE,
  id,
  sql,
  ...extra,
});

interface Script {
  name: string;
  bad?: boolean;
  unknown?: boolean;
  severity?: RuleSeverity;
  store?: string;
  note?: string;
}

async function scan(
  db: SqlRunner,
  id: string,
  at: number,
  scripts: Script[],
  status: CoverageStatus = "complete",
): Promise<void> {
  beginScan(db, { id, kind: "full", at });
  const batch = await prepareBatch(
    {
      scanId: id,
      resourceClass: "workers",
      nodes: scripts.map((s) => ({
        type: "worker_script",
        nativeId: s.name,
        name: s.name,
        props: {
          bad: s.bad ?? true,
          unknown: s.unknown ?? false,
          severity: s.severity ?? null,
          store: s.store ?? null,
          note: s.note ?? null,
        },
      })),
      edges: [],
    },
    at,
  );
  applyBatch(db, batch);
  recordCoverage(db, { scanId: id, resourceClass: "workers", status });
  sweep(db, id, "workers", at);
}

interface FindingRow {
  fingerprint: string;
  rule_id: string;
  rule_version: number;
  severity: string;
  status: string;
  title: string;
  evidence: string;
  insight_id: string | null;
  first_seen: number;
  last_seen: number;
  resolved_at: number | null;
  suppressed_until: number | null;
  suppressed_by: string | null;
  suppress_reason: string | null;
}

const A = "CF-900:worker_script:a";

let db: NodeSqlRunner;
beforeEach(() => {
  db = openNodeDatabase();
  migrate(db);
});
afterEach(() => db.close());

function finding(fingerprint = A): FindingRow {
  const row = db.query<FindingRow & Record<string, string | number | null>>(
    "SELECT * FROM findings WHERE fingerprint = ?",
    fingerprint,
  )[0];
  if (!row) throw new Error(`no finding ${fingerprint}`);
  return row;
}

const findingCount = () => db.query<{ n: number }>("SELECT count(*) AS n FROM findings")[0]?.n ?? 0;

const links = (fingerprint = A) =>
  db.query<{ node_id: string; role: string }>(
    "SELECT node_id, role FROM finding_nodes WHERE fingerprint = ? ORDER BY role, node_id",
    fingerprint,
  );

function suppress(until: number, fingerprint = A): void {
  db.run(
    `UPDATE findings SET status = 'suppressed', suppressed_until = ?, suppressed_by = 'alice',
       suppress_reason = 'accepted until the migration' WHERE fingerprint = ?`,
    until,
    fingerprint,
  );
}

describe("evaluateRules: opening and updating", () => {
  it("opens a finding with evidence, title and node links", async () => {
    await scan(db, "s1", 1000, [{ name: "a", store: "kv_namespace:k1", note: "first" }]);
    expect(evaluateRules(db, [RULE], "s1", 1000)).toEqual([
      {
        ruleId: "CF-900",
        status: "evaluated",
        hits: 1,
        undecided: 0,
        missing: [],
        opened: 1,
        resolved: 0,
      },
    ]);
    const f = finding();
    expect(f).toMatchObject({
      rule_id: "CF-900",
      rule_version: 1,
      severity: "high",
      status: "open",
      title: "Worker flagged as bad",
      insight_id: null,
      first_seen: 1000,
      last_seen: 1000,
      resolved_at: null,
    });
    expect(JSON.parse(f.evidence)).toEqual({
      stores: ["kv_namespace:k1"],
      note: "first",
      names: ["a"],
    });
    expect(links()).toEqual([
      { node_id: "kv_namespace:k1", role: "stores" },
      { node_id: "worker_script:a", role: "subject" },
    ]);
  });

  it("updates severity, evidence and node links and keeps first_seen", async () => {
    await scan(db, "s1", 1000, [{ name: "a", store: "kv_namespace:k1", note: "first" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    await scan(db, "s2", 2000, [{ name: "a", severity: "critical", note: "second" }]);
    const [run] = evaluateRules(db, [RULE], "s2", 2000);
    expect(run).toMatchObject({ status: "evaluated", hits: 1, opened: 0, resolved: 0 });
    const f = finding();
    expect(f).toMatchObject({
      severity: "critical",
      status: "open",
      first_seen: 1000,
      last_seen: 2000,
    });
    expect(JSON.parse(f.evidence)).toEqual({ stores: [null], note: "second", names: ["a"] });
    expect(links()).toEqual([{ node_id: "worker_script:a", role: "subject" }]);
  });

  it("refreshes title and rule version", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    evaluateRules(db, [{ ...RULE, version: 2, title: "Renamed" }], "s1", 1500);
    expect(finding()).toMatchObject({ rule_version: 2, title: "Renamed", last_seen: 1500 });
  });
});

describe("evaluateRules: coverage", () => {
  it("changes nothing and runs no query when coverage is incomplete", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    await scan(db, "s2", 2000, [], "partial");
    const needsExposure = ruleWith("CF-901", "SELECT * FROM no_such_table", {
      requires: ["workers", "exposure"],
    });
    expect(evaluateRules(db, [RULE, needsExposure], "s2", 2000)).toEqual([
      {
        ruleId: "CF-900",
        status: "not_evaluated",
        hits: 0,
        undecided: 0,
        missing: ["workers"],
        opened: 0,
        resolved: 0,
      },
      {
        ruleId: "CF-901",
        status: "not_evaluated",
        hits: 0,
        undecided: 0,
        missing: ["workers", "exposure"],
        opened: 0,
        resolved: 0,
      },
    ]);
    expect(finding()).toMatchObject({ status: "open", last_seen: 1000, resolved_at: null });
  });

  it("only counts coverage of the scan being evaluated", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    beginScan(db, { id: "s2", kind: "full", at: 2000 });
    const [run] = evaluateRules(db, [RULE], "s2", 2000);
    expect(run).toMatchObject({ status: "not_evaluated", missing: ["workers"] });
    expect(findingCount()).toBe(0);
  });

  it("treats derived inputs like resource classes", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    const needsExposure = ruleWith("CF-901", RULE.sql.replaceAll("CF-900", "CF-901"), {
      requires: ["workers", "exposure"],
    });
    expect(evaluateRules(db, [needsExposure], "s1", 1000)[0]?.status).toBe("not_evaluated");
    recordCoverage(db, { scanId: "s1", resourceClass: "exposure", status: "complete" });
    expect(evaluateRules(db, [needsExposure], "s1", 1100)[0]).toMatchObject({
      status: "evaluated",
      opened: 1,
    });
  });
});

describe("evaluateRules: resolve and reopen", () => {
  it("resolves a finding the rule no longer returns, then reopens it", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }, { name: "b" }]);
    evaluateRules(db, [RULE], "s1", 1000);

    await scan(db, "s2", 2000, [{ name: "a", bad: false }, { name: "b" }]);
    expect(evaluateRules(db, [RULE], "s2", 2000)[0]).toMatchObject({
      hits: 1,
      opened: 0,
      resolved: 1,
    });
    expect(finding()).toMatchObject({ status: "resolved", resolved_at: 2000, last_seen: 1000 });
    expect(finding("CF-900:worker_script:b")).toMatchObject({ status: "open", last_seen: 2000 });
    expect(links()).toEqual([{ node_id: "worker_script:a", role: "subject" }]);

    await scan(db, "s3", 3000, [{ name: "a" }, { name: "b" }]);
    expect(evaluateRules(db, [RULE], "s3", 3000)[0]).toMatchObject({ opened: 1, resolved: 0 });
    expect(finding()).toMatchObject({
      status: "open",
      resolved_at: null,
      first_seen: 1000,
      last_seen: 3000,
    });
  });

  it("resolves findings of deleted nodes", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    await scan(db, "s2", 2000, []);
    expect(evaluateRules(db, [RULE], "s2", 2000)[0]).toMatchObject({ hits: 0, resolved: 1 });
    expect(finding().status).toBe("resolved");
  });

  it("leaves resolved findings alone while they stay away", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    await scan(db, "s2", 2000, []);
    evaluateRules(db, [RULE], "s2", 2000);
    await scan(db, "s3", 3000, []);
    expect(evaluateRules(db, [RULE], "s3", 3000)[0]).toMatchObject({ resolved: 0 });
    expect(finding()).toMatchObject({ status: "resolved", resolved_at: 2000 });
  });
});

describe("evaluateRules: suppression", () => {
  beforeEach(async () => {
    await scan(db, "s1", 1000, [{ name: "a", note: "first" }]);
    evaluateRules(db, [RULE], "s1", 1000);
  });

  it("keeps an active suppression and refreshes the evidence", async () => {
    suppress(10_000);
    await scan(db, "s2", 2000, [{ name: "a", note: "second" }]);
    evaluateRules(db, [RULE], "s2", 2000);
    const f = finding();
    expect(f).toMatchObject({
      status: "suppressed",
      severity: "high",
      last_seen: 2000,
      suppressed_until: 10_000,
      suppressed_by: "alice",
      suppress_reason: "accepted until the migration",
    });
    expect(JSON.parse(f.evidence).note).toBe("second");
  });

  it("keeps the accepted severity while a suppressed finding gets less severe", async () => {
    suppress(10_000);
    await scan(db, "s2", 2000, [{ name: "a", severity: "medium" }]);
    evaluateRules(db, [RULE], "s2", 2000);
    expect(finding()).toMatchObject({ status: "suppressed", severity: "high" });
    // Back at the accepted level: no rise, the suppression holds.
    await scan(db, "s3", 3000, [{ name: "a", severity: "high" }]);
    evaluateRules(db, [RULE], "s3", 3000);
    expect(finding()).toMatchObject({ status: "suppressed", severity: "high" });
  });

  it("returns an expired suppression to open", async () => {
    suppress(1500);
    await scan(db, "s2", 2000, [{ name: "a" }]);
    expect(evaluateRules(db, [RULE], "s2", 2000)[0]).toMatchObject({ opened: 0 });
    expect(finding()).toMatchObject({
      status: "open",
      suppressed_until: null,
      suppressed_by: null,
      suppress_reason: null,
    });
  });

  it("ends a suppression early when the severity rises", async () => {
    suppress(10_000);
    await scan(db, "s2", 2000, [{ name: "a", severity: "critical" }]);
    evaluateRules(db, [RULE], "s2", 2000);
    expect(finding()).toMatchObject({
      status: "open",
      severity: "critical",
      suppressed_until: null,
      suppressed_by: null,
    });
  });

  it("resolves a suppressed finding the rule no longer returns", async () => {
    suppress(10_000);
    await scan(db, "s2", 2000, [{ name: "a", bad: false }]);
    expect(evaluateRules(db, [RULE], "s2", 2000)[0]).toMatchObject({ resolved: 1 });
    expect(finding()).toMatchObject({
      status: "resolved",
      resolved_at: 2000,
      suppressed_until: null,
    });
  });

  it("does not touch a suppression when the rule is not evaluated", async () => {
    suppress(1500);
    await scan(db, "s2", 2000, [], "no_permission");
    evaluateRules(db, [RULE], "s2", 2000);
    expect(finding()).toMatchObject({ status: "suppressed", suppressed_until: 1500 });
  });
});

describe("evaluateRules: undecided rows", () => {
  const ruleRun = (scanId: string) =>
    db.query(
      "SELECT status, hits, undecided FROM rule_runs WHERE scan_id = ? AND rule_id = 'CF-900'",
      scanId,
    );

  it("never opens a finding", async () => {
    await scan(db, "s1", 1000, [{ name: "a", unknown: true }]);
    expect(evaluateRules(db, [RULE], "s1", 1000)).toEqual([
      {
        ruleId: "CF-900",
        status: "evaluated",
        hits: 0,
        undecided: 1,
        missing: [],
        opened: 0,
        resolved: 0,
      },
    ]);
    expect(findingCount()).toBe(0);
    expect(links()).toEqual([]);
  });

  it("keeps an open finding open with its severity, evidence and node links", async () => {
    await scan(db, "s1", 1000, [{ name: "a", store: "kv_namespace:k1", note: "first" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    const before = finding();

    await scan(db, "s2", 2000, [{ name: "a", unknown: true, severity: "critical", note: "x" }]);
    expect(evaluateRules(db, [RULE], "s2", 2000)[0]).toMatchObject({
      status: "evaluated",
      hits: 0,
      undecided: 1,
      opened: 0,
      resolved: 0,
    });
    expect(finding()).toEqual(before);
    expect(before).toMatchObject({ status: "open", severity: "high", last_seen: 1000 });
    expect(links()).toEqual([
      { node_id: "kv_namespace:k1", role: "stores" },
      { node_id: "worker_script:a", role: "subject" },
    ]);
  });

  it("keeps a resolved finding resolved", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    await scan(db, "s2", 2000, [{ name: "a", bad: false }]);
    evaluateRules(db, [RULE], "s2", 2000);
    const before = finding();
    expect(before).toMatchObject({ status: "resolved", resolved_at: 2000 });

    await scan(db, "s3", 3000, [{ name: "a", unknown: true }]);
    expect(evaluateRules(db, [RULE], "s3", 3000)[0]).toMatchObject({
      hits: 0,
      undecided: 1,
      opened: 0,
      resolved: 0,
    });
    expect(finding()).toEqual(before);
  });

  it("keeps a suppression that lasts as it is, whatever the undecided row says", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    suppress(10_000);
    const before = finding();
    await scan(db, "s2", 2000, [{ name: "a", unknown: true, severity: "critical" }]);
    evaluateRules(db, [RULE], "s2", 2000);
    expect(finding()).toEqual(before);
    expect(before).toMatchObject({
      status: "suppressed",
      severity: "high",
      suppressed_by: "alice",
    });
  });

  it("R3-07: ends an expired suppression on an undecided row, keeping the finding's state", async () => {
    await scan(db, "s1", 1000, [{ name: "a", store: "kv_namespace:k1", note: "first" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    // "Adding Access this week": then exposure turns unknown and stays so.
    suppress(3000);
    const before = finding();
    const undecidedScan = async (id: string, at: number) => {
      await scan(db, id, at, [{ name: "a", unknown: true, severity: "critical", note: "x" }]);
      return evaluateRules(db, [RULE], id, at)[0];
    };

    await undecidedScan("s2", 2000);
    expect(finding()).toEqual(before);

    // Due at 3000 even though no decided row comes.
    expect(await undecidedScan("s3", 3000)).toMatchObject({
      status: "evaluated",
      hits: 0,
      undecided: 1,
      opened: 0,
      resolved: 0,
    });
    const reopened = {
      ...before,
      status: "open",
      suppressed_until: null,
      suppressed_by: null,
      suppress_reason: null,
    };
    expect(finding()).toEqual(reopened);
    expect(reopened).toMatchObject({ severity: "high", last_seen: 1000 });
    expect(JSON.parse(reopened.evidence).note).toBe("first");
    expect(links()).toEqual([
      { node_id: "kv_namespace:k1", role: "stores" },
      { node_id: "worker_script:a", role: "subject" },
    ]);

    await undecidedScan("s4", 5_000_000);
    expect(finding()).toEqual(reopened);

    await scan(db, "s5", 6_000_000, [{ name: "a" }]);
    expect(evaluateRules(db, [RULE], "s5", 6_000_000)[0]).toMatchObject({ hits: 1, opened: 0 });
    expect(finding()).toMatchObject({ status: "open", last_seen: 6_000_000 });
  });

  it("resolves the finding once the rule decides the fingerprint is gone", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    await scan(db, "s2", 2000, [{ name: "a", unknown: true }]);
    evaluateRules(db, [RULE], "s2", 2000);
    await scan(db, "s3", 3000, [{ name: "a", bad: false }]);
    expect(evaluateRules(db, [RULE], "s3", 3000)[0]).toMatchObject({ resolved: 1 });
    expect(finding()).toMatchObject({ status: "resolved", resolved_at: 3000, last_seen: 1000 });
  });

  it("counts only decided rows as hits, and updates the decided ones as usual", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }, { name: "b" }, { name: "c" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    await scan(db, "s2", 2000, [
      { name: "a", unknown: true },
      { name: "b", note: "second" },
      { name: "c", bad: false },
      { name: "d", unknown: true },
    ]);
    expect(evaluateRules(db, [RULE], "s2", 2000)[0]).toMatchObject({
      status: "evaluated",
      hits: 1,
      undecided: 2,
      opened: 0,
      resolved: 1,
    });
    expect(ruleRun("s2")).toEqual([{ status: "evaluated", hits: 1, undecided: 2 }]);
    expect(finding()).toMatchObject({ status: "open", last_seen: 1000 });
    expect(finding("CF-900:worker_script:b")).toMatchObject({ status: "open", last_seen: 2000 });
    expect(JSON.parse(finding("CF-900:worker_script:b").evidence).note).toBe("second");
    expect(finding("CF-900:worker_script:c")).toMatchObject({ status: "resolved" });
    expect(findingCount()).toBe(3);
  });

  it("does not store the decided column as evidence", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    evaluateRules(db, [RULE], "s1", 1000);
    expect(JSON.parse(finding().evidence)).not.toHaveProperty("decided");
  });
});

describe("evaluateRules: rule runs and errors", () => {
  const broken = ruleWith("CF-902", "SELECT * FROM no_such_table");

  it("records one rule_runs row per rule and scan", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }, { name: "b" }]);
    const needsExposure = ruleWith("CF-901", RULE.sql, { requires: ["exposure"] });
    const rules = [RULE, needsExposure, broken];
    evaluateRules(db, rules, "s1", 1000);
    evaluateRules(db, rules, "s1", 1100);
    expect(
      db.query(
        `SELECT scan_id, rule_id, status, hits, undecided, missing, error FROM rule_runs
         ORDER BY rule_id`,
      ),
    ).toEqual([
      {
        scan_id: "s1",
        rule_id: "CF-900",
        status: "evaluated",
        hits: 2,
        undecided: 0,
        missing: null,
        error: null,
      },
      {
        scan_id: "s1",
        rule_id: "CF-901",
        status: "not_evaluated",
        hits: 0,
        undecided: 0,
        missing: '["exposure"]',
        error: null,
      },
      {
        scan_id: "s1",
        rule_id: "CF-902",
        status: "error",
        hits: 0,
        undecided: 0,
        missing: null,
        error: "no such table: no_such_table",
      },
    ]);
  });

  it("stores the error of a failed run, capped at 500 characters, and clears it on the next run", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    const long = ruleWith("CF-900", `SELECT * FROM t_${"x".repeat(600)}`);
    const [run] = evaluateRules(db, [long], "s1", 1000);
    const stored = () =>
      db.query<{ status: string; error: string | null }>(
        "SELECT status, error FROM rule_runs WHERE scan_id = 's1' AND rule_id = 'CF-900'",
      )[0];
    expect(run?.error).toMatch(/^no such table: t_x+$/);
    expect(run?.error).toHaveLength(500);
    expect(stored()).toEqual({ status: "error", error: run?.error });

    evaluateRules(db, [RULE], "s1", 1100);
    expect(stored()).toEqual({ status: "evaluated", error: null });
  });

  it("keeps going after a rule fails and leaves that rule's findings alone", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    db.run(
      `INSERT INTO findings (fingerprint, rule_id, rule_version, severity, status, title, evidence,
         first_seen, last_seen) VALUES ('CF-902:worker_script:x', 'CF-902', 1, 'low', 'open', 't',
         '{}', 500, 500)`,
    );
    const [first, second] = evaluateRules(db, [broken, RULE], "s1", 1000);
    expect(first).toMatchObject({ ruleId: "CF-902", status: "error", hits: 0, resolved: 0 });
    expect(first?.error).toMatch(/no such table/);
    expect(second).toMatchObject({ ruleId: "CF-900", status: "evaluated", opened: 1 });
    expect(finding("CF-902:worker_script:x")).toMatchObject({ status: "open", last_seen: 500 });
    expect(finding().status).toBe("open");
  });

  const select = (columns: string) =>
    `SELECT ${columns} FROM nodes s WHERE s.type = 'worker_script' AND s.deleted_at IS NULL`;
  it.each([
    [
      "a wrong rule_id",
      select(
        "'CF-001' AS rule_id, 'CF-900:' || s.id AS fingerprint, 'high' AS severity, s.id AS subject_id",
      ),
    ],
    [
      "a fingerprint without the rule prefix",
      select("'CF-900' AS rule_id, s.id AS fingerprint, 'high' AS severity, s.id AS subject_id"),
    ],
    [
      "a fingerprint of another rule with a longer ID",
      select(
        "'CF-900' AS rule_id, 'CF-900b:' || s.id AS fingerprint, 'high' AS severity, s.id AS subject_id",
      ),
    ],
    [
      "duplicate fingerprints",
      select(
        "'CF-900' AS rule_id, 'CF-900:same' AS fingerprint, 'high' AS severity, s.id AS subject_id",
      ),
    ],
    [
      "an unknown severity",
      select(
        "'CF-900' AS rule_id, 'CF-900:' || s.id AS fingerprint, 'severe' AS severity, s.id AS subject_id",
      ),
    ],
    [
      "no subject_id column",
      select("'CF-900' AS rule_id, 'CF-900:' || s.id AS fingerprint, 'high' AS severity"),
    ],
    [
      "a subject that is not a node ID",
      select(
        "'CF-900' AS rule_id, 'CF-900:' || s.id AS fingerprint, 'high' AS severity, s.name AS subject_id",
      ),
    ],
    [
      "a decided value other than 0 or 1",
      select(
        "'CF-900' AS rule_id, 'CF-900:' || s.id AS fingerprint, 'high' AS severity, s.id AS subject_id, 2 AS decided",
      ),
    ],
    [
      "a NULL decided value",
      select(
        "'CF-900' AS rule_id, 'CF-900:' || s.id AS fingerprint, 'high' AS severity, s.id AS subject_id, NULL AS decided",
      ),
    ],
    [
      "a decided and an undecided row with one fingerprint",
      select(
        "'CF-900' AS rule_id, 'CF-900:same' AS fingerprint, 'high' AS severity, s.id AS subject_id, s.name = 'a' AS decided",
      ),
    ],
    [
      "a blob in the evidence",
      select(
        "'CF-900' AS rule_id, 'CF-900:' || s.id AS fingerprint, 'high' AS severity, s.id AS subject_id, x'00' AS raw",
      ),
    ],
  ])("is an error for %s, without writing findings", async (_, sql) => {
    await scan(db, "s1", 1000, [{ name: "a" }, { name: "b" }]);
    const [run] = evaluateRules(db, [ruleWith("CF-900", sql)], "s1", 1000);
    expect(run?.status).toBe("error");
    expect(run?.error).toMatch(/^CF-900: row \d+: /);
    expect(findingCount()).toBe(0);
  });

  it("keeps values of the scanned account out of error messages", async () => {
    await scan(db, "s1", 1000, [{ name: "secret-name" }]);
    const sql = select(
      "'CF-900' AS rule_id, 'CF-900:' || s.id AS fingerprint, s.name AS severity, s.id AS subject_id",
    );
    const [run] = evaluateRules(db, [ruleWith("CF-900", sql)], "s1", 1000);
    expect(run?.status).toBe("error");
    expect(run?.error).not.toContain("secret-name");
  });
});

describe("evaluateRules: evidence", () => {
  it("parses JSON arrays only, and links nodes only from lists of node IDs", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    const sql = `SELECT 'CF-900' AS rule_id, 'CF-900:' || s.id AS fingerprint, 'low' AS severity,
        s.id AS subject_id, '[not json' AS broken, '{"a":1}' AS object, 42 AS count,
        json_array('d1_database:db', NULL) AS stores,
        json_array('d1_database:db', 'example.com') AS mixed,
        json_array('nosuchtype:x') AS unknown_type,
        json_array() AS empty
      FROM nodes s WHERE s.type = 'worker_script'`;
    evaluateRules(db, [ruleWith("CF-900", sql)], "s1", 1000);
    expect(JSON.parse(finding().evidence)).toEqual({
      broken: "[not json",
      object: '{"a":1}',
      count: 42,
      stores: ["d1_database:db", null],
      mixed: ["d1_database:db", "example.com"],
      unknown_type: ["nosuchtype:x"],
      empty: [],
    });
    expect(links()).toEqual([
      { node_id: "d1_database:db", role: "stores" },
      { node_id: "worker_script:a", role: "subject" },
    ]);
  });

  it("caps lists at 100 items and strings at 2,048 characters", async () => {
    await scan(db, "s1", 1000, [{ name: "a" }]);
    const sql = `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 150)
      SELECT 'CF-900' AS rule_id, 'CF-900:' || s.id AS fingerprint, 'low' AS severity,
        s.id AS subject_id, (SELECT json_group_array('kv_namespace:k' || i) FROM n) AS stores,
        hex(zeroblob(1500)) AS long_text, json_array(hex(zeroblob(1500))) AS long_items
      FROM nodes s WHERE s.type = 'worker_script'`;
    evaluateRules(db, [ruleWith("CF-900", sql)], "s1", 1000);
    const evidence = JSON.parse(finding().evidence);
    expect(evidence.stores).toHaveLength(100);
    expect(evidence._truncated).toEqual({ stores: 150 });
    expect(evidence.long_text).toHaveLength(2048);
    expect(evidence.long_items[0]).toHaveLength(2048);
    expect(links()).toHaveLength(101);
  });

  it("links the insight a rule enriches through the finding's nodes", async () => {
    await scan(db, "s1", 1000, [{ name: "a", store: "kv_namespace:k1" }, { name: "b" }]);
    replaceInsights(
      db,
      [
        {
          id: "i-other",
          type: "other_type",
          severity: "Low",
          subjectId: "worker_script:b",
          payload: {},
        },
        {
          id: "i-store",
          type: "kv_type",
          severity: "Low",
          subjectId: "kv_namespace:k1",
          payload: {},
        },
        { id: "i-b", type: "kv_type", severity: "Low", subjectId: "worker_script:b", payload: {} },
      ],
      1000,
    );
    evaluateRules(db, [{ ...RULE, enriches: "kv_type" }], "s1", 1000);
    expect(finding().insight_id).toBe("i-store");
    expect(finding("CF-900:worker_script:b").insight_id).toBe("i-b");

    replaceInsights(db, [], 1500);
    evaluateRules(db, [{ ...RULE, enriches: "kv_type" }], "s1", 1500);
    expect(finding().insight_id).toBeNull();
  });
});
