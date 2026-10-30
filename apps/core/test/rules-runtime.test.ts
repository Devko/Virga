import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import {
  applyBatch,
  beginScan,
  fromDurableObjectStorage,
  guardRead,
  prepareBatch,
  ReadOnlyError,
  type Row,
  recordCoverage,
  replaceExposure,
  type SqlRunner,
  sweep,
} from "@virga/graph";
import { type CompiledRule, evaluateRules, RULES } from "@virga/rules";
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

/**
 * Scan s1 with Worker a and complete `workers` coverage, the finding of
 * Worker a open, and one exposure row.
 */
async function seed(db: SqlRunner): Promise<void> {
  beginScan(db, { id: "s1", kind: "full", at: 1000 });
  replaceExposure(db, [{ entryId: "route:r1", decision: "public", confidence: 2 }], 1000);
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

/** Connection settings a statement can change, read with statements a view cannot shadow. */
const SETTING_NAMES = [
  "ignore_check_constraints",
  "recursive_triggers",
  "reverse_unordered_selects",
  "legacy_alter_table",
  "defer_foreign_keys",
];
const settings = (db: SqlRunner) => ({
  ...Object.fromEntries(SETTING_NAMES.map((name) => [name, db.query(`PRAGMA ${name}`)[0]?.[name]])),
  case_sensitive_like: db.query("SELECT NOT ('a' LIKE 'A') AS v")[0]?.v,
});

/** What a rule run must leave as it was. */
const state = (db: SqlRunner) => ({
  meta: db.query("SELECT key, value FROM meta ORDER BY key"),
  schema: db.query("SELECT type, name, sql FROM sqlite_schema ORDER BY type, name"),
  findings: db.query("SELECT fingerprint, status, last_seen, resolved_at FROM findings"),
  links: db.query("SELECT fingerprint, node_id, role FROM finding_nodes ORDER BY node_id"),
  exposure: db.query("SELECT entry_id, decision FROM exposure"),
  settings: settings(db),
});

/**
 * The Durable Object adapter's read without its tail check, as if both the
 * compiler and that check were bypassed: only the guard stands.
 */
const guardOnly = (db: SqlRunner, storage: DurableObjectStorage, sql: string) =>
  guardRead(db, () => {
    const cursor = storage.sql.exec(sql);
    return { rows: cursor.toArray() as Row[], rowsWritten: cursor.rowsWritten };
  });

const freshGraph = () => env.ACCOUNT_GRAPH.get(env.ACCOUNT_GRAPH.newUniqueId());

/** The rules of R6-02 that hide a statement, each also caught by the guard alone. */
const TWO_STATEMENTS: [string, string][] = [
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
];

describe("rule runs on Durable Object SQL (R6-02)", () => {
  it.each(TWO_STATEMENTS)(
    "R6-02: a two-statement rule with %s ends error and changes nothing",
    async (_, sql) => {
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
    },
  );

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
        errored: ["CF-900"],
        resolved: 0,
      });
      expect(state(db)).toEqual(before);
      expect(db.query("SELECT status, error FROM rule_runs WHERE rule_id = 'CF-900'")).toEqual([
        {
          status: "error",
          error: expect.stringMatching(/^a read-only query holds text after its first statement/),
        },
      ]);
    });
  });

  it.each(TWO_STATEMENTS)(
    "R6-02: the guard alone refuses a rule with %s and changes nothing",
    async (_, sql) => {
      await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
        const db = fromDurableObjectStorage(durable.storage);
        await seed(db);
        const before = state(db);
        expect(() => guardOnly(db, durable.storage, sql)).toThrow(
          sql.includes("no_such_table") ? /no such table/ : ReadOnlyError,
        );
        expect(state(db)).toEqual(before);
      });
    },
  );
});

describe("a run-time read is one statement (R8 hardening, R6-02)", () => {
  it("R8 hardening: drop and re-create: a tail that drops exposure and creates it again ends error and keeps exposure and the finding", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      const create = db.query<{ sql: string }>(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'exposure'",
      )[0]?.sql;
      const before = state(db);
      expect(before.exposure).toHaveLength(1);
      // The last statement reads, so the cursor's rowsWritten is 0.
      const sql = `${HIT_A}; DROP TABLE exposure; ${create}; ${NO_HIT}`;
      const [run] = evaluateRules(db, [rule(sql)], "s1", 2000);
      expect(run).toMatchObject({ status: "error", hits: 0, opened: 0, resolved: 0 });
      expect(run?.error).toMatch(/text after its first statement/);
      expect(state(db)).toEqual(before);
    });
  });

  it("R8 hardening: a $name(...) variable, which SQLite reads past a quote, is refused before it runs", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      const before = state(db);
      const sql = `SELECT $a(') ; DROP TABLE exposure; ${NO_HIT} --' AS v`;
      expect(() => db.queryReadOnly(sql, 1)).toThrow(ReadOnlyError);
      expect(() => db.queryReadOnly(sql, 1)).toThrow(/variable \(\$\)/);
      const [run] = evaluateRules(db, [rule(sql)], "s1", 2000);
      expect(run).toMatchObject({ status: "error", opened: 0, resolved: 0 });
      expect(state(db)).toEqual(before);
    });
  });

  it("R8 hardening: every committed rule still runs", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      beginScan(db, { id: "s1", kind: "full", at: 1000 });
      for (const input of new Set(RULES.flatMap((r) => r.requires))) {
        recordCoverage(db, { scanId: "s1", resourceClass: input, status: "complete" });
      }
      const runs = evaluateRules(db, RULES, "s1", 2000);
      expect(runs.map((r) => [r.ruleId, r.status, r.error])).toEqual(
        RULES.map((r) => [r.id, "evaluated", undefined]),
      );
    });
  });
});

describe("guard state a drop cannot keep (R8 hardening, R6-02)", () => {
  /** The statement that created `name`, as sqlite_schema holds it. */
  const createSql = (db: SqlRunner, name: string) =>
    db.query<{ sql: string }>("SELECT sql FROM sqlite_schema WHERE name = ?", name)[0]?.sql ?? "";

  it("R8 hardening: drop and re-create: the guard alone sees exposure emptied by a drop and an identical create", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      const create = createSql(db, "exposure");
      const before = state(db);
      // Separate statements, as a tail would run them; the last one reads.
      const run = () =>
        guardRead(db, () => {
          durable.storage.sql.exec("DROP TABLE exposure");
          durable.storage.sql.exec(create);
          const cursor = durable.storage.sql.exec(NO_HIT);
          return { rows: cursor.toArray() as Row[], rowsWritten: cursor.rowsWritten };
        });
      expect(run).toThrow(ReadOnlyError);
      expect(run).toThrow(/emptied exposure/);
      expect(state(db)).toEqual(before);
    });
  });

  it("R8 hardening: drop and re-create: the guard alone sees findings emptied with their links", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      const objects = ["findings", "finding_nodes", "findings_rule"].map((n) => createSql(db, n));
      const before = state(db);
      expect(() =>
        guardRead(db, () => {
          durable.storage.sql.exec("DROP TABLE findings; DROP TABLE finding_nodes");
          for (const sql of objects) durable.storage.sql.exec(sql);
          return { rows: [], rowsWritten: 0 };
        }),
      ).toThrow(/emptied finding_nodes, findings/);
      expect(state(db)).toEqual(before);
    });
  });
});

describe("settings are always set back (R8 hardening, R6-02)", () => {
  /** Runs each statement on its own, as a tail would, inside the guard alone. */
  const guardStatements = (db: SqlRunner, storage: DurableObjectStorage, statements: string[]) =>
    guardRead(db, () => {
      for (const sql of statements) storage.sql.exec(sql);
      return { rows: [], rowsWritten: 0 };
    });
  const CHANGE_ALL = [
    "PRAGMA ignore_check_constraints = 1",
    "PRAGMA recursive_triggers = 1",
    "PRAGMA reverse_unordered_selects = 1",
    "PRAGMA legacy_alter_table = 1",
    "PRAGMA defer_foreign_keys = 1",
    "PRAGMA case_sensitive_like = 1",
  ];

  it.each([
    ["fails the read", "SELECT 1 AS nope"],
    ["lies", "SELECT 0 AS legacy_alter_table"],
  ])(
    "R8 hardening: settings read shadowed by a view: a view named pragma_legacy_alter_table that %s, plus changed settings, ends error and leaves every setting as it was",
    async (_, view) => {
      await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
        const db = fromDurableObjectStorage(durable.storage);
        await seed(db);
        const before = state(db);
        expect(Object.values(before.settings)).toEqual([0, 0, 0, 0, 0, 0]);
        const statements = [`CREATE VIEW pragma_legacy_alter_table AS ${view}`, ...CHANGE_ALL];
        expect(() => guardStatements(db, durable.storage, statements)).toThrow(ReadOnlyError);
        expect(state(db)).toEqual(before);
        expect(db.query("SELECT 'a' LIKE 'A' AS ci")).toEqual([{ ci: 1 }]);
      });
    },
  );

  it("R8 hardening: settings are set back when the query fails after changing them", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      const before = state(db);
      const statements = [...CHANGE_ALL, "SELECT * FROM no_such_table"];
      expect(() => guardStatements(db, durable.storage, statements)).toThrow(/no such table/);
      expect(state(db)).toEqual(before);
    });
  });

  it("R8 hardening: defer_foreign_keys is set back, and a rule that sets it ends error", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      const before = state(db);
      expect(() =>
        guardOnly(db, durable.storage, "PRAGMA defer_foreign_keys = 1; SELECT 1 AS x"),
      ).toThrow(/the setting defer_foreign_keys/);
      expect(state(db)).toEqual(before);
      const [run] = evaluateRules(db, [rule("PRAGMA defer_foreign_keys = 1")], "s1", 2000);
      expect(run).toMatchObject({ status: "error", opened: 0, resolved: 0 });
      expect(run?.error).toMatch(/the setting defer_foreign_keys/);
      expect(state(db)).toEqual(before);
    });
  });
});

describe("the guard compares settings with fixed defaults (H-3, R6-02)", () => {
  const DEFAULTS = {
    ignore_check_constraints: 0,
    recursive_triggers: 0,
    reverse_unordered_selects: 0,
    legacy_alter_table: 0,
    defer_foreign_keys: 0,
    case_sensitive_like: 0,
  };

  it("H-3: a fresh graph object holds the defaults the guard expects", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      expect(settings(db)).toEqual(DEFAULTS);
    });
  });

  it.each([
    "ignore_check_constraints",
    "recursive_triggers",
    "reverse_unordered_selects",
    "legacy_alter_table",
    "defer_foreign_keys",
    "case_sensitive_like",
  ])(
    "H-3: %s stuck on the connection before a read fails it closed without running it, and is set back",
    async (name) => {
      await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
        const db = fromDurableObjectStorage(durable.storage);
        await seed(db);
        // As if an earlier statement had left it set, outside any guard.
        durable.storage.sql.exec(`PRAGMA ${name} = 1`);
        expect(settings(db)).toEqual({ ...DEFAULTS, [name]: 1 });
        let ran = false;
        const read = () =>
          guardRead(db, () => {
            ran = true;
            return { rows: [], rowsWritten: 0 };
          });
        expect(read).toThrow(ReadOnlyError);
        expect(ran).toBe(false);
        expect(settings(db)).toEqual(DEFAULTS);
        // Set back, so the next run passes.
        expect(read()).toEqual([]);
        expect(ran).toBe(true);
      });
    },
  );

  it("H-3: a rule run on a connection with a stuck setting ends error and changes no finding", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      durable.storage.sql.exec("PRAGMA reverse_unordered_selects = 1");
      const before = { ...state(db), settings: DEFAULTS };
      const [run] = evaluateRules(db, [rule(NO_HIT)], "s1", 2000);
      expect(run).toMatchObject({ status: "error", opened: 0, resolved: 0 });
      expect(run?.error).toMatch(
        /^the setting reverse_unordered_selects was not at its default before a read-only query/,
      );
      expect(state(db)).toEqual(before);
      // The next run, on the defaults again, resolves the finding.
      expect(evaluateRules(db, [rule(NO_HIT)], "s1", 3000)[0]).toMatchObject({
        status: "evaluated",
        resolved: 1,
      });
    });
  });

  it("H-3: a setting stuck on the connection can no longer become the baseline of a read that keeps it", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      durable.storage.sql.exec("PRAGMA case_sensitive_like = 1");
      // Before H-3 the guard took the stuck value as its baseline, passed the
      // read and set it back to 1, so `LIKE` stayed case sensitive for later runs.
      expect(() => db.queryReadOnly(`${HIT_A} WHERE 'a' LIKE 'A'`)).toThrow(
        /the setting case_sensitive_like was not at its default/,
      );
      expect(db.query("SELECT 'a' LIKE 'A' AS ci")).toEqual([{ ci: 1 }]);
      expect(db.queryReadOnly(`${HIT_A} WHERE 'a' LIKE 'A'`)).toHaveLength(1);
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

  it("H-4: runs whitespace after the last `;`, but refuses a comment there, which fails a rule closed", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const { sql } = durable.storage;
      expect(sql.exec("SELECT 1 AS one; \t\n").toArray()).toEqual([{ one: 1 }]);
      for (const query of ["SELECT 1 AS one; -- c", "SELECT 1 AS one; /* c */", "SELECT 1;;"]) {
        expect(() => sql.exec(query), query).toThrow(/did not contain a statement/);
      }
      // The run-time check lets the comment through; workerd refuses the query.
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      const before = state(db);
      expect(() => db.queryReadOnly(`${NO_HIT}; -- c`)).toThrow(/did not contain a statement/);
      const [run] = evaluateRules(db, [rule(`${NO_HIT}; -- c`)], "s1", 2000);
      expect(run).toMatchObject({ status: "error", opened: 0, resolved: 0 });
      expect(state(db)).toEqual(before);
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

  it("does not count a drop in total_changes(), and an identical create keeps the root page and the schema text", async () => {
    await runInDurableObject(freshGraph(), async (_graph: AccountGraph, durable) => {
      const db = fromDurableObjectStorage(durable.storage);
      await seed(db);
      const { sql } = durable.storage;
      const read = () => ({
        changes: sql.exec("SELECT total_changes() AS n").one().n,
        schema: sql
          .exec("SELECT type, name, rootpage, sql FROM sqlite_schema ORDER BY type, name")
          .toArray(),
        rows: sql.exec("SELECT count(*) AS n FROM exposure").one().n,
      });
      const create = sql.exec("SELECT sql FROM sqlite_schema WHERE name = 'exposure'").one().sql;
      const before = read();
      expect(() =>
        durable.storage.transactionSync(() => {
          sql.exec(`DROP TABLE exposure; ${create}`);
          expect(read()).toEqual({ ...before, rows: 0 });
          throw new Error("rollback");
        }),
      ).toThrow("rollback");
      expect(read()).toEqual(before);
    });
  });

  it("reads each setting with a PRAGMA statement, which a view named like its pragma_ function does not shadow", async () => {
    await runInDurableObject(freshGraph(), (_graph: AccountGraph, durable) => {
      const { sql } = durable.storage;
      expect(() =>
        durable.storage.transactionSync(() => {
          sql.exec("CREATE VIEW pragma_legacy_alter_table AS SELECT 0 AS legacy_alter_table");
          sql.exec("PRAGMA legacy_alter_table = 1");
          expect(sql.exec("SELECT * FROM pragma_legacy_alter_table").one()).toEqual({
            legacy_alter_table: 0,
          });
          expect(sql.exec("PRAGMA legacy_alter_table").one()).toEqual({ legacy_alter_table: 1 });
          sql.exec("PRAGMA legacy_alter_table = 0");
          throw new Error("rollback");
        }),
      ).toThrow("rollback");
      for (const name of SETTING_NAMES) {
        expect(sql.exec(`PRAGMA ${name}`).one()).toEqual({ [name]: 0 });
      }
      expect(sql.exec("PRAGMA case_sensitive_like").toArray()).toEqual([]);
    });
  });

  it("keeps defer_foreign_keys and case_sensitive_like through a rollback", async () => {
    await runInDurableObject(freshGraph(), (_graph: AccountGraph, durable) => {
      const { sql } = durable.storage;
      expect(() =>
        durable.storage.transactionSync(() => {
          sql
            .exec("PRAGMA defer_foreign_keys = 1; PRAGMA case_sensitive_like = 1; SELECT 1 AS x")
            .toArray();
          throw new Error("rollback");
        }),
      ).toThrow("rollback");
      expect(sql.exec("PRAGMA defer_foreign_keys").one()).toEqual({ defer_foreign_keys: 1 });
      expect(sql.exec("SELECT 'a' LIKE 'A' AS ci").one()).toEqual({ ci: 0 });
      sql.exec("PRAGMA defer_foreign_keys = 0");
      sql.exec("PRAGMA case_sensitive_like = 0");
      expect(sql.exec("SELECT 'a' LIKE 'A' AS ci").one()).toEqual({ ci: 1 });
    });
  });
});
