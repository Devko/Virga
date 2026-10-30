import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MIGRATIONS, migrate, SCHEMA_VERSION, schemaVersion } from "../src/index.ts";
import { type NodeSqlRunner, openNodeDatabase } from "../src/node.ts";

let db: NodeSqlRunner;

beforeEach(() => {
  db = openNodeDatabase();
});
afterEach(() => db.close());

const ruleRunColumns = () =>
  db
    .query<{ name: string; type: string; notnull: number; dflt_value: string | null }>(
      "SELECT name, type, \"notnull\", dflt_value FROM pragma_table_info('rule_runs') ORDER BY cid",
    )
    .map((c) => ({ ...c }));

describe("migrations", () => {
  it("are numbered from 1 without gaps, with the initial schema first", () => {
    expect(MIGRATIONS.map((m) => m.version)).toEqual(MIGRATIONS.map((_, i) => i + 1));
    expect(MIGRATIONS[0]?.name).toBe("init");
    expect(SCHEMA_VERSION).toBe(MIGRATIONS.length);
  });

  it("apply step by step, each version once", () => {
    expect(migrate(db, MIGRATIONS.slice(0, 1))).toBe(1);
    expect(schemaVersion(db)).toBe(1);
    expect(migrate(db)).toBe(SCHEMA_VERSION);
    expect(migrate(db)).toBe(SCHEMA_VERSION);
  });
});

describe("migration 2: undecided and error in rule_runs", () => {
  it("adds both columns to a version 1 database and keeps its rows", () => {
    migrate(db, MIGRATIONS.slice(0, 1));
    db.run(
      `INSERT INTO rule_runs (scan_id, rule_id, status, hits, missing)
       VALUES ('s1', 'CF-001', 'not_evaluated', 0, '["vulns"]'), ('s1', 'CF-002', 'evaluated', 2, NULL)`,
    );
    migrate(db);
    expect(schemaVersion(db)).toBeGreaterThanOrEqual(2);
    expect(
      db.query(
        "SELECT rule_id, status, hits, missing, undecided, error FROM rule_runs ORDER BY rule_id",
      ),
    ).toEqual([
      {
        rule_id: "CF-001",
        status: "not_evaluated",
        hits: 0,
        missing: '["vulns"]',
        undecided: 0,
        error: null,
      },
      { rule_id: "CF-002", status: "evaluated", hits: 2, missing: null, undecided: 0, error: null },
    ]);
  });

  it("gives a new database the same rule_runs columns as a migrated one", () => {
    migrate(db);
    const fresh = ruleRunColumns();
    db.close();
    db = openNodeDatabase();
    migrate(db, MIGRATIONS.slice(0, 1));
    migrate(db);
    expect(ruleRunColumns()).toEqual(fresh);
    expect(fresh.slice(-2)).toEqual([
      { name: "undecided", type: "INTEGER", notnull: 1, dflt_value: "0" },
      { name: "error", type: "TEXT", notnull: 0, dflt_value: null },
    ]);
  });

  it("requires a count of undecided rows", () => {
    migrate(db);
    expect(() =>
      db.run(
        "INSERT INTO rule_runs (scan_id, rule_id, status, undecided) VALUES ('s1', 'CF-001', 'evaluated', NULL)",
      ),
    ).toThrow(/NOT NULL/);
  });
});
