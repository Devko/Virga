import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type NodeSqlRunner, openNodeDatabase } from "../src/node.ts";
import { guardRead, ReadOnlyError } from "../src/sql.ts";

let db: NodeSqlRunner;

beforeEach(() => {
  db = openNodeDatabase();
  db.script("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)");
});
afterEach(() => db.close());

describe("NodeSqlRunner.tail (R6-02)", () => {
  it.each([
    ["no semicolon", "SELECT 1"],
    ["one semicolon", "SELECT 1;"],
    ["whitespace and comments", "SELECT 1 ; -- done\n\t/* end */\r\n\f"],
    ["a comment at the end", "SELECT 1; -- done"],
    ["comments before the statement", "-- lead\n/* c */ SELECT 1"],
    ["[x--];", "SELECT 1 AS [x--];\n"],
    ["[a;b]", "SELECT 1 AS [a;b]"],
  ])("is empty after one statement with %s", (_, sql) => {
    expect(db.tail(sql)).toBe("");
  });

  it.each([
    ["a statement after [x--];", "SELECT 1 AS [x--]; UPDATE meta SET value = 'f'", "UPDATE"],
    ["a statement after `x--`;", "SELECT 1 AS `x--`; SELECT 2", "SELECT 2"],
    ["a second semicolon", "SELECT 1;;", ";"],
    ["an empty statement and another", "SELECT 1; /* x */ ; SELECT 2", "; SELECT 2"],
    ["an unterminated comment", "SELECT 1; /* open", "/* open"],
    ["a NUL, where SQLite stops reading", "SELECT 1\u0000; SELECT 2", "\u0000; SELECT 2"],
    ["a NUL inside a comment", "SELECT 1; -- c\u0000 SELECT 2", "\u0000 SELECT 2"],
    ["a vertical tab, which SQLite does not skip", "SELECT 1;\u000b", "\u000b"],
    ["a no-break space, which SQLite does not skip", "SELECT 1; ", " "],
  ])("returns %s", (_, sql, tail) => {
    expect(db.tail(sql).startsWith(tail)).toBe(true);
  });
});

describe("SqlRunner.queryReadOnly (R6-02)", () => {
  const setting = (name: string) => db.query(`PRAGMA ${name}`)[0]?.[name];
  const tables = () => db.query("SELECT name FROM sqlite_schema ORDER BY name");

  it("returns the rows of a statement that only reads", () => {
    db.run("INSERT INTO meta VALUES ('current_scan', 's1')");
    expect(db.queryReadOnly("SELECT value FROM meta WHERE key = ?", "current_scan")).toEqual([
      { value: "s1" },
    ]);
  });

  it.each([
    ["an UPDATE", "UPDATE meta SET value = 'forged' RETURNING key", /changed rows/],
    ["an INSERT", "INSERT INTO meta VALUES ('planted', 'x') RETURNING key", /changed rows/],
    ["a DELETE", "DELETE FROM meta RETURNING key", /changed rows/],
    ["a new table", "CREATE TABLE planted (x)", /changed the schema/],
    ["a new index", "CREATE INDEX planted ON meta (value)", /changed the schema/],
    [
      "a trigger",
      "CREATE TRIGGER planted AFTER UPDATE ON meta BEGIN DELETE FROM meta; END",
      /changed the schema/,
    ],
    [
      "a statement tail",
      "SELECT 1 AS [x--]; UPDATE meta SET value = 'forged'",
      /more than one statement/,
    ],
  ])("refuses %s and keeps nothing of it", (_, sql, message) => {
    db.run("INSERT INTO meta VALUES ('current_scan', 's1')");
    const before = { meta: db.query("SELECT * FROM meta"), tables: tables() };
    expect(() => db.queryReadOnly(sql)).toThrow(message);
    expect({ meta: db.query("SELECT * FROM meta"), tables: tables() }).toEqual(before);
  });

  it.each([
    "ignore_check_constraints",
    "recursive_triggers",
    "reverse_unordered_selects",
    "legacy_alter_table",
  ])("sets %s back, which a rollback keeps, and refuses the read", (name) => {
    // A flag pragma acts when it is prepared, before it runs.
    expect(() => db.queryReadOnly(`PRAGMA ${name} = 1`)).toThrow(`the setting ${name}`);
    expect(setting(name)).toBe(0);
    db.run(`PRAGMA ${name} = 1`);
    expect(() => db.queryReadOnly(`PRAGMA ${name} = 0`)).toThrow(`the setting ${name}`);
    expect(setting(name)).toBe(1);
  });

  it("sets case_sensitive_like back, which can only be seen in what LIKE does", () => {
    expect(() => db.queryReadOnly("PRAGMA case_sensitive_like = 1")).toThrow(
      "the setting case_sensitive_like",
    );
    expect(db.query("SELECT 'a' LIKE 'A' AS ci")).toEqual([{ ci: 1 }]);
  });

  it("sets a setting back when a later statement fails", () => {
    expect(() =>
      guardRead(db, () => {
        db.run("PRAGMA recursive_triggers = 1");
        db.run("INSERT INTO meta VALUES ('planted', 'x')");
        throw new Error("a later statement failed");
      }),
    ).toThrow("a later statement failed");
    expect(setting("recursive_triggers")).toBe(0);
    expect(db.query("SELECT * FROM meta")).toEqual([]);
  });

  it("counts rows the runtime reports for the last statement", () => {
    expect(() => guardRead(db, () => ({ rows: [], rowsWritten: 1 }))).toThrow(ReadOnlyError);
  });
});
