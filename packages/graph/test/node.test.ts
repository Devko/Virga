import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type NodeSqlRunner, openNodeDatabase } from "../src/node.ts";

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
