import { describe, expect, it } from "vitest";
import { compileParams } from "../src/params.ts";

describe("compileParams", () => {
  it("replaces named parameters in order", () => {
    expect(compileParams("SELECT :a + :b, :a")).toEqual({
      sql: "SELECT ? + ?, ?",
      order: ["a", "b", "a"],
    });
  });

  it("ignores strings, identifiers and comments", () => {
    const sql = `SELECT 'x:y', "c:d", json_extract(p, '$.a') -- :nope
      /* :nor */ FROM t WHERE v = :yes`;
    const result = compileParams(sql);
    expect(result.order).toEqual(["yes"]);
    expect(result.sql).toContain("'x:y'");
    expect(result.sql).toContain("-- :nope");
  });

  it("handles escaped quotes", () => {
    expect(compileParams("SELECT 'it''s :not' , :p").order).toEqual(["p"]);
  });

  it("allows one trailing semicolon only", () => {
    expect(compileParams("SELECT 1;\n").sql).toBe("SELECT 1");
    expect(() => compileParams("SELECT 1; DELETE FROM nodes")).toThrow(/one statement/);
  });

  it("rejects positional placeholders", () => {
    expect(() => compileParams("SELECT ?")).toThrow(/named/);
  });

  describe("R6-02: bracket and backtick identifiers are quoted", () => {
    const TAIL = "UPDATE meta SET value = 'forged' WHERE key = 'current_scan'";

    it.each([
      ["[x--]", "[x--]"],
      ["[x/*]", "[x/*]"],
      ["`x--`", "`x--`"],
    ])("reads no comment in %s, so a statement after it is refused", (_, name) => {
      const sql = `SELECT 1 AS ${name}; ${TAIL}`;
      expect(() => compileParams(sql)).toThrow(/exactly one statement/);
    });

    it.each([
      ["[x--];", "SELECT 1 AS [x--];\n", "SELECT 1 AS [x--]"],
      ["[a;b]", "SELECT 1 AS [a;b]", "SELECT 1 AS [a;b]"],
      ["`a;b`", "SELECT 1 AS `a;b`", "SELECT 1 AS `a;b`"],
      ["[a:b] and `c:d`", "SELECT 1 AS [a:b], 2 AS `c:d`", "SELECT 1 AS [a:b], 2 AS `c:d`"],
    ])("keeps %s as one identifier", (_, sql, out) => {
      expect(compileParams(sql)).toEqual({ sql: out, order: [] });
    });

    it("has no escape inside brackets: the first ] ends the identifier", () => {
      expect(() => compileParams(`SELECT 1 AS [a]]; ${TAIL}`)).toThrow(/exactly one statement/);
    });

    it("rejects an unterminated bracket identifier", () => {
      expect(() => compileParams("SELECT 1 AS [x")).toThrow(/unterminated \[/);
    });
  });
});
