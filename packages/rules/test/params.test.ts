import { assertOneStatement } from "@virga/graph";
import { describe, expect, it } from "vitest";
import { compileParams } from "../src/params.ts";
import { RULES } from "../src/rules.gen.ts";

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

describe("R8 hardening: placeholders the compiler does not rewrite", () => {
  it.each([
    ["@name", "SELECT 1 AS v WHERE 1 = @p", "@p"],
    ["$name", "SELECT 1 AS v WHERE 1 = $p", "$p"],
    ["$name(...)", "SELECT $a(') ; DELETE FROM nodes; SELECT 1 --' AS v", "$a("],
    ["#name", "SELECT 1 AS v WHERE 1 = #p", "#p"],
    ["a :name that starts with a digit", "SELECT 1 AS v WHERE 1 = :1", ":1"],
    ["a : without a name", "SELECT 1 AS v WHERE 1 = : p", ":"],
    ["a :name with ::", "SELECT 1 AS v WHERE 1 = :p::q", ":p::"],
    ["a :name(...)", "SELECT 1 AS v WHERE 1 = :p(x)", ":p("],
    ["a :name that runs on in a non-ASCII letter", "SELECT :pé AS v", ":pé"],
    ["a :name that runs on in a $", "SELECT :p$q AS v", ":p$"],
  ])("refuses %s", (_, sql, token) => {
    expect(() => compileParams(sql)).toThrow(
      `unsupported placeholder ${token}; use named :parameters`,
    );
  });

  it("keeps @, $, # and : in strings, identifiers and comments", () => {
    const sql = "SELECT '@a $b #c :d' AS [x@$#:], 1 AS `y$:`, \"z#@\" -- @e :f\n/* $g #h */";
    expect(compileParams(sql)).toEqual({ sql, order: [] });
  });
});

describe("R8 hardening: committed rules pass the run-time one-statement check", () => {
  it.each(RULES.map((r) => [r.id, r.sql] as const))("%s", (_, sql) => {
    expect(() => assertOneStatement(sql)).not.toThrow();
  });
});
