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
});
