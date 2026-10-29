import { describe, expect, it } from "vitest";
import { parseRule } from "../src/parse.ts";

const rule = (
  frontMatter: string,
  body = "SELECT 'X' AS rule_id, :p AS fingerprint, 'low' AS severity",
) =>
  `-- ---\n${frontMatter
    .trim()
    .split("\n")
    .map((l) => `-- ${l}`)
    .join("\n")}\n-- ---\n${body}\n`;

const valid = `
id: CF-999
version: 1
title: Test
severity: low
kind: posture
requires: [workers]
params: { p: 1 }
`;

describe("parseRule", () => {
  it("parses front matter and compiles parameters", () => {
    const parsed = parseRule(rule(valid), "t");
    expect(parsed.id).toBe("CF-999");
    expect(parsed.paramOrder).toEqual(["p"]);
    expect(parsed.sql).toContain("?");
  });

  it("rejects undeclared and unused parameters", () => {
    expect(() => parseRule(rule(valid.replace("{ p: 1 }", "{}")), "t")).toThrow(/no default/);
    expect(() => parseRule(rule(valid.replace("{ p: 1 }", "{ p: 1, q: 2 }")), "t")).toThrow(
      /unused/,
    );
  });

  it("rejects unknown keys and statements that are not queries", () => {
    expect(() => parseRule(rule(`${valid}\nfoo: 1`), "t")).toThrow(/unknown front matter key/);
    expect(() => parseRule(rule(valid, "DELETE FROM nodes WHERE 1 = :p"), "t")).toThrow(
      /SELECT or WITH/,
    );
  });
});
