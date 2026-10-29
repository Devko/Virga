import { describe, expect, it } from "vitest";
import { parseFixture, parseRule } from "../src/parse.ts";

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

describe("parseFixture", () => {
  const fixture = (list: string) => parseFixture(`nodes: []\nexpect: ${list}\n`, "CF-999", "f");

  it("reads hits and undecided rows, and keeps only decided: false", () => {
    expect(
      fixture(`
  - { fingerprint: "CF-999:a", severity: high }
  - { fingerprint: "CF-999:b", decided: true }
  - { fingerprint: "CF-999:c", decided: false }`).expect,
    ).toEqual([
      { fingerprint: "CF-999:a", severity: "high" },
      { fingerprint: "CF-999:b" },
      { fingerprint: "CF-999:c", decided: false },
    ]);
  });

  it.each([
    ["[CF-999:a]", /expect entry 1: must be a mapping/],
    ["[{ severity: high }]", /fingerprint is required/],
    ["[{ fingerprint: CF-999:a, severity: severe }]", /invalid severity/],
    ["[{ fingerprint: CF-999:a, decided: 0 }]", /decided must be true or false/],
    ["[{ fingerprint: CF-999:a, decided: false, severity: low }]", /no severity to expect/],
    ["[{ fingerprint: CF-999:a, undecided: true }]", /unknown key 'undecided'/],
    ["[{ fingerprint: CF-999:a }, { fingerprint: CF-999:a, decided: false }]", /twice/],
  ])("rejects %s", (list, message) => {
    expect(() => fixture(list)).toThrow(message);
  });
});
