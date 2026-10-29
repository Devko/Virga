import { migrate } from "@virga/graph";
import { openNodeDatabase } from "@virga/graph/node";
import { describe, expect, it } from "vitest";
import { FIXTURES } from "../src/fixtures.gen.ts";
import { evaluateFixture, loadFixture, RULES } from "../src/index.ts";
import type { CompiledRule, RuleFixture } from "../src/types.ts";

async function run(rule: CompiledRule, fixture: RuleFixture) {
  const db = openNodeDatabase();
  try {
    migrate(db);
    await loadFixture(db, fixture);
    return evaluateFixture(db, rule, fixture);
  } finally {
    db.close();
  }
}

const ruleById = (id: string) => {
  const rule = RULES.find((r) => r.id === id);
  if (!rule) throw new Error(`missing rule ${id}`);
  return rule;
};

describe("rule fixtures (Node SQLite)", () => {
  it.each(FIXTURES.map((f) => [`${f.rule}/${f.name}`, f] as const))("%s", async (_, fixture) => {
    const result = await run(ruleById(fixture.rule), fixture);
    expect(result.actual).toEqual(result.expected);
  });
});

describe("evaluateFixture: decided rows", () => {
  const rule: CompiledRule = {
    id: "CF-999",
    version: 1,
    title: "Test",
    severity: "low",
    kind: "posture",
    requires: [],
    params: {},
    enriches: null,
    sql: `SELECT 'CF-999' AS rule_id, 'CF-999:' || id AS fingerprint, 'low' AS severity,
                 id AS subject_id, props ->> '$.decided' AS decided
          FROM nodes WHERE type = 'worker_script'`,
    paramOrder: [],
  };
  const scenario = (decided: unknown, expect: RuleFixture["expect"]): RuleFixture => ({
    rule: "CF-999",
    name: "t",
    nodes: [{ type: "worker_script", id: "a", props: { decided } }],
    edges: [],
    expect,
  });
  const fingerprint = "CF-999:worker_script:a";

  it.each<[string, number, RuleFixture["expect"], boolean]>([
    ["an undecided row", 0, [{ fingerprint, decided: false }], true],
    ["a hit with decided = 1", 1, [{ fingerprint, severity: "low" }], true],
    ["a hit where an undecided row is expected", 1, [{ fingerprint, decided: false }], false],
    ["an undecided row where a hit is expected", 0, [{ fingerprint }], false],
    ["an undecided row where none is expected", 0, [], false],
  ])("compares %s", async (_, decided, expected, passed) => {
    expect((await run(rule, scenario(decided, expected))).passed).toBe(passed);
  });

  it("names undecided and invalid rows in the result", async () => {
    expect(await run(rule, scenario(0, []))).toMatchObject({
      expected: [],
      actual: [`${fingerprint} (undecided)`],
    });
    expect(await run(rule, scenario(1, [{ fingerprint, decided: false }]))).toMatchObject({
      expected: [`${fingerprint} (undecided)`],
      actual: [fingerprint],
    });
    expect((await run(rule, scenario(2, [{ fingerprint }]))).actual).toEqual([
      `${fingerprint} (invalid decided)`,
    ]);
  });
});

describe("CF-001 fixtures catch the spec's original service binding bug", () => {
  it("fails a negative fixture when the 0 % filter on the hop is removed", async () => {
    const rule = ruleById("CF-001");
    const buggy: CompiledRule = {
      ...rule,
      sql: rule.sql.replace(
        /\s+AND COALESCE\(json_extract\(d2\.props, '\$\.percentage'\), 100\) > 0/,
        "",
      ),
    };
    expect(buggy.sql).not.toBe(rule.sql);
    const fixture = FIXTURES.find((f) => f.name === "negative-service-binding-to-idle-version");
    if (!fixture) throw new Error("fixture missing");
    const result = await run(buggy, fixture);
    expect(result.passed).toBe(false);
    expect(result.actual).toEqual(["CF-001:worker_script:k (high)"]);
  });
});
