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
