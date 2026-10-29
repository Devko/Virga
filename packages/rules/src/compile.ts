import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { migrate } from "@virga/graph";
import { openNodeDatabase } from "@virga/graph/node";
import { evaluateFixture, loadFixture } from "./fixtures.ts";
import { parseFixture, parseRule } from "./parse.ts";
import type { CompiledRule, RuleFixture } from "./types.ts";

const REQUIRED_COLUMNS = ["rule_id", "fingerprint", "severity"];

export interface CompileResult {
  rules: CompiledRule[];
  fixtures: RuleFixture[];
  errors: string[];
}

/** Reads every rule directory, compiles the rule and its fixtures, and runs the fixtures. */
export async function compileRules(rulesDir: string): Promise<CompileResult> {
  const rules: CompiledRule[] = [];
  const fixtures: RuleFixture[] = [];
  const errors: string[] = [];

  const dirs = readdirSync(rulesDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();

  for (const dir of dirs) {
    let rule: CompiledRule;
    try {
      rule = parseRule(readFileSync(join(rulesDir, dir, "rule.sql"), "utf8"), `${dir}/rule.sql`);
      if (rule.id !== dir)
        throw new Error(`${dir}/rule.sql: id ${rule.id} does not match directory`);
      checkAgainstSchema(rule);
    } catch (error) {
      errors.push((error as Error).message);
      continue;
    }
    rules.push(rule);

    const fixtureDir = join(rulesDir, dir, "fixtures");
    const files = readdirSync(fixtureDir)
      .filter((f) => f.endsWith(".yaml"))
      .sort();
    if (
      !files.some((f) => f.startsWith("positive-")) ||
      !files.some((f) => f.startsWith("negative-"))
    ) {
      errors.push(`${dir}: needs at least one positive-*.yaml and one negative-*.yaml fixture`);
    }
    for (const file of files) {
      const name = file.replace(/\.yaml$/, "");
      try {
        const fixture = parseFixture(readFileSync(join(fixtureDir, file), "utf8"), dir, name);
        if (name.startsWith("negative-") && fixture.expect.length > 0) {
          throw new Error(`${dir}/fixtures/${file}: negative fixture must expect no hits`);
        }
        if (name.startsWith("positive-") && fixture.expect.length === 0) {
          throw new Error(`${dir}/fixtures/${file}: positive fixture must expect hits`);
        }
        const result = await runFixture(rule, fixture);
        if (!result.passed) {
          throw new Error(
            `${dir}/fixtures/${file}: expected [${result.expected.join(", ")}], got [${result.actual.join(", ")}]`,
          );
        }
        fixtures.push(fixture);
      } catch (error) {
        errors.push((error as Error).message);
      }
    }
  }
  return { rules, fixtures, errors };
}

/** Prepares the statement against the current schema and checks the output columns. */
function checkAgainstSchema(rule: CompiledRule): void {
  const db = openNodeDatabase();
  try {
    migrate(db);
    let columns: string[];
    try {
      columns = db.columns(rule.sql);
    } catch (error) {
      throw new Error(`${rule.id}: ${(error as Error).message}`);
    }
    for (const column of REQUIRED_COLUMNS) {
      if (!columns.includes(column)) throw new Error(`${rule.id}: output lacks column ${column}`);
    }
  } finally {
    db.close();
  }
}

async function runFixture(rule: CompiledRule, fixture: RuleFixture) {
  const db = openNodeDatabase();
  try {
    migrate(db);
    await loadFixture(db, fixture);
    return evaluateFixture(db, rule, fixture);
  } finally {
    db.close();
  }
}
