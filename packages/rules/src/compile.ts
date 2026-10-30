import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { RESOURCE_CLASSES } from "@virga/collectors";
import { migrate } from "@virga/graph";
import { openNodeDatabase } from "@virga/graph/node";
import { evaluateFixture, loadFixture } from "./fixtures.ts";
import { parseFixture, parseRule } from "./parse.ts";
import type { CompiledRule, RuleFixture } from "./types.ts";

const REQUIRED_COLUMNS = ["rule_id", "fingerprint", "severity", "subject_id"];

/** Inputs a rule may require: resource classes plus inputs derived by scan steps. */
const KNOWN_INPUTS = new Set<string>([...RESOURCE_CLASSES, "exposure", "packages", "vulns"]);

type FixtureKind = "positive" | "negative" | "undecided";
const FIXTURE_FILE = /^(positive|negative|undecided)-.+\.yaml$/;

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
      for (const input of rule.requires) {
        if (!KNOWN_INPUTS.has(input))
          throw new Error(`${dir}/rule.sql: unknown input '${input}' in requires`);
      }
      checkAgainstSchema(rule);
    } catch (error) {
      errors.push((error as Error).message);
      continue;
    }
    rules.push(rule);

    const fixtureDir = join(rulesDir, dir, "fixtures");
    let entries: Dirent[];
    try {
      entries = readdirSync(fixtureDir, { withFileTypes: true });
    } catch (error) {
      errors.push(`${dir}: no fixtures directory (${(error as Error).message})`);
      continue;
    }
    const files: { file: string; kind: FixtureKind }[] = [];
    for (const entry of entries.filter((e) => !e.name.startsWith(".")).sort(byName)) {
      const kind = entry.isFile()
        ? (FIXTURE_FILE.exec(entry.name)?.[1] as FixtureKind | undefined)
        : undefined;
      if (kind) files.push({ file: entry.name, kind });
      else {
        errors.push(
          `${dir}/fixtures/${entry.name}: fixture files are named positive-, negative- or undecided-<name>.yaml`,
        );
      }
    }
    const kinds = new Set(files.map((f) => f.kind));
    if (!kinds.has("positive") || !kinds.has("negative")) {
      errors.push(`${dir}: needs at least one positive-*.yaml and one negative-*.yaml fixture`);
    }
    if (rule.requires.includes("exposure") && !kinds.has("undecided")) {
      errors.push(
        `${dir}: requires exposure, so it needs an undecided-*.yaml fixture for unknown exposure`,
      );
    }
    for (const { file, kind } of files) {
      const name = file.replace(/\.yaml$/, "");
      try {
        const fixture = parseFixture(readFileSync(join(fixtureDir, file), "utf8"), dir, name);
        const problem = checkFixtureKind(kind, fixture);
        if (problem) throw new Error(`${dir}/fixtures/${file}: ${problem}`);
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

const byName = (a: Dirent, b: Dirent) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

/**
 * The prefix says what a fixture shows: a positive one at least one hit, a
 * negative one no rows at all, and an undecided one at least one row the
 * rule cannot decide. Positive and undecided fixtures may hold both.
 */
function checkFixtureKind(kind: FixtureKind, fixture: RuleFixture): string | null {
  const hits = fixture.expect.filter((e) => e.decided !== false).length;
  const undecided = fixture.expect.length - hits;
  if (kind === "positive" && hits === 0) return "a positive fixture must expect at least one hit";
  if (kind === "negative" && fixture.expect.length > 0) {
    return "a negative fixture must expect no rows";
  }
  if (kind === "undecided" && undecided === 0) {
    return "an undecided fixture must expect at least one undecided row";
  }
  return null;
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
