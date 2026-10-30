import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { RESOURCE_CLASSES } from "@virga/collectors";
import { migrate, type Row } from "@virga/graph";
import { openNodeDatabase } from "@virga/graph/node";
import { evaluateFixture, loadFixture } from "./fixtures.ts";
import { parseFixture, parseRule } from "./parse.ts";
import type { CompiledRule, RuleFixture } from "./types.ts";

const REQUIRED_COLUMNS = ["rule_id", "fingerprint", "severity", "subject_id"];

/** Inputs a rule may require: resource classes plus inputs derived by scan steps. */
const KNOWN_INPUTS = new Set<string>([...RESOURCE_CLASSES, "exposure", "packages", "vulns"]);

/**
 * Inputs a rule needs because it reads a table, whatever its front matter
 * says (R4-04). Exposure without Access coverage is no decision, so reading
 * exposure needs both. Which classes `nodes`, `edges` and `signals` hold
 * depends on their rows, so a table alone does not tell.
 */
const TABLE_INPUTS: Record<string, readonly string[]> = {
  exposure: ["access", "exposure"],
  vulns: ["vulns"],
  insights: ["insights"],
};

/** Opcodes that open a b-tree of the database for reading: p2 is its root page, p3 the database. */
const READ_OPCODES = new Set(["OpenRead", "ReopenIdx"]);

/**
 * Opcodes besides OpenWrite and Clear that change the database. Insert and
 * Delete also fill the temporary tables of a plain SELECT, so a write shows
 * as one of these, OpenWrite, Clear or a write transaction.
 */
const WRITE_OPCODES = new Set([
  "CreateBtree",
  "Destroy",
  "DropIndex",
  "DropTable",
  "DropTrigger",
  "IncrVacuum",
  "ParseSchema",
  "SetCookie",
  "VCreate",
  "VDestroy",
  "VUpdate",
  "Vacuum",
]);

/**
 * Durable Object SQLite refuses a statement whose program grows past about
 * 21,500 operations (SQLITE_NOMEM, measured 2026-10-30); Node SQLite does not.
 */
const MAX_PROGRAM_OPS = 20_000;

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
    let reads: Set<string>;
    try {
      rule = parseRule(readFileSync(join(rulesDir, dir, "rule.sql"), "utf8"), `${dir}/rule.sql`);
      if (rule.id !== dir)
        throw new Error(`${dir}/rule.sql: id ${rule.id} does not match directory`);
      for (const input of rule.requires) {
        if (!KNOWN_INPUTS.has(input))
          throw new Error(`${dir}/rule.sql: unknown input '${input}' in requires`);
      }
      reads = checkAgainstSchema(rule);
    } catch (error) {
      errors.push((error as Error).message);
      continue;
    }
    const derived = [...reads].filter((table) => table in TABLE_INPUTS).sort();
    const missing = [...new Set(derived.flatMap((table) => TABLE_INPUTS[table] ?? []))]
      .filter((input) => !rule.requires.includes(input))
      .sort();
    if (missing.length > 0) {
      const list = missing.join(", ");
      errors.push(
        `${dir}/rule.sql: reads ${derived.join(", ")}, so requires must also list ${list}`,
      );
    } else {
      rules.push(rule);
    }

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
    const exposure = reads.has("exposure")
      ? "reads"
      : rule.requires.includes("exposure")
        ? "requires"
        : null;
    if (exposure && !kinds.has("undecided")) {
      errors.push(
        `${dir}: ${exposure} exposure, so it needs an undecided-*.yaml fixture for unknown exposure`,
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

interface ProgramStep {
  opcode: string;
  p1: number;
  p2: number;
  p3: number;
}

/**
 * Prepares the statement against the current schema, checks the output
 * columns, and returns the tables its program reads. A statement that
 * writes is refused: a WITH clause can front INSERT, UPDATE or DELETE with
 * RETURNING, which passes the SELECT/WITH check of the parser (R4-05).
 *
 * Node SQLite compiles only the first statement, so the checks below and
 * the fixtures would see nothing after it, while Durable Object SQL runs
 * every statement. SQLite's own reading of where the first one ends decides
 * whether anything follows it, not the parameter scan (R6-02).
 */
function checkAgainstSchema(rule: CompiledRule): Set<string> {
  const db = openNodeDatabase();
  try {
    migrate(db);
    let columns: string[];
    let program: ProgramStep[];
    try {
      const tail = db.tail(rule.sql);
      if (tail !== "") {
        const excerpt = JSON.stringify(tail.slice(0, 40));
        throw new Error(`text after the first statement (${excerpt}); a rule is one statement`);
      }
      const params = rule.paramOrder.map((name) => rule.params[name] ?? null);
      program = db.query<ProgramStep & Row>(`EXPLAIN ${rule.sql}`, ...params);
      columns = db.columns(rule.sql);
    } catch (error) {
      throw new Error(`${rule.id}: ${(error as Error).message}`);
    }
    const tables = new Map<number, string>([[1, "sqlite_schema"]]);
    for (const row of db.query<{ rootpage: number; tbl_name: string }>(
      "SELECT rootpage, tbl_name FROM sqlite_schema WHERE rootpage > 0",
    )) {
      tables.set(row.rootpage, row.tbl_name);
    }
    const table = (root: number, database: number) =>
      (database === 0 && tables.get(root)) || `root page ${root} of database ${database}`;

    const reads = new Set<string>();
    for (const step of program) {
      // DELETE without WHERE empties the table with Clear (root page in p1).
      if (step.opcode === "OpenWrite" || step.opcode === "Clear") {
        const [root, database] = step.opcode === "Clear" ? [step.p1, step.p2] : [step.p2, step.p3];
        throw new Error(`${rule.id}: writes to ${table(root, database)}; a rule may only read`);
      }
      if (WRITE_OPCODES.has(step.opcode) || (step.opcode === "Transaction" && step.p2 !== 0)) {
        throw new Error(`${rule.id}: changes the database (${step.opcode}); a rule may only read`);
      }
      if (READ_OPCODES.has(step.opcode)) reads.add(table(step.p2, step.p3));
    }
    if (program.length > MAX_PROGRAM_OPS) {
      throw new Error(
        `${rule.id}: compiles to ${program.length} operations; Durable Object SQLite accepts about ${MAX_PROGRAM_OPS}`,
      );
    }
    for (const column of REQUIRED_COLUMNS) {
      if (!columns.includes(column)) throw new Error(`${rule.id}: output lacks column ${column}`);
    }
    return reads;
  } finally {
    db.close();
  }
}

async function runFixture(rule: CompiledRule, fixture: RuleFixture) {
  const db = openNodeDatabase();
  try {
    migrate(db);
    await loadFixture(db, fixture);
    // The program check refuses writes; this refuses any it might miss.
    db.script("PRAGMA query_only = ON");
    return evaluateFixture(db, rule, fixture);
  } finally {
    db.close();
  }
}
