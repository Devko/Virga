import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { compileRules } from "../src/compile.ts";
import { REVIEW_RULES, reviewFixtures } from "./review-rules.ts";

const SELECT_SCRIPTS = `SELECT 'CF-999' AS rule_id, 'CF-999:' || id AS fingerprint, 'low' AS severity,
       id AS subject_id, COALESCE(props ->> '$.decided', 1) AS decided
FROM nodes WHERE type = 'worker_script' AND deleted_at IS NULL`;

const rule = (requires: string, sql = SELECT_SCRIPTS) => `-- ---
-- id: CF-999
-- version: 1
-- title: Test
-- severity: low
-- kind: posture
-- requires: ${requires}
-- ---
${sql}
`;

const fingerprint = "CF-999:worker_script:a";
const FIXTURES = {
  hit: `nodes: [{ type: worker_script, id: a }]\nexpect: [{ fingerprint: "${fingerprint}" }]\n`,
  none: "nodes: []\nexpect: []\n",
  undecided: `nodes: [{ type: worker_script, id: a, props: { decided: 0 } }]\nexpect: [{ fingerprint: "${fingerprint}", decided: false }]\n`,
};

let root: string | undefined;
afterEach(() => {
  if (root) rmSync(root, { recursive: true, force: true });
  root = undefined;
});

/** Writes a rules directory with one rule and the given fixture files. */
async function compile(fixtures: Record<string, string>, requires = "[workers]", sql?: string) {
  root = mkdtempSync(join(tmpdir(), "virga-rules-"));
  const dir = join(root, "CF-999");
  mkdirSync(join(dir, "fixtures"), { recursive: true });
  writeFileSync(join(dir, "rule.sql"), rule(requires, sql));
  for (const [file, content] of Object.entries(fixtures)) {
    writeFileSync(join(dir, "fixtures", file), content);
  }
  return compileRules(root);
}

describe("compileRules: fixture checks", () => {
  it("accepts positive, negative and undecided fixtures", async () => {
    const result = await compile({
      "positive-a.yaml": FIXTURES.hit,
      "negative-a.yaml": FIXTURES.none,
      "undecided-a.yaml": FIXTURES.undecided,
    });
    expect(result.errors).toEqual([]);
    expect(result.fixtures.map((f) => f.name)).toEqual(["negative-a", "positive-a", "undecided-a"]);
  });

  it.each([
    ["another prefix", "edge-case.yaml"],
    ["no prefix", "a.yaml"],
    ["a prefix without a name", "positive.yaml"],
    ["another extension", "positive-b.yml"],
  ])("rejects a fixture file with %s", async (_, file) => {
    const result = await compile({
      "positive-a.yaml": FIXTURES.hit,
      "negative-a.yaml": FIXTURES.none,
      [file]: FIXTURES.hit,
    });
    expect(result.errors).toEqual([
      `CF-999/fixtures/${file}: fixture files are named positive-, negative- or undecided-<name>.yaml`,
    ]);
  });

  it("rejects a positive fixture that expects only undecided rows", async () => {
    const result = await compile({
      "positive-a.yaml": FIXTURES.hit,
      "positive-b.yaml": FIXTURES.undecided,
      "negative-a.yaml": FIXTURES.none,
    });
    expect(result.errors).toEqual([
      expect.stringMatching(/positive-b\.yaml: a positive fixture must expect at least one hit/),
    ]);
  });

  it("rejects a negative fixture that expects an undecided row", async () => {
    const result = await compile({
      "positive-a.yaml": FIXTURES.hit,
      "negative-a.yaml": FIXTURES.none,
      "negative-b.yaml": FIXTURES.undecided,
    });
    expect(result.errors).toEqual([
      expect.stringMatching(/negative-b\.yaml: a negative fixture must expect no rows/),
    ]);
  });

  it.each([
    ["only hits", FIXTURES.hit],
    ["no rows", FIXTURES.none],
  ])("rejects an undecided fixture that expects %s", async (_, content) => {
    const result = await compile({
      "positive-a.yaml": FIXTURES.hit,
      "negative-a.yaml": FIXTURES.none,
      "undecided-a.yaml": content,
    });
    expect(result.errors).toEqual([
      expect.stringMatching(
        /undecided-a\.yaml: an undecided fixture must expect at least one undecided row/,
      ),
    ]);
  });

  it("accepts hits next to undecided rows in positive and undecided fixtures", async () => {
    const both = `nodes: [{ type: worker_script, id: a }, { type: worker_script, id: b, props: { decided: 0 } }]
expect: [{ fingerprint: "${fingerprint}" }, { fingerprint: "CF-999:worker_script:b", decided: false }]
`;
    const result = await compile({
      "positive-a.yaml": both,
      "negative-a.yaml": FIXTURES.none,
      "undecided-a.yaml": both,
    });
    expect(result.errors).toEqual([]);
  });

  it("still needs a positive and a negative fixture", async () => {
    const result = await compile({ "undecided-a.yaml": FIXTURES.undecided });
    expect(result.errors).toEqual([
      "CF-999: needs at least one positive-*.yaml and one negative-*.yaml fixture",
    ]);
  });

  it("needs an undecided fixture when the rule requires exposure", async () => {
    const fixtures = { "positive-a.yaml": FIXTURES.hit, "negative-a.yaml": FIXTURES.none };
    const requires = "[workers, access, exposure]";
    expect((await compile(fixtures, requires)).errors).toEqual([
      "CF-999: requires exposure, so it needs an undecided-*.yaml fixture for unknown exposure",
    ]);
    expect(
      (await compile({ ...fixtures, "undecided-a.yaml": FIXTURES.undecided }, requires)).errors,
    ).toEqual([]);
  });

  it("reports a rule without a fixtures directory", async () => {
    root = mkdtempSync(join(tmpdir(), "virga-rules-"));
    mkdirSync(join(root, "CF-999"));
    writeFileSync(join(root, "CF-999", "rule.sql"), rule("[workers]"));
    const result = await compileRules(root);
    expect(result.errors).toEqual([expect.stringMatching(/^CF-999: no fixtures directory/)]);
  });
});

/** Worker scripts unless Access protects them: reads exposure through `table`. */
const readsExposure = (table = "exposure") => `${SELECT_SCRIPTS}
  AND NOT EXISTS (SELECT 1 FROM ${table} x WHERE x.entry_id = id AND x.decision = 'access')`;

const ALL_FIXTURES = {
  "positive-a.yaml": FIXTURES.hit,
  "negative-a.yaml": FIXTURES.none,
  "undecided-a.yaml": FIXTURES.undecided,
};

describe("compileRules: inputs from the tables a rule reads", () => {
  it("R4-04: rejects a rule that reads exposure without requiring exposure and access", async () => {
    const result = await compile(ALL_FIXTURES, "[workers]", readsExposure());
    expect(result.errors).toEqual([
      "CF-999/rule.sql: reads exposure, so requires must also list access, exposure",
    ]);
    expect(result.rules).toEqual([]);
  });

  it("R4-04: rejects a rule that reads exposure and requires it, but not access", async () => {
    const result = await compile(ALL_FIXTURES, "[workers, exposure]", readsExposure());
    expect(result.errors).toEqual([
      "CF-999/rule.sql: reads exposure, so requires must also list access",
    ]);
  });

  it.each([
    ["a quoted name", '"exposure"'],
    ["a schema name", "main.exposure"],
    ["a comment before the name", "/* table */ exposure"],
    ["brackets", "[exposure]"],
    ["backticks", "`exposure`"],
    ["a view of it in a CTE", "(WITH e AS (SELECT * FROM exposure) SELECT * FROM e)"],
  ])("R4-04: finds the exposure table behind %s", async (_, table) => {
    const result = await compile(ALL_FIXTURES, "[workers]", readsExposure(table));
    expect(result.errors).toEqual([
      "CF-999/rule.sql: reads exposure, so requires must also list access, exposure",
    ]);
  });

  it.each([
    ["vulns", "vulns", "vulns"],
    ["insights", "insights", "insights"],
  ])("R4-04: rejects a rule that reads %s without requiring it", async (_, table, input) => {
    const sql = `${SELECT_SCRIPTS}\n  AND NOT EXISTS (SELECT 1 FROM ${table})`;
    const result = await compile(ALL_FIXTURES, "[workers]", sql);
    expect(result.errors).toEqual([
      `CF-999/rule.sql: reads ${table}, so requires must also list ${input}`,
    ]);
    expect((await compile(ALL_FIXTURES, `[workers, ${input}]`, sql)).errors).toEqual([]);
  });

  it("R4-04: accepts a rule that reads exposure and requires exposure and access", async () => {
    const result = await compile(ALL_FIXTURES, "[workers, access, exposure]", readsExposure());
    expect(result.errors).toEqual([]);
    expect(result.rules.map((r) => r.requires)).toEqual([["workers", "access", "exposure"]]);
  });

  it("R4-04: needs an undecided fixture when the rule reads exposure", async () => {
    const fixtures = { "positive-a.yaml": FIXTURES.hit, "negative-a.yaml": FIXTURES.none };
    const result = await compile(fixtures, "[workers, access, exposure]", readsExposure());
    expect(result.errors).toEqual([
      "CF-999: reads exposure, so it needs an undecided-*.yaml fixture for unknown exposure",
    ]);
  });

  it("R4-04: fails the review's copy of CF-004 that drops exposure from requires", async () => {
    root = mkdtempSync(join(tmpdir(), "virga-rules-"));
    const dir = join(root, "CF-004");
    cpSync(fileURLToPath(new URL("../../../rules/CF-004", import.meta.url)), dir, {
      recursive: true,
    });
    const file = join(dir, "rule.sql");
    const source = readFileSync(file, "utf8");
    const changed = source.replace(
      "-- requires: [tunnels, access, exposure]",
      "-- requires: [tunnels, access]",
    );
    expect(changed).not.toBe(source);
    writeFileSync(file, changed);
    for (const fixture of readdirSync(join(dir, "fixtures"))) {
      if (fixture.startsWith("undecided-")) rmSync(join(dir, "fixtures", fixture));
    }
    expect((await compileRules(root)).errors).toEqual([
      "CF-004/rule.sql: reads exposure, so requires must also list exposure",
      "CF-004: reads exposure, so it needs an undecided-*.yaml fixture for unknown exposure",
    ]);
  });
});

describe("compileRules: rules only read", () => {
  // The review's CF-998: a CTE in front of DML passes the SELECT/WITH check.
  const RETURNING = `RETURNING 'CF-999' AS rule_id, 'CF-999:' || key AS fingerprint,
  'low' AS severity, key AS subject_id`;

  it.each([
    [
      "an INSERT",
      "meta",
      `WITH z AS (SELECT id FROM nodes WHERE type = 'zone')
INSERT INTO meta (key, value) SELECT 'current_scan', 'forged' FROM z WHERE true
ON CONFLICT (key) DO UPDATE SET value = excluded.value ${RETURNING}`,
    ],
    [
      "an UPDATE",
      "meta",
      `WITH z AS (SELECT 1) UPDATE meta SET value = 'forged' WHERE key = 'current_scan' ${RETURNING}`,
    ],
    [
      "a DELETE",
      "findings",
      `WITH z AS (SELECT 1) DELETE FROM findings
RETURNING 'CF-999' AS rule_id, fingerprint, 'low' AS severity, fingerprint AS subject_id`,
    ],
    [
      "a REPLACE",
      "meta",
      `WITH z AS (SELECT 1) REPLACE INTO meta (key, value) VALUES ('current_scan', 'forged') ${RETURNING}`,
    ],
  ])("R4-05: rejects %s behind a CTE, with RETURNING", async (_, table, sql) => {
    const result = await compile(ALL_FIXTURES, "[workers]", sql);
    expect(result.errors).toEqual([`CF-999: writes to ${table}; a rule may only read`]);
    expect(result.rules).toEqual([]);
    expect(result.fixtures).toEqual([]);
  });

  it("R4-05: rejects a write without RETURNING for the write, not for its columns", async () => {
    const sql = "WITH z AS (SELECT 1) DELETE FROM exposure";
    expect((await compile(ALL_FIXTURES, "[workers]", sql)).errors).toEqual([
      "CF-999: writes to exposure; a rule may only read",
    ]);
  });
});

/** Writes a rules directory with the given rule file and fixtures, and compiles it. */
async function compileSource(id: string, source: string, fixtures: Record<string, string>) {
  root = mkdtempSync(join(tmpdir(), "virga-rules-"));
  const dir = join(root, id);
  mkdirSync(join(dir, "fixtures"), { recursive: true });
  writeFileSync(join(dir, "rule.sql"), source);
  for (const [file, content] of Object.entries(fixtures)) {
    writeFileSync(join(dir, "fixtures", file), content);
  }
  return compileRules(root);
}

describe("compileRules: one statement (R6-02)", () => {
  it.each(Object.entries(REVIEW_RULES))("refuses the review's %s", async (id, source) => {
    const result = await compileSource(id, source, reviewFixtures(id));
    expect(result.errors).toEqual([`${id}/rule.sql: a rule must contain exactly one statement`]);
    expect(result.rules).toEqual([]);
    expect(result.fixtures).toEqual([]);
  });

  it("refuses a statement after [x--]; on the same line", async () => {
    const sql = `${SELECT_SCRIPTS.replace("FROM nodes", "FROM nodes AS [x--]")}; DELETE FROM findings`;
    expect((await compile(ALL_FIXTURES, "[workers]", sql)).errors).toEqual([
      "CF-999/rule.sql: a rule must contain exactly one statement",
    ]);
  });

  it("refuses a statement after a backtick identifier holding --", async () => {
    const sql = `${SELECT_SCRIPTS.replace("FROM nodes", "FROM nodes AS `x--`")}; DELETE FROM findings`;
    expect((await compile(ALL_FIXTURES, "[workers]", sql)).errors).toEqual([
      "CF-999/rule.sql: a rule must contain exactly one statement",
    ]);
  });

  it("accepts [x--]; at the end and drops the semicolon", async () => {
    const sql = `${SELECT_SCRIPTS} AND id NOT IN (SELECT id FROM nodes AS [x--] WHERE false);`;
    const result = await compile(ALL_FIXTURES, "[workers]", sql);
    expect(result.errors).toEqual([]);
    expect(result.rules[0]?.sql.endsWith("WHERE false)")).toBe(true);
  });

  it.each(["[a;b]", "`a;b`", "[a:b]"])("keeps %s as one column name", async (name) => {
    const sql = SELECT_SCRIPTS.replace(" AS decided", ` AS decided, 1 AS ${name}`);
    const result = await compile(ALL_FIXTURES, "[workers]", sql);
    expect(result.errors).toEqual([]);
    expect(result.rules[0]?.sql).toContain(`1 AS ${name}`);
    expect(result.rules[0]?.paramOrder).toEqual([]);
  });
});

describe("compileRules: statement size", () => {
  it("refuses a statement too large for Durable Object SQLite", async () => {
    const cases = Array.from({ length: 8000 }, (_, i) => `WHEN '${i}' THEN ${i}`).join(" ");
    const sql = SELECT_SCRIPTS.replace(" AS decided", ` AS decided, CASE id ${cases} END AS big`);
    const [error] = (await compile(ALL_FIXTURES, "[workers]", sql)).errors;
    expect(error).toMatch(/^CF-999: compiles to \d+ operations; Durable Object SQLite accepts/);
  });
});
