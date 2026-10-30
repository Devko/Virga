import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { compileRules } from "../src/compile.ts";

const rule = (requires: string) => `-- ---
-- id: CF-999
-- version: 1
-- title: Test
-- severity: low
-- kind: posture
-- requires: ${requires}
-- ---
SELECT 'CF-999' AS rule_id, 'CF-999:' || id AS fingerprint, 'low' AS severity,
       id AS subject_id, COALESCE(props ->> '$.decided', 1) AS decided
FROM nodes WHERE type = 'worker_script' AND deleted_at IS NULL
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
async function compile(fixtures: Record<string, string>, requires = "[workers]") {
  root = mkdtempSync(join(tmpdir(), "virga-rules-"));
  const dir = join(root, "CF-999");
  mkdirSync(join(dir, "fixtures"), { recursive: true });
  writeFileSync(join(dir, "rule.sql"), rule(requires));
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
