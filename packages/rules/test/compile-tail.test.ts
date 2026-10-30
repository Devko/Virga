import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { compileRules } from "../src/compile.ts";
import { REVIEW_RULES, reviewFixtures } from "./review-rules.ts";

// A parameter scan that, like the one before R6-02, misses everything after
// the first statement: the compiler must still refuse the tail from what
// SQLite compiles.
vi.mock("../src/params.ts", () => ({
  compileParams: (source: string) => ({ sql: source.trim(), order: [] }),
}));

let root: string | undefined;
afterEach(() => {
  if (root) rmSync(root, { recursive: true, force: true });
  root = undefined;
});

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

const zoneRule = (body: string) => `-- ---
-- id: CF-997
-- version: 1
-- title: Zone exists
-- severity: low
-- kind: posture
-- requires: [zones]
-- ---
SELECT 'CF-997' AS rule_id, 'CF-997:' || id AS fingerprint, 'low' AS severity, id AS subject_id
FROM nodes WHERE type = 'zone' AND deleted_at IS NULL${body}
`;

describe("compileRules: no statement tail (R6-02)", () => {
  it.each(Object.entries(REVIEW_RULES))("refuses the review's %s", async (id, source) => {
    const result = await compileSource(id, source, reviewFixtures(id));
    expect(result.errors).toEqual([
      expect.stringMatching(
        new RegExp(`^${id}: text after the first statement \\(".+"\\); a rule is one statement$`),
      ),
    ]);
    expect(result.rules).toEqual([]);
    expect(result.fixtures).toEqual([]);
  });

  it.each([
    ["a second semicolon", ";;"],
    ["a NUL before a statement", "\u0000; DELETE FROM findings"],
    ["an unterminated comment", "; /* open"],
  ])("refuses %s", async (_, body) => {
    const result = await compileSource("CF-997", zoneRule(body), reviewFixtures("CF-997"));
    expect(result.errors).toEqual([
      expect.stringMatching(/^CF-997: text after the first statement .*; a rule is one statement$/),
    ]);
  });

  it.each([
    ["nothing", ""],
    ["one semicolon", ";"],
    ["a semicolon, whitespace and comments", " ;\n-- done\n/* end */\t"],
  ])("accepts %s after the statement", async (_, body) => {
    const result = await compileSource("CF-997", zoneRule(body), reviewFixtures("CF-997"));
    expect(result.errors).toEqual([]);
    expect(result.rules.map((r) => r.id)).toEqual(["CF-997"]);
  });
});
