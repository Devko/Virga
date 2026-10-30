import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { checkGenerated, GENERATED_FILES } from "../src/generate.ts";

const PACKAGE = fileURLToPath(new URL("..", import.meta.url));
const SRC = join(PACKAGE, "src");
const RULES_DIR = fileURLToPath(new URL("../../../rules/", import.meta.url));

/** The first rule's SQL in a generated module, with a statement added after it by hand. */
const withTail = (text: string) =>
  text.replace(/("sql": "(?:[^"\\]|\\.)*)"/, '$1;\\nDELETE FROM exposure"');

let root: string | undefined;
afterEach(() => {
  if (root) rmSync(root, { recursive: true, force: true });
  root = undefined;
});
const temp = () => {
  root = mkdtempSync(join(tmpdir(), "virga-generate-"));
  return root;
};

describe("checkGenerated", () => {
  it("R8-05: finds the committed generated modules equal to the compiler output", async () => {
    const result = await checkGenerated();
    expect(result.errors).toEqual([]);
    expect(result.rules).toBeGreaterThan(0);
    expect(result.fixtures).toBeGreaterThan(result.rules);
    expect(result.files.map((f) => [f.name, f.path, f.stale])).toEqual(
      GENERATED_FILES.map((name) => [name, join(SRC, name), false]),
    );
    for (const file of result.files) {
      expect(Buffer.from(file.content).equals(readFileSync(file.path)), file.name).toBe(true);
    }
  });

  it("R8-05: names a generated module whose bytes are not the compiler output", async () => {
    const outDir = temp();
    const rules = readFileSync(join(SRC, "rules.gen.ts"), "utf8");
    expect(withTail(rules)).not.toBe(rules);
    writeFileSync(join(outDir, "rules.gen.ts"), withTail(rules));
    cpSync(join(SRC, "fixtures.gen.ts"), join(outDir, "fixtures.gen.ts"));
    let result = await checkGenerated({ rulesDir: RULES_DIR, outDir });
    expect(result.errors).toEqual([]);
    expect(result.files.filter((f) => f.stale).map((f) => f.name)).toEqual(["rules.gen.ts"]);

    // A missing module, and one with other line endings, are stale too.
    rmSync(join(outDir, "rules.gen.ts"));
    writeFileSync(
      join(outDir, "fixtures.gen.ts"),
      readFileSync(join(SRC, "fixtures.gen.ts"), "utf8").replaceAll("\n", "\r\n"),
    );
    result = await checkGenerated({ rulesDir: RULES_DIR, outDir });
    expect(result.files.filter((f) => f.stale).map((f) => f.name)).toEqual([
      "rules.gen.ts",
      "fixtures.gen.ts",
    ]);
  });

  it("R8-05: returns the compiler's errors and compares nothing", async () => {
    const dir = temp();
    const rulesDir = join(dir, "rules");
    cpSync(join(RULES_DIR, "CF-003"), join(rulesDir, "CF-003"), { recursive: true });
    const sql = join(rulesDir, "CF-003", "rule.sql");
    writeFileSync(sql, `${readFileSync(sql, "utf8").trimEnd()};\nDELETE FROM exposure\n`);
    const result = await checkGenerated({ rulesDir, outDir: join(dir, "out") });
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors.join("\n")).toMatch(/\bCF-003\b/);
    expect(result.files).toEqual([]);
  });
});

/**
 * cli.ts in a copy of this package, with a copy of rules/ and the package's
 * dependencies through a link to its node_modules.
 */
describe("cli.ts", () => {
  const checkout = () => {
    const dir = temp();
    cpSync(SRC, join(dir, "packages", "rules", "src"), { recursive: true });
    cpSync(join(PACKAGE, "package.json"), join(dir, "packages", "rules", "package.json"));
    symlinkSync(
      join(PACKAGE, "node_modules"),
      join(dir, "packages", "rules", "node_modules"),
      "junction",
    );
    cpSync(RULES_DIR, join(dir, "rules"), { recursive: true });
    return join(dir, "packages", "rules", "src");
  };
  const cli = (src: string, ...args: string[]) => {
    const result = spawnSync(process.execPath, [join(src, "cli.ts"), ...args], {
      encoding: "utf8",
      timeout: 60_000,
    });
    // Node's SQLite warns on load that it is experimental.
    const stderr = result.stderr
      .split("\n")
      .filter((line) => !/ExperimentalWarning: SQLite|--trace-warnings/.test(line))
      .join("\n");
    return { status: result.status, stdout: result.stdout, stderr };
  };

  it("R8-05: keeps the output and exit codes of check and build", { timeout: 60_000 }, async () => {
    const src = checkout();
    const { rules, fixtures } = await checkGenerated();
    const passed = `${rules} rule(s), ${fixtures} fixture(s) passed\n`;
    expect(cli(src, "check")).toEqual({ status: 0, stdout: passed, stderr: "" });

    const committed = readFileSync(join(src, "rules.gen.ts"), "utf8");
    writeFileSync(join(src, "rules.gen.ts"), withTail(committed));
    rmSync(join(src, "fixtures.gen.ts"));
    expect(cli(src, "check")).toEqual({
      status: 1,
      stdout: "",
      stderr:
        "error: rules.gen.ts is out of date; run pnpm rules:build\nerror: fixtures.gen.ts is out of date; run pnpm rules:build\n",
    });
    expect(readFileSync(join(src, "rules.gen.ts"), "utf8")).toBe(withTail(committed));

    expect(cli(src, "build")).toEqual({ status: 0, stdout: passed, stderr: "" });
    for (const name of GENERATED_FILES) {
      expect(readFileSync(join(src, name), "utf8"), name).toBe(
        readFileSync(join(SRC, name), "utf8"),
      );
    }

    const sql = join(src, "..", "..", "..", "rules", "CF-003", "rule.sql");
    writeFileSync(sql, `${readFileSync(sql, "utf8").trimEnd()};\nDELETE FROM exposure\n`);
    const failing = cli(src, "check");
    expect(failing.status).toBe(1);
    expect(failing.stdout).toBe("");
    expect(failing.stderr).toMatch(/^error: CF-003\b/);

    expect(cli(src)).toEqual({ status: 2, stdout: "", stderr: "usage: cli.ts build|check\n" });
  });
});
