import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { REPO_ROOT } from "./helpers.ts";

const RANGE = join(REPO_ROOT, "infra", "test-range");
const tf = (file: string) => readFileSync(join(RANGE, file), "utf8");

/** The paths of `paths` that the repository's .gitignore ignores, as git decides it. */
function ignored(paths: readonly string[]): string[] {
  const dir = mkdtempSync(join(tmpdir(), "virga-gitignore-"));
  try {
    expect(spawnSync("git", ["init", "-q", dir]).status).toBe(0);
    copyFileSync(join(REPO_ROOT, ".gitignore"), join(dir, ".gitignore"));
    const result = spawnSync("git", ["-C", dir, "check-ignore", "--no-index", "--stdin"], {
      input: paths.join("\n"),
      encoding: "utf8",
    });
    return result.stdout.split("\n").filter((line) => line !== "");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The text of a top-level block, from its header line to the closing brace at column 0. */
function block(text: string, header: string): string {
  const start = text.indexOf(`\n${header} {\n`);
  expect(start, header).toBeGreaterThan(-1);
  const end = text.indexOf("\n}\n", start);
  return text.slice(start + 1, end + 2);
}

describe("test range (round 9 hardening, Terraform)", () => {
  it("test range: .gitignore keeps saved plans and every variable file out of git", () => {
    const secret = [
      "infra/test-range/tfplan",
      "infra/test-range/range.tfplan",
      "infra/test-range/terraform.tfvars",
      "infra/test-range/terraform.tfvars.json",
      "infra/test-range/local.auto.tfvars",
      "infra/test-range/local.auto.tfvars.json",
      "infra/test-range/terraform.tfstate",
      "infra/test-range/terraform.tfstate.backup",
    ];
    expect(ignored([...secret, "infra/test-range/terraform.tfvars.example"])).toEqual(secret);
  });

  it("test range: every resource takes its account and zone from the checked zone data source", () => {
    const files = readdirSync(RANGE).filter((file) => file.endsWith(".tf"));
    const zone = block(tf("main.tf"), 'data "cloudflare_zone" "range"');
    for (const file of files.filter((file) => file !== "variables.tf")) {
      const text = file === "main.tf" ? tf(file).replace(zone, "") : tf(file);
      expect(text, file).not.toMatch(/\bvar\.(?:account_id|zone_id)\b/);
    }
    expect(tf("main.tf")).toMatch(/^ {2}account_id = data\.cloudflare_zone\.range\.account\.id$/m);
    expect(tf("main.tf")).toMatch(/^ {2}zone_id {4}= data\.cloudflare_zone\.range\.id$/m);
    expect(zone).toMatch(/^ {2}zone_id = var\.zone_id$/m);
  });

  it("test range: the zone data source refuses another account, another name and no confirmation", () => {
    const zone = block(tf("main.tf"), 'data "cloudflare_zone" "range"');
    const conditions = (kind: string) =>
      [...zone.matchAll(new RegExp(`${kind} \\{\\n\\s+condition\\s+= (.+)\\n`, "g"))].map(
        (match) => match[1],
      );
    expect(conditions("precondition")).toEqual(["var.dedicated_test_account"]);
    // Terraform evaluates self only in postconditions, after the read.
    expect(conditions("postcondition")).toEqual([
      "self.id == var.zone_id",
      "try(self.account.id, null) == var.account_id",
      "self.name == var.zone_name",
    ]);
  });
});
