import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CREDENTIAL_VARS } from "../lib/run.ts";
import { REPO_ROOT } from "./helpers.ts";

/**
 * Runs scripts/deploy.ts from a copy of scripts/ in an empty checkout: it has
 * no apps, so whatever the script gets to, it never starts Wrangler.
 */
describe("deploy.ts", () => {
  let root = "";
  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "virga-deploy-"));
    cpSync(join(REPO_ROOT, "scripts", "deploy.ts"), join(root, "scripts", "deploy.ts"));
    cpSync(join(REPO_ROOT, "scripts", "lib"), join(root, "scripts", "lib"), { recursive: true });
    writeFileSync(join(root, "package.json"), '{ "type": "module" }');
  });
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  const deploy = (args: string[], extra: Record<string, string>) => {
    const env: NodeJS.ProcessEnv = { ...process.env, ...extra };
    for (const name of CREDENTIAL_VARS) delete env[name];
    return spawnSync(process.execPath, [join(root, "scripts", "deploy.ts"), ...args], {
      env,
      encoding: "utf8",
      timeout: 20_000,
    });
  };

  it("R3-03: refuses to run while CLOUDFLARE_ENV selects a named environment", () => {
    const result = deploy(["--dry-run"], { CLOUDFLARE_ENV: "prod" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("error: unset CLOUDFLARE_ENV");
    // Refused before reading any config.
    expect(result.stderr).not.toContain("wrangler.jsonc");
  });

  it("R3-03: takes no --env", () => {
    const result = deploy(["--dry-run", "--env", "prod"], {});
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("usage: node scripts/deploy.ts [--dry-run]");
  });
});
