import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { API_VARS, CREDENTIAL_VARS, OVERRIDE_VARS } from "../lib/run.ts";
import { REPO_ROOT } from "./helpers.ts";

/**
 * Runs scripts/deploy.ts from a copy of scripts/ in a checkout without
 * Wrangler: whatever the script gets to, it never starts Wrangler.
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
  afterEach(() => rmSync(join(root, "apps"), { recursive: true, force: true }));

  const deploy = (args: string[], extra: Record<string, string>) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    for (const name of [...CREDENTIAL_VARS, ...OVERRIDE_VARS, ...Object.keys(API_VARS)]) {
      delete env[name];
    }
    return spawnSync(process.execPath, [join(root, "scripts", "deploy.ts"), ...args], {
      env: { ...env, ...extra },
      encoding: "utf8",
      timeout: 20_000,
    });
  };
  /** The committed configs of every app, with `files` added to the app directories. */
  const apps = (files: Record<string, string>) => {
    for (const app of ["broker", "core", "web"]) {
      mkdirSync(join(root, "apps", app), { recursive: true });
      cpSync(
        join(REPO_ROOT, "apps", app, "wrangler.jsonc"),
        join(root, "apps", app, "wrangler.jsonc"),
      );
    }
    for (const [path, text] of Object.entries(files)) writeFileSync(join(root, "apps", path), text);
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

  it("R5-03: refuses an API base URL in the operator's environment", () => {
    for (const name of ["CLOUDFLARE_API_BASE_URL", "CF_API_BASE_URL"]) {
      const result = deploy(["--dry-run"], { [name]: "http://127.0.0.1:18787/client/v4" });
      expect(result.status, name).toBe(1);
      expect(result.stderr).toContain(`error: unset ${name}; the deploy sends the token only to`);
      expect(result.stderr).not.toContain("wrangler.jsonc");
    }
  });

  it("R5-03: refuses to run while an app has a .env file that would redirect the token", () => {
    apps({ "broker/.env": "CLOUDFLARE_API_BASE_URL=http://127.0.0.1:18787/client/v4\n" });
    const result = deploy(["--dry-run"], {});
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "error: apps/broker/.env: Wrangler would load it into its environment",
    );
    expect(result.stdout).not.toContain("Configs:");
  });

  it("R5-03: refuses .env, .env.local and .dev.vars files that would rename or reselect a Worker", () => {
    const override = "CLOUDFLARE_ENV=prod\nWRANGLER_CI_OVERRIDE_NAME=virga-broker\n";
    for (const file of [".env", ".env.local", ".dev.vars"]) {
      apps({ [`web/${file}`]: override });
      const result = deploy(["--dry-run"], {});
      expect(result.status, file).toBe(1);
      expect(result.stderr).toContain(`error: apps/web/${file}: Wrangler would load it`);
      rmSync(join(root, "apps"), { recursive: true, force: true });
    }
  });
});
