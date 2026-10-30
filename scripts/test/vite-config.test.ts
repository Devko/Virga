import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { REPO_ROOT } from "./helpers.ts";

/**
 * Runs the SPA build of apps/web (its vite.config.ts and Vite) on a small SPA
 * in a temporary directory. Vite copies spa/public into the assets and
 * follows symlinks while it copies, so a link there would publish its target.
 */
describe("apps/web/vite.config.ts", () => {
  const web = join(REPO_ROOT, "apps", "web");
  let dir = "";
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "virga-spa-"));
    mkdirSync(join(dir, "spa", "public", "icons"), { recursive: true });
    mkdirSync(join(dir, "outside"));
    writeFileSync(join(dir, "outside", "id_ed25519"), "a private key");
    writeFileSync(
      join(dir, "spa", "index.html"),
      '<!doctype html><script type="module" src="./main.js"></script>',
    );
    writeFileSync(join(dir, "spa", "main.js"), 'document.title = "virga";');
    writeFileSync(join(dir, "spa", "public", "icons", "favicon.svg"), "<svg/>");
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const build = () => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.NODE_OPTIONS;
    return spawnSync(
      process.execPath,
      [
        join(web, "node_modules", "vite", "bin", "vite.js"),
        "build",
        "--config",
        join(web, "vite.config.ts"),
        "--logLevel",
        "error",
      ],
      { cwd: dir, env, encoding: "utf8", timeout: 60_000 },
    );
  };
  const client = join("dist", "client");

  it("R6-01: copies a public directory of plain files", () => {
    const result = build();
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    expect(readFileSync(join(dir, client, "icons", "favicon.svg"), "utf8")).toBe("<svg/>");
  });

  it("R6-01: fails on a symlink to a file in the public directory", () => {
    symlinkSync(join(dir, "outside", "id_ed25519"), join(dir, "spa", "public", "icons", "key.svg"));
    const result = build();
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      `${join(dir, "spa", "public", "icons", "key.svg")}: the public directory holds a symlink`,
    );
    expect(readdirSync(dir)).not.toContain("dist");
  });

  it("R6-01: fails on a linked directory, and on a public directory that is a link", () => {
    symlinkSync(join(dir, "outside"), join(dir, "spa", "public", "home"));
    let result = build();
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(`${join(dir, "spa", "public", "home")}: the public directory`);

    rmSync(join(dir, "spa", "public"), { recursive: true });
    symlinkSync(join(dir, "outside"), join(dir, "spa", "public"));
    result = build();
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(`${join(dir, "spa", "public")}: the public directory`);
    expect(readdirSync(dir)).not.toContain("dist");
  });
});
