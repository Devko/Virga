import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { devNull, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PROXY_VARS, UNSAFE_VARS } from "../lib/run.ts";
import { type FakeWrangler, fakeWrangler, put, REPO_ROOT } from "./helpers.ts";

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
    // The test's own Cloudflare, Wrangler, proxy and Node settings stay out.
    const env: NodeJS.ProcessEnv = { ...process.env };
    for (const name of Object.keys(env)) {
      if (
        /^(?:CLOUDFLARE|CF|WRANGLER)_/i.test(name) ||
        PROXY_VARS.includes(name) ||
        Object.hasOwn(UNSAFE_VARS, name)
      ) {
        delete env[name];
      }
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

  it("R6-01: refuses a symlink under an app directory before anything runs", () => {
    apps({ "web/package.json": '{ "scripts": { "build": "vite build" } }' });
    mkdirSync(join(root, "apps", "web", "spa", "public"), { recursive: true });
    writeFileSync(join(root, "id_ed25519"), "a private key");
    symlinkSync(join(root, "id_ed25519"), join(root, "apps", "web", "spa", "public", "key.svg"));
    const result = deploy(["--dry-run"], {});
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "error: apps/web holds symlinks outside node_modules: apps/web/spa/public/key.svg.",
    );
    expect(result.stdout).not.toMatch(/Building|Configs:/);
  });

  it("R5-03: refuses NODE_OPTIONS, whose code runs in the deploy before it could drop it", () => {
    const probe = join(root, "probe.cjs");
    writeFileSync(probe, 'process.stdout.write("probe loaded\\n");');
    const result = deploy(["--dry-run"], { NODE_OPTIONS: `--require ${probe}` });
    expect(result.stdout).toContain("probe loaded");
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("error: unset NODE_OPTIONS: it can load code");
    // Refused before reading any config.
    expect(result.stderr).not.toContain("wrangler.jsonc");
  });

  it("R5-03: refuses NODE_TLS_REJECT_UNAUTHORIZED, also in a dry run", () => {
    for (const value of ["0", "1"]) {
      const result = deploy(["--dry-run"], { NODE_TLS_REJECT_UNAUTHORIZED: value });
      expect(result.status, value).toBe(1);
      expect(result.stderr).toContain("error: unset NODE_TLS_REJECT_UNAUTHORIZED: it turns off");
      expect(result.stderr).toContain("NODE_EXTRA_CA_CERTS");
    }
  });

  it("R7-01: refuses NODE_DEBUG and NODE_DEBUG_NATIVE, also in a dry run", () => {
    for (const [name, value] of [
      ["NODE_DEBUG", "child_process"],
      ["NODE_DEBUG", "http,tls"],
      ["NODE_DEBUG_NATIVE", "INSPECTOR_SERVER"],
    ] as const) {
      const result = deploy(["--dry-run"], {
        [name]: value,
        CLOUDFLARE_API_TOKEN: "cfat_R701SECRETabcdefghijklmnopqrstuvwxyz0123",
      });
      expect(result.status, `${name}=${value}`).toBe(1);
      expect(result.stderr).toContain(`error: unset ${name}: `);
      expect(result.stdout + result.stderr).not.toContain("R701SECRET");
      // Refused before reading any config.
      expect(result.stderr).not.toContain("wrangler.jsonc");
    }
  });

  it("R7-02: refuses the loader's library search paths and NODE_COMPILE_CACHE, also in a dry run", () => {
    for (const name of [
      "LD_LIBRARY_PATH",
      "DYLD_LIBRARY_PATH",
      "DYLD_FALLBACK_LIBRARY_PATH",
      "DYLD_FRAMEWORK_PATH",
      "DYLD_FALLBACK_FRAMEWORK_PATH",
      "DYLD_VERSIONED_LIBRARY_PATH",
      "DYLD_VERSIONED_FRAMEWORK_PATH",
      "NODE_COMPILE_CACHE",
    ]) {
      const result = deploy(["--dry-run"], { [name]: join(root, "planted") });
      expect(result.status, name).toBe(1);
      expect(result.stderr).toContain(`error: unset ${name}: `);
      expect(result.stderr).not.toContain("wrangler.jsonc");
    }
  });

  it("R5-03: prints the proxy settings it passes to Wrangler, without credentials", () => {
    const result = deploy(["--dry-run"], {
      HTTPS_PROXY: "http://alice:s3cret-pass@proxy.example:3128",
      NODE_EXTRA_CA_CERTS: "/etc/ssl/proxy-ca.pem",
    });
    expect(result.stdout).toContain(
      "Proxy settings passed to Wrangler:\n  HTTPS_PROXY: proxy.example:3128 (credentials not shown)\n  NODE_EXTRA_CA_CERTS: /etc/ssl/proxy-ca.pem;",
    );
    expect(result.stdout + result.stderr).not.toMatch(/alice|s3cret/);
  });

  it("R5-03: names the Cloudflare and Wrangler variables it does not pass to Wrangler", () => {
    const result = deploy(["--dry-run"], {
      CLOUDFLARE_API_TOKEN: "the-deploy-token-value",
      WRANGLER_LOG: "debug",
      CLOUDFLARE_INCLUDE_PROCESS_ENV: "true",
    });
    expect(result.stdout).toContain(
      "Wrangler does not get CLOUDFLARE_API_TOKEN, CLOUDFLARE_INCLUDE_PROCESS_ENV, WRANGLER_LOG",
    );
    expect(result.stdout + result.stderr).not.toContain("the-deploy-token-value");
  });
});

/**
 * A stand-in Wrangler bin file. It logs each call with its app and whether
 * it holds the token, and, when asked through a file, rewrites the web config
 * from the broker's call, as a process left running by a build could.
 */
const LOGGING_BIN = String.raw`const { appendFileSync, existsSync } = require("node:fs");
const { basename, join, resolve } = require("node:path");
const root = resolve(__dirname, "../../../../../..");
const app = basename(process.cwd());
const token = process.env.CLOUDFLARE_API_TOKEN ? "token" : "no-token";
appendFileSync(join(root, "calls.log"), app + " " + token + " " + process.argv.slice(2).join(" ") + "\n");
if (app === "broker" && existsSync(join(root, "rewrite-later"))) {
  appendFileSync(join(root, "apps", "web", "wrangler.jsonc"), "\n");
}
`;

/** A web build that fills the assets directory, as vite build does. */
const BUILD = `import { mkdirSync, writeFileSync } from "node:fs";
mkdirSync("dist/client", { recursive: true });
writeFileSync("dist/client/index.html", "<!doctype html>");
`;

const TOKEN = "the-deploy-token-value-0123456789";
const REAL = {
  CLOUDFLARE_API_TOKEN: TOKEN,
  CLOUDFLARE_ACCOUNT_ID: "0123456789abcdef0123456789abcdef",
};

/**
 * Runs scripts/deploy.ts in a checkout with the committed configs and main
 * modules, a stand-in Wrangler installed as pnpm installs it, and a web build
 * that runs apps/web/build.mjs (R6-01).
 */
describe("deploy.ts and the builds (R6-01)", () => {
  let root = "";
  let fake: FakeWrangler;
  const app = (name: string) => join(root, "apps", name);
  const committed = (name: string, file: string) =>
    readFileSync(join(REPO_ROOT, "apps", name, file), "utf8");
  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "virga-deploy-build-")));
    cpSync(join(REPO_ROOT, "scripts", "deploy.ts"), join(root, "scripts", "deploy.ts"));
    cpSync(join(REPO_ROOT, "scripts", "lib"), join(root, "scripts", "lib"), { recursive: true });
    writeFileSync(join(root, "package.json"), '{ "type": "module" }');
    for (const name of ["broker", "core", "web"]) {
      put(join(app(name), "wrangler.jsonc"), committed(name, "wrangler.jsonc"));
      put(join(app(name), "src", "index.ts"), committed(name, join("src", "index.ts")));
    }
    put(join(app("web"), "package.json"), '{ "scripts": { "build": "node build.mjs" } }');
    put(join(app("web"), "build.mjs"), BUILD);
    fake = fakeWrangler(root, ["broker", "core", "web"].map(app), LOGGING_BIN);
    // A stand-in for pnpm that runs build.mjs for `pnpm run build`.
    put(
      join(root, "path", "pnpm"),
      '#!/bin/sh\n[ "$1 $2" = "run build" ] && exec node build.mjs\nexit 1\n',
      0o755,
    );
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const deploy = (args: string[], extra: Record<string, string> = {}) => {
    const env: NodeJS.ProcessEnv = {};
    for (const name of ["HOME", "TMPDIR", "LANG"]) {
      if (process.env[name] !== undefined) env[name] = process.env[name];
    }
    env.PATH = [join(root, "path"), dirname(process.execPath), "/usr/bin", "/bin"].join(":");
    return spawnSync(process.execPath, [join(root, "scripts", "deploy.ts"), ...args], {
      env: { ...env, ...extra },
      encoding: "utf8",
      timeout: 30_000,
    });
  };
  const calls = () =>
    existsSync(join(root, "calls.log")) ? readFileSync(join(root, "calls.log"), "utf8") : "";
  const build = (source: string) => put(join(app("web"), "build.mjs"), `${BUILD}${source}`);

  it("R6-01: builds first, then checks the configs, then runs the recorded Wrangler on them", () => {
    const result = deploy(["--dry-run"]);
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    const building = result.stdout.indexOf("Building virga-web");
    expect(building).toBeGreaterThan(-1);
    expect(result.stdout.indexOf("Configs: virga-broker, virga-core, virga-web")).toBeGreaterThan(
      building,
    );
    expect(calls().split("\n")).toEqual([
      ...["broker", "core", "web"].map(
        (name) =>
          `${name} no-token deploy --autoconfig=false --dry-run --config ${join(app(name), "wrangler.jsonc")} --env-file ${devNull}`,
      ),
      "",
    ]);
    expect(result.stdout).not.toContain("shim ran");
  });

  const UNSAFE = `{ "bindings": [{ "name": "API", "type": "service", "service": "virga-broker", "entrypoint": "ApiCaller" }] }`;
  for (const [key, value, refusal] of [
    ["unsafe", UNSAFE, "unsafe is not supported"],
    ["build", '{ "command": "node steal.mjs" }', "build.command is not supported"],
  ] as const) {
    it(`R6-01: a build that adds ${key} to wrangler.jsonc stops the deploy before any Wrangler call`, () => {
      build(`import { readFileSync } from "node:fs";
const config = readFileSync("wrangler.jsonc", "utf8");
writeFileSync("wrangler.jsonc", config.replace(/\\}\\s*$/, ${JSON.stringify(`, "${key}": ${value} }\n`)}));
`);
      for (const args of [[], ["--dry-run"]]) {
        const result = deploy(args, REAL);
        expect(result.stdout).toContain("Building virga-web");
        expect(result.status).toBe(1);
        expect(result.stderr).toContain(`error: apps/web/wrangler.jsonc: ${refusal}`);
        expect(calls()).toBe("");
        expect(result.stdout + result.stderr).not.toContain(TOKEN);
        put(join(app("web"), "wrangler.jsonc"), committed("web", "wrangler.jsonc"));
      }
    });
  }

  it("R6-01: a build that edits the Wrangler shim or a file Wrangler runs stops the deploy before any Wrangler call", () => {
    for (const file of [
      join(app("web"), "node_modules", ".bin", "wrangler"),
      fake.bin,
      join(fake.wrangler, "wrangler-dist", "cli.js"),
      join(fake.esbuild, "lib", "main.js"),
    ]) {
      const before = readFileSync(file);
      build(`import { appendFileSync } from "node:fs";
appendFileSync(${JSON.stringify(file)}, "\\nconsole.log(process.env.CLOUDFLARE_API_TOKEN);\\n");
`);
      const result = deploy([], REAL);
      expect(result.status, file).toBe(1);
      expect(result.stderr).toContain("changed after the deploy recorded it before the builds: ");
      expect(result.stderr).toContain(file);
      expect(calls()).toBe("");
      expect(result.stdout + result.stderr).not.toMatch(/shim ran|the-deploy-token-value/);
      writeFileSync(file, before);
    }
  });

  it("R6-01: checks the app directories again after the builds", () => {
    build(
      `writeFileSync(".env", "CLOUDFLARE_API_BASE_URL=http://127.0.0.1:18787/client/v4\\n");\n`,
    );
    let result = deploy([], REAL);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "error: apps/web/.env: Wrangler would load it into its environment",
    );
    rmSync(join(app("web"), ".env"));

    build(`import { symlinkSync } from "node:fs";
symlinkSync(${JSON.stringify(join(root, "package.json"))}, "src/linked.ts");
`);
    result = deploy([], REAL);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      "error: apps/web holds symlinks outside node_modules: apps/web/src/linked.ts.",
    );
    expect(calls()).toBe("");
  });

  it("R6-01: refuses a config that changed after its check, before the Wrangler call that reads it", () => {
    writeFileSync(join(root, "rewrite-later"), "");
    const result = deploy(["--dry-run"]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      `error: ${join(app("web"), "wrangler.jsonc")} changed after the deploy checked it; refusing to pass it to Wrangler`,
    );
    expect(
      calls()
        .split("\n")
        .map((line) => line.split(" ")[0]),
    ).toEqual(["broker", "core", ""]);
  });
});
