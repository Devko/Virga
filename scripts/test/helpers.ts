import { chmodSync, cpSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { WorkerConfig } from "../lib/config.ts";

export const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));

/**
 * What scripts/deploy.ts needs of a checkout under `root`, without apps:
 * the script and its lib, a package.json, and the rule compiler with the
 * committed rules and generated modules (R8-05). The compiler's dependencies
 * are the repository's, through a link to its node_modules.
 */
export function deployCheckout(root: string) {
  for (const path of ["scripts/deploy.ts", "scripts/lib", "packages/rules/src", "rules"]) {
    cpSync(join(REPO_ROOT, path), join(root, path), { recursive: true });
  }
  cpSync(join(REPO_ROOT, "packages/rules/package.json"), join(root, "packages/rules/package.json"));
  symlinkSync(
    join(REPO_ROOT, "packages/rules/node_modules"),
    join(root, "packages/rules/node_modules"),
  );
  writeFileSync(join(root, "package.json"), '{ "type": "module" }');
}

const NAMES: Record<string, string> = {
  broker: "virga-broker",
  core: "virga-core",
  web: "virga-web",
};

/** A config as parseWorkerConfig returns it, for tests that need no file. */
export function worker(app: string, overrides: Partial<WorkerConfig> = {}): WorkerConfig {
  return {
    app,
    dir: `/repo/apps/${app}`,
    configPath: `/repo/apps/${app}/wrangler.jsonc`,
    configSha256: "0".repeat(64),
    displayPath: `apps/${app}/wrangler.jsonc`,
    name: NAMES[app] ?? app,
    main: "src/index.ts",
    workersDev: app === "web" ? null : false,
    previewUrls: app === "web" ? null : false,
    hasRoutes: false,
    hasAssets: false,
    assetsDirectory: null,
    keys: [],
    services: [],
    d1: [],
    secretsStore: [],
    durableObjects: [],
    workflows: [],
    vars: {},
    requiredSecrets: [],
    ...overrides,
  };
}

export function put(path: string, text: string, mode = 0o644) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
  chmodSync(path, mode);
}

export interface FakeWrangler {
  /** node_modules/.pnpm/wrangler@4.151.0/node_modules/wrangler */
  wrangler: string;
  /** Its bin file, bin/wrangler.js. */
  bin: string;
  /** A dependency, esbuild, linked next to the package as pnpm links it. */
  esbuild: string;
  /** esbuild's optional platform package. */
  platform: string;
  /** apps/<app>/node_modules/.bin/wrangler of each app, which prints `shim ran`. */
  shims: string[];
}

/**
 * A stand-in Wrangler installed the way pnpm installs it under `root`, linked
 * from each of `appDirs`. `bin` is the source of its bin file. Its shims in
 * node_modules/.bin print `shim ran`; the deploy never runs them.
 */
export function fakeWrangler(root: string, appDirs: readonly string[], bin: string): FakeWrangler {
  const store = join(root, "node_modules", ".pnpm");
  const wrangler = join(store, "wrangler@4.151.0", "node_modules", "wrangler");
  const esbuild = join(store, "esbuild@0.28.2", "node_modules", "esbuild");
  const platform = join(
    store,
    "@esbuild+linux-x64@0.28.2",
    "node_modules",
    "@esbuild",
    "linux-x64",
  );
  put(
    join(wrangler, "package.json"),
    JSON.stringify({
      name: "wrangler",
      version: "4.151.0",
      bin: { wrangler: "./bin/wrangler.js", wrangler2: "./bin/wrangler.js" },
      main: "wrangler-dist/cli.js",
      dependencies: { esbuild: "0.28.2" },
      optionalDependencies: { fsevents: "2.3.3" },
    }),
  );
  put(join(wrangler, "bin", "wrangler.js"), bin, 0o755);
  put(join(wrangler, "wrangler-dist", "cli.js"), "module.exports = {};\n");
  // pnpm's shims for the package's own dependencies: never loaded by Wrangler.
  put(join(wrangler, "node_modules", ".bin", "esbuild"), "#!/bin/sh\n", 0o755);
  symlinkSync(
    join("..", "..", "esbuild@0.28.2", "node_modules", "esbuild"),
    join(store, "wrangler@4.151.0", "node_modules", "esbuild"),
  );
  put(
    join(esbuild, "package.json"),
    JSON.stringify({
      name: "esbuild",
      version: "0.28.2",
      main: "lib/main.js",
      optionalDependencies: { "@esbuild/linux-x64": "0.28.2", "@esbuild/darwin-arm64": "0.28.2" },
    }),
  );
  put(join(esbuild, "lib", "main.js"), "module.exports = {};\n");
  put(
    join(platform, "package.json"),
    JSON.stringify({ name: "@esbuild/linux-x64", version: "0.28.2" }),
  );
  put(join(platform, "bin", "esbuild"), "a binary", 0o755);
  mkdirSync(join(store, "esbuild@0.28.2", "node_modules", "@esbuild"), { recursive: true });
  symlinkSync(platform, join(store, "esbuild@0.28.2", "node_modules", "@esbuild", "linux-x64"));
  // pnpm hoists every package here, where Node searches from every package in the store.
  mkdirSync(join(store, "node_modules"));
  symlinkSync(esbuild, join(store, "node_modules", "esbuild"));
  const shims: string[] = [];
  for (const appDir of appDirs) {
    mkdirSync(join(appDir, "node_modules", ".bin"), { recursive: true });
    symlinkSync(wrangler, join(appDir, "node_modules", "wrangler"));
    const shim = join(appDir, "node_modules", ".bin", "wrangler");
    put(shim, '#!/bin/sh\necho "shim ran"\n', 0o755);
    put(join(appDir, "node_modules", ".bin", "vite"), "#!/bin/sh\n", 0o755);
    shims.push(shim);
  }
  return { wrangler, bin: join(wrangler, "bin", "wrangler.js"), esbuild, platform, shims };
}
