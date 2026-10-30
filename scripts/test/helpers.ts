import { fileURLToPath } from "node:url";
import type { WorkerConfig } from "../lib/config.ts";

export const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));

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
