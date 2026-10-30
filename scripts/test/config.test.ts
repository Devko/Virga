import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ConfigError, parseWorkerConfig, readWorkerConfig } from "../lib/config.ts";
import { REPO_ROOT } from "./helpers.ts";

const source = {
  app: "core",
  dir: "/x/apps/core",
  configPath: "/x/apps/core/wrangler.jsonc",
  where: "apps/core/wrangler.jsonc",
};

describe("readWorkerConfig on the repository", () => {
  it("reads the broker config", () => {
    const broker = readWorkerConfig(REPO_ROOT, "broker");
    expect(broker).toMatchObject({
      app: "broker",
      name: "virga-broker",
      main: "src/index.ts",
      workersDev: false,
      previewUrls: false,
      hasRoutes: false,
      services: [],
      d1: [
        {
          binding: "VAULT",
          databaseName: "virga-vault",
          databaseId: null,
          migrationsDir: "migrations",
        },
      ],
      secretsStore: [{ binding: "MASTER_KEY_STORE", secretName: "virga-master-key" }],
      durableObjects: [{ binding: "RATE_BUDGET", className: "RateBudget", scriptName: null }],
      displayPath: "apps/broker/wrangler.jsonc",
    });
  });

  it("reads the core config with its service binding and Workflows", () => {
    const core = readWorkerConfig(REPO_ROOT, "core");
    expect(core?.services).toEqual([
      { binding: "BROKER", service: "virga-broker", entrypoint: "ApiCaller" },
    ]);
    expect(core?.workflows.map((w) => w.className)).toEqual(["ScanWorkflow", "DispatchWorkflow"]);
    expect(core?.d1[0]?.databaseName).toBe("virga-index");
  });
});

describe("readWorkerConfig", () => {
  let root = "";
  afterEach(() => rmSync(root, { recursive: true, force: true }));
  /** A checkout with files in apps/web, and optionally elsewhere (paths relative to the root). */
  const app = (files: Record<string, string>, elsewhere: Record<string, string> = {}) => {
    root = mkdtempSync(join(tmpdir(), "virga-config-"));
    mkdirSync(join(root, "apps", "web"), { recursive: true });
    for (const [name, text] of Object.entries(files))
      writeFileSync(join(root, "apps", "web", name), text);
    for (const [path, text] of Object.entries(elsewhere)) writeFileSync(join(root, path), text);
  };

  it("returns null for an app without a config", () => {
    app({});
    expect(readWorkerConfig(root, "web")).toBeNull();
    expect(readWorkerConfig(root, "missing")).toBeNull();
  });

  it("reads wrangler.json as well", () => {
    app({ "wrangler.json": `{ "name": "virga-web" }` });
    expect(readWorkerConfig(root, "web")?.name).toBe("virga-web");
  });

  it("R3-03: refuses a second config next to the app's config", () => {
    app({
      "wrangler.jsonc": `{ "name": "virga-web" }`,
      "wrangler.json": `{ "name": "virga-web" }`,
    });
    expect(() => readWorkerConfig(root, "web")).toThrow(
      /apps\/web\/wrangler.json and .*apps\/web\/wrangler.jsonc: an app has one Wrangler config/,
    );
  });

  it("R3-03: refuses a Wrangler config above the app, which Wrangler would find first", () => {
    const stray = `{ "name": "virga-web", "services": [{ "binding": "API", "service": "virga-broker", "entrypoint": "ApiCaller" }] }`;
    app({ "wrangler.jsonc": `{ "name": "virga-web" }` }, { "wrangler.json": stray });
    expect(() => readWorkerConfig(root, "web")).toThrow(
      "apps/web/wrangler.jsonc: wrangler.json is a Wrangler config above the app",
    );
    rmSync(join(root, "wrangler.json"));
    writeFileSync(join(root, "apps", "wrangler.toml"), `name = "virga-web"`);
    expect(() => readWorkerConfig(root, "web")).toThrow(/apps\/wrangler.toml is a Wrangler config/);
  });

  it("refuses wrangler.toml", () => {
    app({ "wrangler.toml": `name = "virga-web"` });
    expect(() => readWorkerConfig(root, "web")).toThrow(ConfigError);
  });

  it("names the file in syntax errors", () => {
    app({ "wrangler.jsonc": `{ "name": }` });
    expect(() => readWorkerConfig(root, "web")).toThrow(/apps\/web\/wrangler.jsonc/);
  });

  it("R5-01: refuses a __proto__ member, whose bindings Wrangler would deploy unchecked", () => {
    // The member from the round 5 review: the vault and the master key in virga-web.
    app({
      "wrangler.jsonc": `{
        "name": "virga-web",
        "main": "src/index.ts",
        "__proto__": {
          "d1_databases": [{ "binding": "VAULT", "database_name": "virga-vault", "database_id": "6f1c3a52-0b7e-4f38-9d0a-5c2e8b7a4d11" }],
          "secrets_store_secrets": [{ "binding": "MASTER_KEY_STORE", "store_id": "0123456789abcdef0123456789abcdef", "secret_name": "virga-master-key" }]
        }
      }`,
    });
    expect(() => readWorkerConfig(root, "web")).toThrow(
      /apps\/web\/wrangler.jsonc: key "__proto__" is refused/,
    );
  });

  it("R5-01: refuses a duplicate key, which a reviewer may read either way", () => {
    app({ "wrangler.jsonc": `{ "name": "virga-web", "workers_dev": false, "workers_dev": true }` });
    expect(() => readWorkerConfig(root, "web")).toThrow(/duplicate key "workers_dev"/);
  });
});

describe("parseWorkerConfig", () => {
  it("fills defaults for optional fields", () => {
    const config = parseWorkerConfig({ name: "virga-web" }, source);
    expect(config).toMatchObject({
      main: null,
      workersDev: null,
      previewUrls: null,
      hasRoutes: false,
      hasAssets: false,
      keys: [["name"]],
      services: [],
      d1: [],
      vars: {},
      requiredSecrets: [],
    });
  });

  it("reads service entrypoints, routes, assets, vars and required secrets", () => {
    const config = parseWorkerConfig(
      {
        name: "virga-web",
        main: "src/worker.ts",
        routes: [{ pattern: "virga.example.com", custom_domain: true }],
        assets: { directory: "dist" },
        services: [
          { binding: "GRAPH", service: "virga-core", entrypoint: "GraphReader" },
          { binding: "X", service: "virga-core" },
        ],
        vars: { ADMIN_EMAILS: "a@example.com" },
        secrets: { required: ["ACCESS_AUD"] },
        env: { staging: {} },
      },
      source,
    );
    expect(config.services).toEqual([
      { binding: "GRAPH", service: "virga-core", entrypoint: "GraphReader" },
      { binding: "X", service: "virga-core", entrypoint: null },
    ]);
    expect(config).toMatchObject({
      hasRoutes: true,
      hasAssets: true,
      vars: { ADMIN_EMAILS: "a@example.com" },
      requiredSecrets: ["ACCESS_AUD"],
    });
    expect(config.keys).toContainEqual(["env", "staging"]);
  });

  it("collects every problem in one error", () => {
    const parse = () =>
      parseWorkerConfig(
        {
          workers_dev: "no",
          services: [{ binding: "B" }],
          d1_databases: {},
          durable_objects: { bindings: [{ name: "X" }] },
          secrets: { required: [1] },
        },
        source,
      );
    expect(parse).toThrow(ConfigError);
    let message = "";
    try {
      parse();
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("config.name is missing");
    expect(message).toContain("workers_dev must be a boolean");
    expect(message).toContain("services[0].service is missing");
    expect(message).toContain("d1_databases must be an array");
    expect(message).toContain("durable_objects.bindings[0].class_name is missing");
    expect(message).toContain("secrets.required must be an array of strings");
    expect(message.split("\n").every((line) => line.startsWith("apps/core/wrangler.jsonc: "))).toBe(
      true,
    );
  });

  it("R5-02: records the path of every key, but not the names inside vars", () => {
    const config = parseWorkerConfig(
      {
        name: "virga-web",
        vars: { ANY_NAME: { nested: true } },
        unsafe: { bindings: [{ name: "API", type: "service" }] },
        "odd.key": [[{ deep: 1 }]],
      },
      source,
    );
    expect(config.keys).toEqual([
      ["name"],
      ["vars"],
      ["unsafe"],
      ["unsafe", "bindings"],
      ["unsafe", "bindings", 0, "name"],
      ["unsafe", "bindings", 0, "type"],
      ["odd.key"],
      ["odd.key", 0, 0, "deep"],
    ]);
  });

  it("rejects a config that is not an object", () => {
    expect(() => parseWorkerConfig([], source)).toThrow(/not an object/);
  });
});
