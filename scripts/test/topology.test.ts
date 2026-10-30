import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readWorkerConfig, type WorkerConfig } from "../lib/config.ts";
import { loadExports, type ModuleExports } from "../lib/exports.ts";
import { parseJsonc } from "../lib/jsonc.ts";
import { CONFIG_KEYS, checkTopology, type Issue, NESTED_KEYS } from "../lib/topology.ts";
import { REPO_ROOT, worker } from "./helpers.ts";

const EXPORTS: Record<string, string[]> = {
  "virga-broker": ["ApiCaller", "TokenIntake", "RateBudget", "default"],
  "virga-core": ["AccountGraph", "Admin", "GraphReader", "ScanWorkflow", "default"],
  "virga-web": ["default"],
};
const exportsOf = (w: WorkerConfig): ModuleExports | null =>
  EXPORTS[w.name] ? { names: new Set(EXPORTS[w.name]), star: false } : null;

const broker = (o: Partial<WorkerConfig> = {}) =>
  worker("broker", {
    d1: [
      {
        binding: "VAULT",
        databaseName: "virga-vault",
        databaseId: null,
        migrationsDir: "migrations",
      },
    ],
    secretsStore: [
      {
        binding: "MASTER_KEY_STORE",
        storeId: "<SECRETS_STORE_ID>",
        secretName: "virga-master-key",
      },
    ],
    durableObjects: [{ binding: "RATE_BUDGET", className: "RateBudget", scriptName: null }],
    ...o,
  });
const core = (o: Partial<WorkerConfig> = {}) =>
  worker("core", {
    services: [{ binding: "BROKER", service: "virga-broker", entrypoint: "ApiCaller" }],
    d1: [
      {
        binding: "INDEX",
        databaseName: "virga-index",
        databaseId: null,
        migrationsDir: "migrations",
      },
    ],
    durableObjects: [{ binding: "ACCOUNT_GRAPH", className: "AccountGraph", scriptName: null }],
    workflows: [{ binding: "SCAN_WORKFLOW", className: "ScanWorkflow", scriptName: null }],
    ...o,
  });
const web = (o: Partial<WorkerConfig> = {}) =>
  worker("web", {
    services: [
      { binding: "INTAKE", service: "virga-broker", entrypoint: "TokenIntake" },
      { binding: "GRAPH", service: "virga-core", entrypoint: "GraphReader" },
      { binding: "ADMIN", service: "virga-core", entrypoint: "Admin" },
    ],
    hasAssets: true,
    ...o,
  });

const errors = (issues: Issue[]) => issues.filter((i) => i.level === "error").map((i) => i.message);
const warnings = (issues: Issue[]) =>
  issues.filter((i) => i.level === "warning").map((i) => i.message);
const check = (...workers: WorkerConfig[]) => checkTopology(workers, exportsOf);

describe("checkTopology on the repository", () => {
  it("accepts the committed configs", () => {
    const configs = ["broker", "core", "web"].flatMap(
      (app) => readWorkerConfig(REPO_ROOT, app) ?? [],
    );
    expect(checkTopology(configs, loadExports)).toEqual([]);
  });
});

describe("checkTopology", () => {
  it("accepts broker and core alone, and all three Workers", () => {
    expect(check(broker(), core())).toEqual([]);
    expect(check(broker(), core(), web())).toEqual([]);
  });

  it("requires broker and core", () => {
    expect(errors(check(core()))).toEqual(
      expect.arrayContaining(["apps/broker: no wrangler.jsonc found"]),
    );
  });

  it("rejects a Worker with an unexpected name", () => {
    expect(errors(check(broker({ name: "broker" }), core()))).toContainEqual(
      expect.stringContaining('name is "broker", expected "virga-broker"'),
    );
  });

  it("rejects bindings to unknown services and to a Worker missing from the checkout", () => {
    const issues = check(
      broker(),
      core({
        services: [
          { binding: "BROKER", service: "virga-broker", entrypoint: "ApiCaller" },
          { binding: "OTHER", service: "someone-else", entrypoint: "X" },
        ],
      }),
    );
    expect(errors(issues)).toContainEqual(
      expect.stringContaining("someone-else, which is not a Virga Worker"),
    );
    const toWeb = check(
      broker({ services: [{ binding: "W", service: "virga-web", entrypoint: "X" }] }),
      core(),
    );
    expect(errors(toWeb)).toContainEqual(
      expect.stringContaining("virga-web, which is not in this checkout"),
    );
  });

  it("rejects a binding without entrypoint", () => {
    const issues = check(
      broker(),
      core({ services: [{ binding: "BROKER", service: "virga-broker", entrypoint: null }] }),
    );
    expect(errors(issues)).toContainEqual(expect.stringContaining("has no entrypoint"));
  });

  it("rejects an entrypoint the target does not export", () => {
    const issues = check(
      broker(),
      core({ services: [{ binding: "BROKER", service: "virga-broker", entrypoint: "ApiCallr" }] }),
    );
    expect(errors(issues)).toEqual(
      expect.arrayContaining([
        expect.stringContaining("virga-broker#ApiCallr, which src/index.ts does not export"),
        expect.stringContaining("may not bind virga-broker#ApiCallr"),
        expect.stringContaining("has no service binding to virga-broker#ApiCaller"),
      ]),
    );
  });

  it("only warns about an entrypoint behind export *", () => {
    const issues = checkTopology(
      [
        broker(),
        core({ services: [{ binding: "B", service: "virga-broker", entrypoint: "ApiCaller" }] }),
      ],
      (w) =>
        w.name === "virga-broker" ? { names: new Set(["RateBudget"]), star: true } : exportsOf(w),
    );
    expect(errors(issues)).toEqual([]);
    expect(warnings(issues)).toContainEqual(expect.stringContaining("export *"));
  });

  it("keeps the API caller away from the web Worker", () => {
    const issues = check(
      broker(),
      core(),
      web({
        services: [
          ...web().services,
          { binding: "API", service: "virga-broker", entrypoint: "ApiCaller" },
        ],
      }),
    );
    expect(errors(issues)).toEqual([
      expect.stringContaining("virga-web may not bind virga-broker#ApiCaller"),
    ]);
  });

  it("requires the web Worker's TokenIntake and GraphReader, and warns without Admin", () => {
    const issues = check(
      broker(),
      core(),
      web({ services: [{ binding: "GRAPH", service: "virga-core", entrypoint: "GraphReader" }] }),
    );
    expect(errors(issues)).toEqual([
      expect.stringContaining("no service binding to virga-broker#TokenIntake"),
    ]);
    expect(warnings(issues)).toEqual([
      expect.stringContaining("no service binding to virga-core#Admin"),
    ]);
  });

  it("rejects a binding against the deploy order", () => {
    const issues = check(
      broker({ services: [{ binding: "CORE", service: "virga-core", entrypoint: "GraphReader" }] }),
      core(),
    );
    expect(errors(issues)).toEqual(
      expect.arrayContaining([
        expect.stringContaining(
          "virga-broker binds virga-core, but virga-core is deployed after it",
        ),
        expect.stringContaining("virga-broker may not bind virga-core#GraphReader (allowed: none)"),
      ]),
    );
  });

  it("keeps the broker and core off the internet", () => {
    const issues = check(
      broker({ workersDev: null }),
      core({ previewUrls: true, hasRoutes: true }),
    );
    expect(errors(issues)).toEqual([
      "apps/broker/wrangler.jsonc: workers_dev must be false",
      "apps/core/wrangler.jsonc: preview_urls must be false",
      "apps/core/wrangler.jsonc: virga-core must have no routes",
    ]);
  });

  it("keeps state and keys out of the web Worker", () => {
    const issues = check(
      broker(),
      core(),
      web({
        d1: [
          {
            binding: "DB",
            databaseName: "virga-web-db",
            databaseId: null,
            migrationsDir: "migrations",
          },
        ],
        durableObjects: [{ binding: "G", className: "AccountGraph", scriptName: "virga-core" }],
        secretsStore: [{ binding: "K", storeId: "s", secretName: "k" }],
      }),
    );
    expect(errors(issues)).toEqual([
      expect.stringContaining("Durable Object binding G uses class AccountGraph of virga-core"),
      "apps/web/wrangler.jsonc: virga-web must not bind D1 databases",
      expect.stringContaining("virga-web must not bind Durable Objects"),
      expect.stringContaining("only virga-broker binds Secrets Store secrets"),
    ]);
  });

  it("keeps the vault database on the broker (D-08)", () => {
    const issues = check(
      broker(),
      core({
        d1: [
          ...core().d1,
          {
            binding: "VAULT",
            databaseName: "virga-vault",
            databaseId: null,
            migrationsDir: "migrations",
          },
        ],
      }),
    );
    expect(errors(issues)).toEqual([
      expect.stringContaining("D1 database virga-vault is also bound by virga-broker"),
    ]);
  });

  it("R3-06: keeps one owner per database_id, whatever the name says", () => {
    const vault = {
      binding: "VAULT",
      databaseName: "virga-vault",
      databaseId: "6f1c3a52-0b7e-4f38-9d0a-5c2e8b7a4d11",
      migrationsDir: "migrations",
    };
    const issues = check(
      broker({ d1: [vault] }),
      core({ d1: [{ ...vault, binding: "INDEX", databaseName: "virga-index" }] }),
    );
    expect(errors(issues)).toEqual([
      "apps/core/wrangler.jsonc: D1 database_id 6f1c3a52-0b7e-4f38-9d0a-5c2e8b7a4d11 is also bound by virga-broker; each database belongs to one Worker (D-08)",
    ]);
  });

  it("needs a database_name to create and migrate a database", () => {
    const issues = check(
      broker({
        d1: [
          { binding: "VAULT", databaseName: null, databaseId: null, migrationsDir: "migrations" },
        ],
      }),
      core(),
    );
    expect(errors(issues)).toEqual([
      expect.stringContaining("D1 binding VAULT needs database_name"),
    ]);
  });

  it("checks that Durable Object and Workflow classes are exported", () => {
    const issues = check(
      broker(),
      core({
        workflows: [{ binding: "DISPATCH", className: "DispatchWorkflow", scriptName: null }],
      }),
    );
    expect(errors(issues)).toEqual([
      expect.stringContaining("Workflow binding DISPATCH names class DispatchWorkflow"),
    ]);
  });

  it("R3-04: refuses Cloudflare credentials in secrets.required", () => {
    const issues = check(
      broker(),
      core(),
      web({ requiredSecrets: ["CLOUDFLARE_API_TOKEN", "CF_API_KEY", "ACCESS_AUD"] }),
    );
    expect(errors(issues)).toEqual([
      expect.stringContaining("secrets.required names CLOUDFLARE_API_TOKEN"),
      expect.stringContaining("secrets.required names CF_API_KEY"),
    ]);
  });

  it("R3-03: refuses named environments, which the deploy never checks", () => {
    const issues = check(broker({ keys: [["env"], ["env", "prod"]] }), core());
    expect(errors(issues)).toEqual([
      expect.stringContaining(
        "apps/broker/wrangler.jsonc: named environments (env) are not supported",
      ),
    ]);
    expect(warnings(issues)).toEqual([]);
  });
});

/**
 * Each case changes one committed config the way a reviewed commit could,
 * and reads it as the deploy does (R5-02).
 */
describe("checkTopology on every key Wrangler deploys", () => {
  let root = "";
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  // biome-ignore lint/suspicious/noExplicitAny: the cases edit configs of any shape
  type Config = Record<string, any>;
  const committed = (app: string) => readWorkerConfig(REPO_ROOT, app) as WorkerConfig;
  /** Errors for the committed configs with `change` applied to the config of `app`. */
  const errorsWith = (app: string, change: (config: Config) => void) => {
    const text = readFileSync(join(REPO_ROOT, "apps", app, "wrangler.jsonc"), "utf8");
    const config = parseJsonc(text) as Config;
    change(config);
    root = mkdtempSync(join(tmpdir(), "virga-keys-"));
    mkdirSync(join(root, "apps", app), { recursive: true });
    writeFileSync(join(root, "apps", app, "wrangler.jsonc"), JSON.stringify(config));
    const changed = readWorkerConfig(root, app) as WorkerConfig;
    const workers = ["broker", "core", "web"].map((a) => (a === app ? changed : committed(a)));
    return errors(checkTopology(workers, (w) => loadExports(committed(w.app))));
  };

  it("R5-02: refuses unsafe bindings, which could give virga-web the ApiCaller", () => {
    const issues = errorsWith("web", (c) => {
      c.unsafe = {
        bindings: [
          { name: "API", type: "service", service: "virga-broker", entrypoint: "ApiCaller" },
        ],
      };
    });
    expect(issues).toEqual([
      expect.stringContaining("apps/web/wrangler.jsonc: unsafe is not supported"),
    ]);
  });

  it("R5-02: refuses a Workflow binding in virga-web to virga-core's ScanWorkflow", () => {
    const issues = errorsWith("web", (c) => {
      c.workflows = [
        {
          binding: "SCAN",
          name: "virga-scan",
          class_name: "ScanWorkflow",
          script_name: "virga-core",
        },
      ];
    });
    expect(issues).toEqual([
      "apps/web/wrangler.jsonc: virga-web may not set workflows; the deploy does not check it there, and Wrangler would deploy it",
      expect.stringContaining(
        "Workflow binding SCAN uses class ScanWorkflow of virga-core; bindings to another Worker's classes are not part of the topology",
      ),
      "apps/web/wrangler.jsonc: virga-web must not bind Workflows; it starts scans through Admin",
    ]);
  });

  it("R5-02: refuses a Durable Object or Workflow class of another Worker everywhere", () => {
    const issues = errorsWith("core", (c) => {
      c.durable_objects.bindings.push({
        name: "RATE",
        class_name: "RateBudget",
        script_name: "virga-broker",
      });
    });
    expect(issues).toEqual([
      expect.stringContaining(
        "Durable Object binding RATE uses class RateBudget of virga-broker; bindings to another Worker's classes are not part of the topology",
      ),
    ]);
  });

  it("R5-02: refuses build.command in every Worker, since Wrangler runs it with the deploy token", () => {
    for (const app of ["broker", "core", "web"]) {
      const issues = errorsWith(app, (c) => {
        c.build = { command: "node -e 'console.log(process.env.CLOUDFLARE_API_TOKEN)'" };
      });
      expect(issues).toEqual([
        expect.stringContaining(
          `apps/${app}/wrangler.jsonc: build.command is not supported: Wrangler runs it with the deploy token in its environment`,
        ),
      ]);
    }
  });

  it("R5-02: refuses top-level keys outside each Worker's list", () => {
    const cases: [string, string, unknown][] = [
      ["web", "previews", { d1_databases: [{ binding: "VAULT", database_name: "virga-vault" }] }],
      ["web", "tail_consumers", [{ service: "elsewhere" }]],
      ["core", "kv_namespaces", [{ binding: "KV", id: "x" }]],
      ["broker", "account_id", "0123456789abcdef0123456789abcdef"],
      ["broker", "keep_vars", true],
      ["broker", "assets", { directory: "src" }],
      ["web", "migrations", [{ tag: "v1", new_sqlite_classes: ["X"] }]],
    ];
    for (const [app, key, value] of cases) {
      const issues = errorsWith(app, (c) => {
        c[key] = value;
      });
      expect(issues, key).toContainEqual(expect.stringContaining(`apps/${app}/wrangler.jsonc:`));
      expect(issues.join("\n"), key).toMatch(
        new RegExp(`\\b${key} is not supported|may not set ${key}`),
      );
    }
  });

  it("R5-02: refuses nested keys the checks do not read", () => {
    const cases: [string, string, (c: Config) => void][] = [
      ["core", "services[].props", (c) => (c.services[0].props = { admin: true })],
      [
        "broker",
        "d1_databases[].migrations_table",
        (c) => (c.d1_databases[0].migrations_table = "x"),
      ],
      [
        "core",
        "durable_objects.bindings[].environment",
        (c) => (c.durable_objects.bindings[0].environment = "prod"),
      ],
      [
        "core",
        "migrations[].transferred_classes",
        (c) =>
          c.migrations.push({
            tag: "v2",
            transferred_classes: [
              { from: "RateBudget", from_script: "virga-broker", to: "AccountGraph" },
            ],
          }),
      ],
      [
        "web",
        "observability.logs.destinations",
        (c) => (c.observability.logs = { destinations: ["elsewhere"] }),
      ],
      ["web", "assets.unknown", (c) => (c.assets.unknown = true)],
    ];
    for (const [app, path, change] of cases) {
      const issues = errorsWith(app, change);
      expect(issues, path).toEqual([
        expect.stringContaining(`apps/${app}/wrangler.jsonc: ${path} is not supported`),
      ]);
    }
  });

  it("R5-02: names an odd key as it is, so it cannot pass for an allowed path", () => {
    const issues = errorsWith("web", (c) => {
      c.observability["logs.enabled"] = true;
    });
    expect(issues).toEqual([
      expect.stringContaining(`observability["logs.enabled"] is not supported`),
    ]);
  });

  it("R5-02: allows only keys of Wrangler's own config schema", () => {
    const schema = JSON.parse(
      readFileSync(
        join(REPO_ROOT, "apps", "broker", "node_modules", "wrangler", "config-schema.json"),
        "utf8",
      ),
    ) as { definitions: Record<string, Schema> };
    interface Schema {
      $ref?: string;
      anyOf?: Schema[];
      items?: Schema;
      properties?: Record<string, Schema>;
    }
    const resolve = (s: Schema): Schema =>
      s.$ref ? resolve(schema.definitions[s.$ref.split("/").pop() as string] as Schema) : s;
    /** The schemas a generic path such as `services[].binding` can name. */
    const at = (path: string): Schema[] => {
      let current = [resolve({ $ref: "#/definitions/RawConfig" })];
      for (const part of path.match(/\[\]|[^.[\]]+/g) ?? []) {
        const expanded = current.flatMap((s) => (s.anyOf ? s.anyOf.map(resolve) : [s]));
        current = expanded.flatMap((s) => {
          const next = part === "[]" ? s.items : s.properties?.[part];
          return next ? [resolve(next)] : [];
        });
      }
      return current;
    };
    const paths = [...new Set(Object.values(CONFIG_KEYS).flat()), ...NESTED_KEYS];
    for (const path of paths) expect(at(path), path).not.toEqual([]);
  });
});
