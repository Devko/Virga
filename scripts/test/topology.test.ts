import { describe, expect, it } from "vitest";
import { readWorkerConfig, type WorkerConfig } from "../lib/config.ts";
import { loadExports, type ModuleExports } from "../lib/exports.ts";
import { checkTopology, type Issue } from "../lib/topology.ts";
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

  it("R3-03: refuses named environments, which the deploy never checks", () => {
    const issues = check(broker({ hasEnvironments: true }), core());
    expect(errors(issues)).toEqual([
      expect.stringContaining(
        "apps/broker/wrangler.jsonc: named environments (env) are not supported",
      ),
    ]);
    expect(warnings(issues)).toEqual([]);
  });
});
