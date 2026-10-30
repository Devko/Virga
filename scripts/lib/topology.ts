import type { KeyPath, WorkerConfig } from "./config.ts";
import type { ModuleExports } from "./exports.ts";
import { isCloudflareVar } from "./run.ts";

export interface Issue {
  level: "error" | "warning";
  message: string;
}

/** The Workers of an instance, in deploy order: each one binds only Workers above it. */
export const WORKERS = [
  { app: "broker", name: "virga-broker", optional: false },
  { app: "core", name: "virga-core", optional: false },
  // Built by its own work package; a checkout without it deploys broker and core.
  { app: "web", name: "virga-web", optional: true },
] as const;

interface Grant {
  service: string;
  entrypoint: string;
  required: boolean;
}

/**
 * The service bindings each Worker may have (docs/implementation-plan.md,
 * deployment topology; D-06, D-08). Only the core Worker reaches the
 * Cloudflare API, and only the web Worker hands tokens to the broker.
 */
export const SERVICE_GRANTS: Readonly<Record<string, readonly Grant[]>> = {
  "virga-broker": [],
  "virga-core": [{ service: "virga-broker", entrypoint: "ApiCaller", required: true }],
  "virga-web": [
    { service: "virga-broker", entrypoint: "TokenIntake", required: true },
    { service: "virga-core", entrypoint: "GraphReader", required: true },
    // Without it the UI can neither add accounts nor start scans.
    { service: "virga-core", entrypoint: "Admin", required: false },
  ],
};

const COMMON_KEYS = [
  "$schema",
  "name",
  "main",
  "compatibility_date",
  "compatibility_flags",
  "workers_dev",
  "preview_urls",
  "observability",
  "vars",
  "secrets",
];

/**
 * The top-level keys each Worker may set (R5-02). Wrangler deploys every key
 * of its schema (node_modules/wrangler/config-schema.json), and the checks
 * below read only these, so any other key would deploy unchecked. A new key
 * goes here together with the check that covers it.
 */
export const CONFIG_KEYS: Readonly<Record<string, readonly string[]>> = {
  "virga-broker": [
    ...COMMON_KEYS,
    "d1_databases",
    "durable_objects",
    "migrations",
    "secrets_store_secrets",
  ],
  "virga-core": [
    ...COMMON_KEYS,
    "services",
    "d1_databases",
    "durable_objects",
    "migrations",
    "workflows",
  ],
  "virga-web": [...COMMON_KEYS, "routes", "route", "services", "assets"],
};

/** Keys below the top level that any Worker may set, by path; `[]` stands for any index. */
export const NESTED_KEYS: ReadonlySet<string> = new Set([
  "observability.enabled",
  "observability.head_sampling_rate",
  "observability.logs",
  "observability.logs.enabled",
  "observability.logs.head_sampling_rate",
  "observability.logs.invocation_logs",
  "observability.logs.persist",
  "observability.traces",
  "observability.traces.enabled",
  "observability.traces.head_sampling_rate",
  "observability.traces.persist",
  "secrets.required",
  "routes[].pattern",
  "routes[].custom_domain",
  "routes[].zone_id",
  "routes[].zone_name",
  "route.pattern",
  "route.custom_domain",
  "route.zone_id",
  "route.zone_name",
  "services[].binding",
  "services[].service",
  "services[].entrypoint",
  "d1_databases[].binding",
  "d1_databases[].database_name",
  "d1_databases[].database_id",
  "d1_databases[].migrations_dir",
  "secrets_store_secrets[].binding",
  "secrets_store_secrets[].store_id",
  "secrets_store_secrets[].secret_name",
  "durable_objects.bindings",
  "durable_objects.bindings[].name",
  "durable_objects.bindings[].class_name",
  "durable_objects.bindings[].script_name",
  "migrations[].tag",
  "migrations[].new_sqlite_classes",
  "migrations[].renamed_classes",
  "migrations[].renamed_classes[].from",
  "migrations[].renamed_classes[].to",
  "migrations[].deleted_classes",
  "workflows[].binding",
  "workflows[].name",
  "workflows[].class_name",
  "workflows[].script_name",
  "workflows[].schedules",
  "workflows[].limits",
  "workflows[].limits.steps",
  "workflows[].concurrency",
  "workflows[].concurrency.limit",
  "workflows[].default_retention",
  "workflows[].default_retention.success_retention",
  "workflows[].default_retention.error_retention",
  "assets.directory",
  "assets.binding",
  "assets.run_worker_first",
  "assets.not_found_handling",
  "assets.html_handling",
]);

/** Why some keys are refused, where the generic reason says too little. */
const KEY_REASONS = new Map([
  [
    "env",
    "named environments (env) are not supported; the deploy checks only the top-level configuration, and Wrangler would deploy an environment chosen with --env or CLOUDFLARE_ENV unchecked",
  ],
  [
    "build",
    "build.command is not supported: Wrangler runs it with the deploy token in its environment. Put the step in the app's build script, which the deploy runs without credentials (R3-05)",
  ],
  ["unsafe", "unsafe is not supported: its bindings and metadata bypass every binding check"],
  [
    "previews",
    "previews is not supported: it holds the bindings of preview versions, which the deploy does not check",
  ],
  [
    "migrations[].transferred_classes",
    "migrations[].transferred_classes is not supported: it moves the Durable Objects of another Worker into this one",
  ],
]);

/** Workers that hold no state and no keys: no D1, no Durable Objects, no Workflows, no Secrets Store. */
const STATELESS = new Set(["virga-web"]);
/** Workers that must not be reachable from the internet. */
const INTERNAL = new Set(["virga-broker", "virga-core"]);
const KEY_HOLDER = "virga-broker";

export type ExportsOf = (worker: WorkerConfig) => ModuleExports | null;

/**
 * Checks the configs of an instance against each other: names, service
 * bindings with their entrypoints, deploy order, and where state and keys
 * may live. `workers` are the configs found, in any order.
 */
export function checkTopology(workers: readonly WorkerConfig[], exportsOf: ExportsOf): Issue[] {
  const issues: Issue[] = [];
  const error = (message: string) => issues.push({ level: "error", message });
  const warning = (message: string) => issues.push({ level: "warning", message });

  const rank = new Map<string, number>(WORKERS.map((w, i) => [w.name, i]));
  const byName = new Map<string, WorkerConfig>();
  for (const expected of WORKERS) {
    const worker = workers.find((w) => w.app === expected.app);
    if (!worker) {
      if (!expected.optional) error(`apps/${expected.app}: no wrangler.jsonc found`);
      continue;
    }
    if (worker.name !== expected.name) {
      error(`${where(worker)}: name is "${worker.name}", expected "${expected.name}"`);
      continue;
    }
    byName.set(worker.name, worker);
  }

  for (const worker of byName.values()) {
    const at = where(worker);
    checkKeys(worker, error);
    const grants = SERVICE_GRANTS[worker.name] ?? [];
    for (const binding of worker.services) {
      const target = byName.get(binding.service);
      const label = `${binding.service}#${binding.entrypoint ?? "default"}`;
      if (!target) {
        error(
          rank.has(binding.service)
            ? `${at}: service binding ${binding.binding} targets ${binding.service}, which is not in this checkout`
            : `${at}: service binding ${binding.binding} targets ${binding.service}, which is not a Virga Worker`,
        );
        continue;
      }
      if ((rank.get(target.name) ?? 0) >= (rank.get(worker.name) ?? 0)) {
        error(
          `${at}: ${worker.name} binds ${target.name}, but ${target.name} is deployed after it (order: ${WORKERS.map((w) => w.name).join(", ")})`,
        );
      }
      if (binding.entrypoint === null) {
        error(
          `${at}: service binding ${binding.binding} has no entrypoint; the default export of ${target.name} answers 404`,
        );
        continue;
      }
      if (
        !grants.some((g) => g.service === binding.service && g.entrypoint === binding.entrypoint)
      ) {
        error(`${at}: ${worker.name} may not bind ${label} (allowed: ${allowed(grants)})`);
      }
      const exported = exportsOf(target);
      if (exported === null) {
        error(`${at}: cannot read the main module of ${target.name} to check ${label}`);
      } else if (!exported.names.has(binding.entrypoint)) {
        const message = `${at}: service binding ${binding.binding} names ${label}, which ${target.main ?? "its main module"} does not export`;
        if (exported.star) warning(`${message} directly (it has export *)`);
        else error(message);
      }
    }
    for (const grant of grants) {
      const bound = worker.services.some(
        (s) => s.service === grant.service && s.entrypoint === grant.entrypoint,
      );
      if (bound || !byName.has(grant.service)) continue;
      const message = `${at}: ${worker.name} has no service binding to ${grant.service}#${grant.entrypoint}`;
      if (grant.required) error(message);
      else warning(message);
    }

    checkClasses(worker, exportsOf, error);
    checkState(worker, error);
    if (INTERNAL.has(worker.name)) {
      if (worker.workersDev !== false) error(`${at}: workers_dev must be false`);
      if (worker.previewUrls !== false) error(`${at}: preview_urls must be false`);
      if (worker.hasRoutes) error(`${at}: ${worker.name} must have no routes`);
    }
    for (const name of worker.requiredSecrets) {
      if (isCloudflareVar(name)) {
        error(
          `${at}: secrets.required names ${name}; Cloudflare credentials are never Worker secrets`,
        );
      }
    }
  }

  // By name and by ID: Wrangler binds by database_id, whatever database_name says (R3-06).
  const databases = new Map<string, string>();
  for (const worker of byName.values()) {
    for (const db of worker.d1) {
      if (db.databaseName === null) {
        error(
          `${where(worker)}: D1 binding ${db.binding} needs database_name, so that the deploy script can create and migrate it`,
        );
      }
      const keys = [
        db.databaseName === null ? null : `D1 database ${db.databaseName}`,
        db.databaseId === null ? null : `D1 database_id ${db.databaseId}`,
      ];
      for (const key of keys) {
        if (key === null) continue;
        const owner = databases.get(key);
        if (owner !== undefined && owner !== worker.name) {
          error(
            `${where(worker)}: ${key} is also bound by ${owner}; each database belongs to one Worker (D-08)`,
          );
        }
        databases.set(key, worker.name);
      }
    }
  }
  return issues;
}

/**
 * Refuses every key outside the Worker's lists, once per key: under a refused
 * key, nothing more is reported.
 */
function checkKeys(worker: WorkerConfig, error: (m: string) => void) {
  const allowed = CONFIG_KEYS[worker.name] ?? [];
  const refused = new Set<string>();
  for (const path of worker.keys) {
    const name = formatPath(path);
    const parents = path.slice(1).map((_, i) => formatPath(path.slice(0, i + 1)));
    if (parents.some((parent) => refused.has(parent)) || refused.has(name)) continue;
    const top = String(path[0]);
    if (path.length === 1 ? allowed.includes(top) : NESTED_KEYS.has(name)) continue;
    refused.add(name);
    const reason = KEY_REASONS.get(name);
    if (reason !== undefined) error(`${where(worker)}: ${reason}`);
    else if (path.length === 1 && Object.values(CONFIG_KEYS).some((keys) => keys.includes(top))) {
      error(
        `${where(worker)}: ${worker.name} may not set ${name}; the deploy does not check it there, and Wrangler would deploy it`,
      );
    } else {
      error(
        `${where(worker)}: ${name} is not supported: the deploy does not check it, and Wrangler would deploy it`,
      );
    }
  }
}

/** `services[].entrypoint`; a key that is not a plain name is quoted, so it cannot pass for a path. */
function formatPath(path: KeyPath): string {
  return path
    .map((part, i) => {
      if (typeof part === "number") return "[]";
      if (!/^[$\w]+$/.test(part)) return `[${JSON.stringify(part)}]`;
      return i === 0 ? part : `.${part}`;
    })
    .join("");
}

function checkClasses(worker: WorkerConfig, exportsOf: ExportsOf, error: (m: string) => void) {
  const bindings = [
    ...worker.durableObjects.map((b) => ({ ...b, kind: "Durable Object" })),
    ...worker.workflows.map((b) => ({ ...b, kind: "Workflow" })),
  ];
  const local = bindings.filter((b) => b.scriptName === null || b.scriptName === worker.name);
  for (const b of bindings) {
    if (local.includes(b)) continue;
    error(
      `${where(worker)}: ${b.kind} binding ${b.binding} uses class ${b.className} of ${b.scriptName}; bindings to another Worker's classes are not part of the topology`,
    );
  }
  if (local.length === 0) return;
  const exported = exportsOf(worker);
  if (exported === null) {
    error(`${where(worker)}: cannot read the main module to check its ${local[0]?.kind} classes`);
    return;
  }
  for (const b of local) {
    if (!exported.names.has(b.className) && !exported.star) {
      error(
        `${where(worker)}: ${b.kind} binding ${b.binding} names class ${b.className}, which ${worker.main} does not export`,
      );
    }
  }
}

function checkState(worker: WorkerConfig, error: (m: string) => void) {
  const at = where(worker);
  if (STATELESS.has(worker.name)) {
    if (worker.d1.length > 0) error(`${at}: ${worker.name} must not bind D1 databases`);
    if (worker.durableObjects.length > 0) {
      error(
        `${at}: ${worker.name} must not bind Durable Objects; it reads the graph through GraphReader`,
      );
    }
    if (worker.workflows.length > 0) {
      error(`${at}: ${worker.name} must not bind Workflows; it starts scans through Admin`);
    }
  }
  if (worker.name !== KEY_HOLDER && worker.secretsStore.length > 0) {
    error(`${at}: only ${KEY_HOLDER} binds Secrets Store secrets (the master key, D-15)`);
  }
}

const allowed = (grants: readonly Grant[]) =>
  grants.length === 0 ? "none" : grants.map((g) => `${g.service}#${g.entrypoint}`).join(", ");

const where = (worker: WorkerConfig) => worker.displayPath;
