import type { WorkerConfig } from "./config.ts";
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

/** Workers that hold no state and no keys: no D1, no Durable Objects, no Secrets Store. */
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
    if (worker.hasEnvironments) {
      error(
        `${at}: named environments (env) are not supported; the deploy checks only the top-level configuration, and Wrangler would deploy an environment chosen with --env or CLOUDFLARE_ENV unchecked`,
      );
    }
  }

  const databases = new Map<string, string>();
  for (const worker of byName.values()) {
    for (const db of worker.d1) {
      const key = db.databaseName ?? db.databaseId;
      if (db.databaseName === null) {
        error(
          `${where(worker)}: D1 binding ${db.binding} needs database_name, so that the deploy script can create and migrate it`,
        );
      }
      if (key === null) continue;
      const owner = databases.get(key);
      if (owner !== undefined && owner !== worker.name) {
        error(
          `${where(worker)}: D1 database ${key} is also bound by ${owner}; each database belongs to one Worker (D-08)`,
        );
      }
      databases.set(key, worker.name);
    }
  }
  return issues;
}

function checkClasses(worker: WorkerConfig, exportsOf: ExportsOf, error: (m: string) => void) {
  const local = [
    ...worker.durableObjects.map((b) => ({ ...b, kind: "Durable Object" })),
    ...worker.workflows.map((b) => ({ ...b, kind: "Workflow" })),
  ].filter((b) => b.scriptName === null || b.scriptName === worker.name);
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
  }
  if (worker.name !== KEY_HOLDER && worker.secretsStore.length > 0) {
    error(`${at}: only ${KEY_HOLDER} binds Secrets Store secrets (the master key, D-15)`);
  }
}

const allowed = (grants: readonly Grant[]) =>
  grants.length === 0 ? "none" : grants.map((g) => `${g.service}#${g.entrypoint}`).join(", ");

const where = (worker: WorkerConfig) => worker.displayPath;
