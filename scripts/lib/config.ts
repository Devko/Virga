import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { parseJsonc } from "./jsonc.ts";

export interface ServiceBinding {
  binding: string;
  service: string;
  /** Named entrypoint; null binds the default export. */
  entrypoint: string | null;
}

export interface D1Binding {
  binding: string;
  databaseName: string | null;
  databaseId: string | null;
  /** As configured, or Wrangler's default `migrations`. */
  migrationsDir: string;
}

export interface SecretsStoreBinding {
  binding: string;
  storeId: string;
  secretName: string;
}

/** A Durable Object or Workflow binding: a class, here or in another Worker. */
export interface ClassBinding {
  binding: string;
  className: string;
  scriptName: string | null;
}

/** The parts of a Wrangler configuration that the deploy script checks. */
export interface WorkerConfig {
  /** Directory name under apps/, for example `broker`. */
  app: string;
  dir: string;
  configPath: string;
  /** Config path relative to the repository root, for messages. */
  displayPath: string;
  name: string;
  main: string | null;
  workersDev: boolean | null;
  previewUrls: boolean | null;
  hasRoutes: boolean;
  hasAssets: boolean;
  hasEnvironments: boolean;
  services: ServiceBinding[];
  d1: D1Binding[];
  secretsStore: SecretsStoreBinding[];
  durableObjects: ClassBinding[];
  workflows: ClassBinding[];
  vars: Record<string, unknown>;
  /** `secrets.required`: secrets Wrangler insists on at deploy time. */
  requiredSecrets: string[];
}

export class ConfigError extends Error {}

/** The files Wrangler looks for without --config, in its order. */
const WRANGLER_FILES = ["wrangler.json", "wrangler.jsonc", "wrangler.toml"];

type Json = Record<string, unknown>;

const isRecord = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Path of the app's Wrangler configuration, or null when the app has none. */
export function findConfigFile(dir: string): string | null {
  const found = WRANGLER_FILES.map((file) => join(dir, file)).filter((path) => existsSync(path));
  if (found.length > 1) {
    throw new ConfigError(
      `${found.join(" and ")}: an app has one Wrangler config; remove all but one`,
    );
  }
  const path = found[0];
  if (path === undefined) return null;
  if (path.endsWith(".toml")) {
    throw new ConfigError(`${path}: only wrangler.jsonc and wrangler.json are supported`);
  }
  return path;
}

/**
 * Wrangler configs in the directories above `dir`, up to the filesystem root.
 * Wrangler run there without --config takes the first wrangler.json above
 * before the app's own wrangler.jsonc (R3-03).
 */
export function configsAbove(dir: string): string[] {
  const found: string[] = [];
  let current = dir;
  while (dirname(current) !== current) {
    current = dirname(current);
    for (const file of WRANGLER_FILES) {
      if (existsSync(join(current, file))) found.push(join(current, file));
    }
  }
  return found;
}

/** Reads apps/<app>/wrangler.jsonc. Returns null when the app or its config does not exist. */
export function readWorkerConfig(root: string, app: string): WorkerConfig | null {
  const dir = join(root, "apps", app);
  const configPath = findConfigFile(dir);
  if (configPath === null) return null;
  const where = relative(root, configPath);
  const show = (path: string) => {
    const inside = relative(root, path);
    return inside.startsWith("..") ? path : inside;
  };
  const above = configsAbove(dir);
  if (above.length > 0) {
    throw new ConfigError(
      above
        .map(
          (path) =>
            `${where}: ${show(path)} is a Wrangler config above the app; Wrangler run in apps/${app} without --config would use it. Remove it`,
        )
        .join("\n"),
    );
  }
  let raw: unknown;
  try {
    raw = parseJsonc(readFileSync(configPath, "utf8"));
  } catch (error) {
    throw new ConfigError(`${where}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return parseWorkerConfig(raw, { app, dir, configPath, where });
}

interface Source {
  app: string;
  dir: string;
  configPath: string;
  /** Path shown in messages. */
  where: string;
}

/** Validates the fields the checks rely on and collects every problem before failing. */
export function parseWorkerConfig(raw: unknown, source: Source): WorkerConfig {
  const problems: string[] = [];
  const fail = (message: string) => problems.push(message);
  if (!isRecord(raw)) throw new ConfigError(`${source.where}: the configuration is not an object`);

  const str = (obj: Json, key: string, at: string): string | null => {
    const value = obj[key];
    if (value === undefined) return null;
    if (typeof value === "string" && value.length > 0) return value;
    fail(`${at}.${key} must be a non-empty string`);
    return null;
  };
  const bool = (key: string): boolean | null => {
    const value = raw[key];
    if (value === undefined) return null;
    if (typeof value === "boolean") return value;
    fail(`${key} must be a boolean`);
    return null;
  };
  const list = (value: unknown, at: string): Json[] => {
    if (value === undefined) return [];
    if (!Array.isArray(value)) {
      fail(`${at} must be an array`);
      return [];
    }
    return value.filter((item, i) => {
      if (isRecord(item)) return true;
      fail(`${at}[${i}] must be an object`);
      return false;
    });
  };
  const required = (obj: Json, key: string, at: string): string => {
    const value = str(obj, key, at);
    if (value === null && obj[key] === undefined) fail(`${at}.${key} is missing`);
    return value ?? "";
  };

  const name = required(raw, "name", "config");

  const services = list(raw.services, "services").map((s, i): ServiceBinding => {
    const at = `services[${i}]`;
    return {
      binding: required(s, "binding", at),
      service: required(s, "service", at),
      entrypoint: str(s, "entrypoint", at),
    };
  });

  const d1 = list(raw.d1_databases, "d1_databases").map((d, i): D1Binding => {
    const at = `d1_databases[${i}]`;
    return {
      binding: required(d, "binding", at),
      databaseName: str(d, "database_name", at),
      databaseId: str(d, "database_id", at),
      migrationsDir: str(d, "migrations_dir", at) ?? "migrations",
    };
  });

  const secretsStore = list(raw.secrets_store_secrets, "secrets_store_secrets").map(
    (s, i): SecretsStoreBinding => {
      const at = `secrets_store_secrets[${i}]`;
      return {
        binding: required(s, "binding", at),
        storeId: required(s, "store_id", at),
        secretName: required(s, "secret_name", at),
      };
    },
  );

  const classBinding = (b: Json, at: string, bindingKey: string): ClassBinding => ({
    binding: required(b, bindingKey, at),
    className: required(b, "class_name", at),
    scriptName: str(b, "script_name", at),
  });
  const durable = raw.durable_objects;
  if (durable !== undefined && !isRecord(durable)) fail("durable_objects must be an object");
  const durableObjects = list(
    isRecord(durable) ? durable.bindings : undefined,
    "durable_objects.bindings",
  ).map((b, i) => classBinding(b, `durable_objects.bindings[${i}]`, "name"));
  const workflows = list(raw.workflows, "workflows").map((w, i) =>
    classBinding(w, `workflows[${i}]`, "binding"),
  );

  const vars = raw.vars === undefined ? {} : raw.vars;
  if (!isRecord(vars)) fail("vars must be an object");

  const secrets = raw.secrets;
  let requiredSecrets: string[] = [];
  if (secrets !== undefined) {
    const names = isRecord(secrets) ? secrets.required : undefined;
    if (names === undefined) requiredSecrets = [];
    else if (Array.isArray(names) && names.every((n) => typeof n === "string"))
      requiredSecrets = names;
    else fail("secrets.required must be an array of strings");
  }

  const main = str(raw, "main", "config");
  const workersDev = bool("workers_dev");
  const previewUrls = bool("preview_urls");

  if (problems.length > 0) {
    throw new ConfigError(problems.map((p) => `${source.where}: ${p}`).join("\n"));
  }
  return {
    app: source.app,
    dir: source.dir,
    configPath: source.configPath,
    displayPath: source.where,
    name,
    main,
    workersDev,
    previewUrls,
    hasRoutes: raw.routes !== undefined || raw.route !== undefined,
    hasAssets: raw.assets !== undefined,
    hasEnvironments: raw.env !== undefined,
    services,
    d1,
    secretsStore,
    durableObjects,
    workflows,
    vars: isRecord(vars) ? vars : {},
    requiredSecrets,
  };
}
