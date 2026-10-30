import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { parseJsonc } from "./jsonc.ts";
import { dotEnvFiles, dotEnvProblem, sha256 } from "./run.ts";

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

/** Where a key sits in a config: object keys, and array indexes as numbers. */
export type KeyPath = readonly (string | number)[];

/** The parts of a Wrangler configuration that the deploy script checks. */
export interface WorkerConfig {
  /** Directory name under apps/, for example `broker`. */
  app: string;
  dir: string;
  configPath: string;
  /** sha256 of the config's bytes as the script read and checked them (R6-01). */
  configSha256: string;
  /** Config path relative to the repository root, for messages. */
  displayPath: string;
  name: string;
  main: string | null;
  workersDev: boolean | null;
  previewUrls: boolean | null;
  hasRoutes: boolean;
  hasAssets: boolean;
  /** `assets.directory` as written; Wrangler resolves it against the config's directory. */
  assetsDirectory: string | null;
  /**
   * Every key in the config, parents before children, so that checkTopology
   * can refuse what it does not check (R5-02). The names inside `vars` are free.
   */
  keys: KeyPath[];
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

/** Symlinks named in a message; the rest are counted. */
const SHOWN_LINKS = 5;

/** A path relative to the repository root, or as it is when outside it. */
const shown = (root: string, path: string) => {
  const inside = relative(root, path);
  return inside.startsWith("..") ? path : inside;
};

/** Refuses a Wrangler config above the app and a .env file Wrangler would load. */
function checkSurroundings(root: string, app: string, configPath: string) {
  const dir = dirname(configPath);
  const where = relative(root, configPath);
  const above = configsAbove(dir);
  if (above.length > 0) {
    throw new ConfigError(
      above
        .map(
          (path) =>
            `${where}: ${shown(root, path)} is a Wrangler config above the app; Wrangler run in apps/${app} without --config would use it. Remove it`,
        )
        .join("\n"),
    );
  }
  const dotEnv = dotEnvFiles(dir);
  if (dotEnv.length > 0) {
    throw new ConfigError(dotEnv.map((path) => dotEnvProblem(shown(root, path))).join("\n"));
  }
}

/**
 * Symlinks under `dir`, the directory itself included, but not in its own
 * node_modules: pnpm links every dependency there, as the lockfile says.
 */
function appLinks(dir: string): string[] {
  if (lstatSync(dir, { throwIfNoEntry: false })?.isSymbolicLink()) return [dir];
  const links: string[] = [];
  const pending = [dir];
  for (let current = pending.pop(); current !== undefined; current = pending.pop()) {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (current === dir && entry.name === "node_modules") continue;
      if (entry.isSymbolicLink()) links.push(path);
      else if (entry.isDirectory()) pending.push(path);
    }
  }
  return links.sort();
}

/**
 * The checks of apps/<app> that need no parsed config: one Wrangler config,
 * none above the app, no .env file, and no symlink outside node_modules.
 * Wrangler bundles, migrates and uploads what a link points to, and Vite
 * copies it, from wherever that is. The deploy runs these before the builds
 * and again after them (R6-01). Returns the config's path, or null when the
 * app has none.
 */
export function checkAppDir(root: string, app: string): string | null {
  const dir = join(root, "apps", app);
  const configPath = findConfigFile(dir);
  if (configPath === null) return null;
  checkSurroundings(root, app, configPath);
  let links: string[];
  try {
    links = appLinks(dir);
  } catch (error) {
    throw new ConfigError(
      `apps/${app} cannot be read: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (links.length > 0) {
    const list = links.slice(0, SHOWN_LINKS).map((path) => shown(root, path));
    const more = links.length > SHOWN_LINKS ? ` and ${links.length - SHOWN_LINKS} more` : "";
    throw new ConfigError(
      `apps/${app} holds symlinks outside node_modules: ${list.join(", ")}${more}. Wrangler and Vite read what a link points to, wherever that is, into the bundle, the migrations and the assets. Replace each link with the file`,
    );
  }
  return configPath;
}

/**
 * Reads apps/<app>/wrangler.jsonc, and records the sha256 of the bytes it
 * checked. Returns null when the app or its config does not exist.
 */
export function readWorkerConfig(root: string, app: string): WorkerConfig | null {
  const dir = join(root, "apps", app);
  const configPath = findConfigFile(dir);
  if (configPath === null) return null;
  const where = relative(root, configPath);
  checkSurroundings(root, app, configPath);
  let raw: unknown;
  let bytes: Buffer;
  try {
    bytes = readFileSync(configPath);
    raw = parseJsonc(bytes.toString("utf8"));
  } catch (error) {
    throw new ConfigError(`${where}: ${error instanceof Error ? error.message : String(error)}`);
  }
  const config = {
    ...parseWorkerConfig(raw, { app, dir, configPath, where }),
    configSha256: sha256(bytes),
  };
  const assets = assetsDirectoryProblem(config);
  if (assets !== null) throw new ConfigError(`${where}: ${assets}`);
  return config;
}

type AssetsSource = Pick<WorkerConfig, "app" | "dir" | "name" | "assetsDirectory">;

/**
 * `path` with every symlink followed, and the part that does not exist yet
 * as written; or the link on the way that points nowhere.
 */
function realPath(path: string): { real: string } | { dangling: string } {
  const rest: string[] = [];
  let current = path;
  for (;;) {
    try {
      return { real: join(realpathSync(current), ...rest) };
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" || dirname(current) === current) throw error;
    }
    if (lstatSync(current, { throwIfNoEntry: false })?.isSymbolicLink()) {
      return { dangling: current };
    }
    rest.unshift(basename(current));
    current = dirname(current);
  }
}

/**
 * Why Wrangler would upload files from outside apps/<app> as the Worker's
 * assets, or null. assets.directory is resolved as Wrangler resolves it,
 * then with symlinks followed, so a link counts where it points. A directory
 * the build has yet to create is checked as written (R5-03).
 */
export function assetsDirectoryProblem(worker: AssetsSource): string | null {
  const directory = worker.assetsDirectory;
  if (directory === null) return null;
  const at = `assets.directory "${directory}"`;
  const app = `apps/${worker.app}`;
  let appDir: string;
  let resolved: ReturnType<typeof realPath>;
  try {
    appDir = realpathSync(worker.dir);
    resolved = realPath(resolve(worker.dir, directory));
  } catch (error) {
    return `${at} cannot be resolved: ${error instanceof Error ? error.message : String(error)}`;
  }
  if ("dangling" in resolved) {
    return `${at} passes through ${resolved.dangling}, a symlink to a path that does not exist. Remove the link`;
  }
  const inside = relative(appDir, resolved.real);
  if (inside === "") {
    return `${at} is ${app} itself; Wrangler would upload its sources and config with ${worker.name}. Use a directory below it, such as ./dist/client`;
  }
  if (inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) {
    return `${at} resolves to ${resolved.real} (symlinks followed), outside ${app}; Wrangler would upload what it holds with ${worker.name}. Keep the assets in a directory below ${app}`;
  }
  return null;
}

/**
 * Symlinks in the assets directory, once the build has filled it. Wrangler
 * uploads the file a link points to and the files under a linked directory,
 * wherever they are, so the assets must be plain files and directories.
 */
export function assetsLinkProblem(worker: AssetsSource): string | null {
  if (worker.assetsDirectory === null) return null;
  const dir = resolve(worker.dir, worker.assetsDirectory);
  if (!existsSync(dir)) return null;
  const at = `assets.directory "${worker.assetsDirectory}"`;
  const links: string[] = [];
  try {
    const pending = [dir];
    for (let current = pending.pop(); current !== undefined; current = pending.pop()) {
      for (const entry of readdirSync(current, { withFileTypes: true })) {
        const path = join(current, entry.name);
        if (entry.isSymbolicLink()) links.push(path);
        else if (entry.isDirectory()) pending.push(path);
      }
    }
  } catch (error) {
    return `${at} cannot be read: ${error instanceof Error ? error.message : String(error)}`;
  }
  if (links.length === 0) return null;
  const shown = links
    .map((path) => join("apps", worker.app, relative(worker.dir, path)))
    .sort()
    .slice(0, SHOWN_LINKS);
  const more = links.length > SHOWN_LINKS ? ` and ${links.length - SHOWN_LINKS} more` : "";
  return `${at} holds symlinks, whose targets Wrangler would upload: ${shown.join(", ")}${more}. Replace them with the files`;
}

interface Source {
  app: string;
  dir: string;
  configPath: string;
  /** Path shown in messages. */
  where: string;
}

/** Validates the fields the checks rely on and collects every problem before failing. */
export function parseWorkerConfig(
  raw: unknown,
  source: Source,
): Omit<WorkerConfig, "configSha256"> {
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

  const assets = raw.assets;
  if (assets !== undefined && !isRecord(assets)) fail("assets must be an object");
  const assetsDirectory = isRecord(assets) ? str(assets, "directory", "assets") : null;

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
    assetsDirectory,
    keys: keyPaths(raw),
    services,
    d1,
    secretsStore,
    durableObjects,
    workflows,
    vars: isRecord(vars) ? vars : {},
    requiredSecrets,
  };
}

function keyPaths(value: unknown, path: KeyPath = []): KeyPath[] {
  if (Array.isArray(value)) return value.flatMap((item, i) => keyPaths(item, [...path, i]));
  if (!isRecord(value) || (path.length === 1 && path[0] === "vars")) return [];
  return Object.entries(value).flatMap(([key, child]) => [
    [...path, key],
    ...keyPaths(child, [...path, key]),
  ]);
}
