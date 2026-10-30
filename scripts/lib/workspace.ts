import { createHash } from "node:crypto";
import {
  lstatSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  statSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { parseJsonc } from "./jsonc.ts";

/** The scope of the workspace packages under packages/. */
const SCOPE = "@virga";

/** Paths named in a message; the rest are counted. */
const SHOWN = 5;

export class WorkspaceError extends Error {}

/** A path relative to the repository root, or as it is when outside it. */
const shown = (root: string, path: string) => {
  const inside = relative(root, path);
  return inside.startsWith("..") ? path : inside;
};

const list = (root: string, paths: readonly string[]) => {
  const more = paths.length > SHOWN ? ` and ${paths.length - SHOWN} more` : "";
  return `${paths
    .slice(0, SHOWN)
    .map((path) => shown(root, path))
    .join(", ")}${more}`;
};

const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error));

/**
 * The files Wrangler's bundler, esbuild 0.28.2, reads in a directory to
 * resolve the imports of the modules below it (R10-04): package.json for
 * exports, main, imports and browser, and tsconfig.json, or jsconfig.json
 * without one, for paths and baseUrl. esbuild finds them by name in any
 * case.
 */
const RESOLUTION_FILES = new Set(["package.json", "tsconfig.json", "jsconfig.json"]);
const TSCONFIG_FILES = new Set(["tsconfig.json", "jsconfig.json"]);
const isResolutionFile = (name: string) => RESOLUTION_FILES.has(name.toLowerCase());
const isTsconfig = (path: string) => TSCONFIG_FILES.has(basename(path).toLowerCase());

export interface Sources {
  /** Symlinks, the directory itself included when it is one. */
  links: string[];
  /** node_modules directories other than the directory's own. */
  modules: string[];
  /** Files named package.json, tsconfig.json or jsconfig.json, in any case (R10-04). */
  resolution: string[];
}

/**
 * What a bundler reads through or resolves from under `dir`, outside its
 * own node_modules, where pnpm links every dependency as the lockfile says:
 * symlinks, whose targets it reads wherever they are, other node_modules
 * directories, which it searches first for a package imported below them,
 * and the package.json and tsconfig files that tell it how to resolve an
 * import.
 */
export function walkSources(dir: string): Sources {
  if (lstatSync(dir, { throwIfNoEntry: false })?.isSymbolicLink()) {
    return { links: [dir], modules: [], resolution: [] };
  }
  const found: Sources = { links: [], modules: [], resolution: [] };
  const pending = [dir];
  for (let current = pending.pop(); current !== undefined; current = pending.pop()) {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (current === dir && entry.name === "node_modules") continue;
      if (entry.isSymbolicLink()) {
        found.links.push(path);
      } else if (entry.isDirectory()) {
        // Case-insensitive file systems open node_modules under any case.
        if (entry.name.toLowerCase() === "node_modules") found.modules.push(path);
        pending.push(path);
      } else if (isResolutionFile(entry.name)) {
        found.resolution.push(path);
      }
    }
  }
  found.links.sort();
  found.modules.sort();
  found.resolution.sort();
  return found;
}

/**
 * The workspace packages an app bundles, as the deploy recorded them (L-2).
 * Wrangler bundles most of virga-core's and virga-broker's code from
 * packages/ through the links pnpm puts in node_modules/@virga.
 */
export interface WorkspaceRecord {
  root: string;
  app: string;
  /** apps/<app>. */
  appDir: string;
  /**
   * Every link in node_modules/@virga of the app and of the workspace
   * packages they lead to, by path, with the real path of the package.
   */
  links: ReadonlyMap<string, string>;
  /**
   * The files that tell esbuild how to resolve the app's imports, by path,
   * with the sha256 of each, `absent` for a path an extends could name, or
   * what stands there instead of a file (R10-04): every package.json,
   * tsconfig.json and jsconfig.json in the app directory and in the
   * workspace packages it bundles, outside their node_modules, and in every
   * directory above them, and the files their tsconfig files extend.
   */
  resolution: ReadonlyMap<string, string>;
}

const realOrNull = (path: string) => {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
};

function packageName(dir: string): unknown {
  try {
    const pkg: unknown = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    return typeof pkg === "object" && pkg !== null ? (pkg as { name?: unknown }).name : null;
  } catch {
    return null;
  }
}

const sha256 = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");

/** How a resolution file is recorded: its sha256, `absent`, or what stands there instead. */
function fingerprint(path: string): string {
  try {
    const stat = lstatSync(path, { throwIfNoEntry: false });
    if (stat === undefined) return "absent";
    if (stat.isSymbolicLink()) {
      let content = "dangling";
      try {
        content = sha256(readFileSync(path));
      } catch {}
      return `link:${readlinkSync(path)} ${content}`;
    }
    if (stat.isFile()) return sha256(readFileSync(path));
    return stat.isDirectory() ? "directory" : "other";
  } catch (error) {
    return `unreadable: ${(error as NodeJS.ErrnoException).code ?? errorText(error)}`;
  }
}

/** The directories above `dir`, nearest first, up to the filesystem root. */
function above(dir: string): string[] {
  const out: string[] = [];
  for (let current = dir; dirname(current) !== current; current = dirname(current)) {
    out.push(dirname(current));
  }
  return out;
}

/**
 * The resolution files in `dir` itself, by any case. Where the directory
 * cannot be listed, esbuild finds none either; the names as spelled are
 * checked anyway.
 */
function resolutionFilesIn(dir: string): string[] {
  try {
    return readdirSync(dir)
      .filter(isResolutionFile)
      .map((name) => join(dir, name))
      .sort();
  } catch {
    return [...RESOLUTION_FILES]
      .map((name) => join(dir, name))
      .filter((path) => fingerprint(path) !== "absent");
  }
}

/** Whether `path` is a file, or a link to one. */
function isFile(path: string): boolean {
  try {
    return statSync(path, { throwIfNoEntry: false })?.isFile() === true;
  } catch {
    return false;
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * compilerOptions that map an import to a file before node_modules is
 * searched: esbuild follows paths and baseUrl, TypeScript rootDirs too.
 * Virga sets none of them.
 */
const MAPPING_OPTIONS = ["paths", "baseUrl", "rootDirs"];

/** An extends that esbuild and TypeScript take as a path, not as a package in node_modules. */
const isPath = (value: string) => /^\.\.?[\\/]/.test(value) || isAbsolute(value);

/**
 * Records the resolution files of `trees`, the app directory and the
 * workspace packages it bundles, each with the resolution files walkSources
 * found under it: those files, the ones in every directory above each tree,
 * and the files the tsconfig files extend, the way esbuild 0.28.2 and
 * TypeScript follow extends. esbuild takes the nearest tsconfig.json, or
 * jsconfig.json, above a module; each found under a tree is one, and so is
 * the nearest above a tree that holds none at its top. Each of these, and
 * each file it extends, must set none of MAPPING_OPTIONS and extend only
 * files by path (R10-04).
 */
function recordResolution(
  root: string,
  app: string,
  trees: ReadonlyMap<string, readonly string[]>,
  problems: string[],
): Map<string, string> {
  const files = new Map<string, string>();
  const record = (path: string) => {
    if (!files.has(path)) files.set(path, fingerprint(path));
    return files.get(path) as string;
  };
  /** tsconfig files to check, each with the file that extends it, or null. */
  const pending: [string, string | null][] = [];
  const listed = new Map<string, string[]>();
  const filesIn = (dir: string) => {
    let found = listed.get(dir);
    if (found === undefined) {
      found = resolutionFilesIn(dir);
      listed.set(dir, found);
    }
    return found;
  };
  for (const [dir, found] of trees) {
    for (const path of found) record(path);
    const configs = found.filter(isTsconfig);
    for (const path of configs) pending.push([path, null]);
    let nearest = configs.some((path) => dirname(path) === dir);
    for (const parent of above(dir)) {
      const here = filesIn(parent);
      for (const path of here) record(path);
      // esbuild skips a directory of that name.
      const configsHere = here.filter((path) => isTsconfig(path) && isFile(path));
      if (!nearest && configsHere.length > 0) {
        for (const path of configsHere) pending.push([path, null]);
        nearest = true;
      }
    }
  }

  const checked = new Set<string>();
  for (let next = pending.shift(); next !== undefined; next = pending.shift()) {
    const [path, from] = next;
    if (checked.has(path)) continue;
    checked.add(path);
    const label =
      from === null
        ? shown(root, path)
        : `${shown(root, path)}, which ${shown(root, from)} extends`;
    /** The file as the subject of a sentence. */
    const name = from === null ? label : `${label},`;
    let config: unknown;
    try {
      config = parseJsonc(readFileSync(path, "utf8"));
    } catch (error) {
      problems.push(
        `${name} cannot be read as JSON with comments: ${errorText(error)}. Wrangler's bundler (esbuild) reads it to resolve imports, so the deploy checks it too. Fix it`,
      );
      continue;
    }
    if (!isRecord(config)) {
      problems.push(`${name} holds no JSON object. Fix it`);
      continue;
    }
    const options = config.compilerOptions;
    const mapping = isRecord(options)
      ? MAPPING_OPTIONS.filter((key) => Object.hasOwn(options, key))
      : [];
    if (mapping.length > 0) {
      problems.push(
        `${name} sets ${mapping.map((key) => `compilerOptions.${key}`).join(" and ")}: Wrangler's bundler (esbuild) resolves imports through paths and baseUrl before node_modules, and TypeScript through rootDirs too, so a mapping could make apps/${app} bundle another module in place of a workspace package, past the checks of the workspace links and the generated rules. Virga sets none of them; remove it`,
      );
    }
    if (!Object.hasOwn(config, "extends")) continue;
    const value = config.extends;
    const bases = typeof value === "string" ? [value] : Array.isArray(value) ? value : [null];
    for (const base of bases) {
      if (typeof base !== "string") {
        problems.push(`${label}: extends is neither a path nor a list of paths. Fix it`);
        break;
      }
      if (!isPath(base)) {
        problems.push(
          `${name} extends ${JSON.stringify(base)}, a package: esbuild and TypeScript would look for it in node_modules, where the deploy does not check it. Extend a file by its path, starting with ./ or ../, as Virga's tsconfig files extend ../../tsconfig.base.json`,
        );
        continue;
      }
      // As esbuild and TypeScript do: the path as written, then with .json added.
      const target = resolve(dirname(path), base);
      let file = target;
      if (record(target) === "absent" && !target.endsWith(".json")) {
        file = `${target}.json`;
        record(file);
      }
      if (!isFile(file)) {
        const tried = file === target ? "" : ", also with .json";
        problems.push(
          `${name} extends ${JSON.stringify(base)}, which is not a file (${shown(root, target)}${tried}). Fix or remove the extends`,
        );
        continue;
      }
      pending.push([file, path]);
    }
  }
  return files;
}

/**
 * Records the workspace packages apps/<app> bundles: each entry of the app's
 * node_modules/@virga, and of the node_modules/@virga of every workspace
 * package reached that way, must lead to packages/<name>, the package named
 * @virga/<name>. The packages reached hold no symlink and no node_modules
 * directory outside their own node_modules (as walkSources finds them), so
 * Wrangler bundles the files in packages/ and nothing a link or a planted
 * package puts in their place. It also records the files that tell esbuild
 * how to resolve the app's imports, whose tsconfig files may map no import
 * (recordResolution, R10-04). Throws a WorkspaceError naming every problem.
 */
export function recordWorkspace(root: string, app: string): WorkspaceRecord {
  const appDir = join(root, "apps", app);
  const links = new Map<string, string>();
  const problems: string[] = [];
  /** Each workspace package reached, with the first link that reached it. */
  const reached = new Map<string, string>();
  const pending = [appDir];
  for (let from = pending.shift(); from !== undefined; from = pending.shift()) {
    const scope = join(from, "node_modules", SCOPE);
    const stat = lstatSync(scope, { throwIfNoEntry: false });
    if (stat === undefined) continue;
    if (!stat.isDirectory()) {
      problems.push(
        `${shown(root, scope)} is not a directory; pnpm links each workspace package into a directory of that name. Run pnpm install`,
      );
      continue;
    }
    for (const name of readdirSync(scope).sort()) {
      const link = join(scope, name);
      const expected = join(root, "packages", name);
      const target = realOrNull(link);
      const workspace = packageName(expected) === `${SCOPE}/${name}` ? realOrNull(expected) : null;
      if (target === null) {
        problems.push(
          `${shown(root, link)} leads to a path that does not exist; it should lead to packages/${name}. Run pnpm install`,
        );
      } else if (workspace === null) {
        problems.push(
          `${shown(root, link)}: packages/${name} is not the workspace package ${SCOPE}/${name}, so Wrangler would bundle what the link leads to (${target}) unchecked. Remove it and run pnpm install`,
        );
      } else if (target !== workspace) {
        problems.push(
          `${shown(root, link)} leads to ${target}, not to packages/${name}, the workspace package ${SCOPE}/${name}; Wrangler would bundle what it leads to. Unless you changed the link yourself, find what wrote it, starting with the build scripts, and deploy from a fresh clone (operator guide, Troubleshooting)`,
        );
      } else {
        links.set(link, target);
        if (!reached.has(expected)) {
          reached.set(expected, link);
          pending.push(expected);
        }
      }
    }
  }
  /** The resolution files under the app directory and each package reached. */
  const trees = new Map<string, string[]>();
  // The app's own links and node_modules directories are checkAppDir's.
  if (lstatSync(appDir, { throwIfNoEntry: false })?.isDirectory()) {
    try {
      trees.set(appDir, walkSources(appDir).resolution);
    } catch (error) {
      problems.push(`apps/${app} cannot be read: ${errorText(error)}`);
    }
  }
  for (const [dir, via] of reached) {
    const where = `${shown(root, dir)}, which apps/${app} bundles through ${shown(root, via)},`;
    let found: Sources;
    try {
      found = walkSources(dir);
    } catch (error) {
      problems.push(`${where} cannot be read: ${errorText(error)}`);
      continue;
    }
    trees.set(dir, found.resolution);
    if (found.links.length > 0) {
      problems.push(
        `${where} holds symlinks outside node_modules: ${list(root, found.links)}. Wrangler bundles what a link points to, wherever that is. Replace each link with the file`,
      );
    }
    if (found.modules.length > 0) {
      problems.push(
        `${where} holds node_modules directories other than its own: ${list(root, found.modules)}. Wrangler takes a package from the nearest node_modules directory, so one there would replace the package pnpm installed. Remove them`,
      );
    }
  }
  const resolution = recordResolution(root, app, trees, problems);
  if (problems.length > 0) throw new WorkspaceError(problems.join("\n"));
  return { root, app, appDir, links, resolution };
}

/**
 * Why the workspace packages of `before.app` are no longer those recorded
 * before the builds, or null: a link added, removed or retargeted, a
 * resolution file added, removed or changed, or any problem recordWorkspace
 * finds now. Without a link, Wrangler would look for the package in the
 * node_modules directories further up.
 */
export function workspaceChanges(before: WorkspaceRecord): string | null {
  let now: WorkspaceRecord;
  try {
    now = recordWorkspace(before.root, before.app);
  } catch (error) {
    return errorText(error);
  }
  const changes: string[] = [];
  const changed = [...new Set([...before.links.keys(), ...now.links.keys()])]
    .filter((path) => before.links.get(path) !== now.links.get(path))
    .sort();
  if (changed.length > 0) {
    changes.push(
      `the workspace links of apps/${before.app} changed after the deploy recorded them before the builds: ${list(before.root, changed)}. Wrangler takes the workspace packages through them. Unless you changed them yourself, find what wrote them, starting with the build scripts, and deploy from a fresh clone (operator guide, Troubleshooting)`,
    );
  }
  const was = (path: string) => before.resolution.get(path) ?? "absent";
  const is = (path: string) => now.resolution.get(path) ?? "absent";
  const files = [...new Set([...before.resolution.keys(), ...now.resolution.keys()])]
    .filter((path) => was(path) !== is(path))
    .sort()
    .map((path) => {
      const how = was(path) === "absent" ? "added" : is(path) === "absent" ? "removed" : "changed";
      return `${shown(before.root, path)} (${how})`;
    });
  if (files.length > 0) {
    const more = files.length > SHOWN ? ` and ${files.length - SHOWN} more` : "";
    changes.push(
      `the files that tell Wrangler's bundler how to resolve the modules of apps/${before.app} changed after the deploy recorded them before the builds: ${files.slice(0, SHOWN).join(", ")}${more}. esbuild takes paths and baseUrl from tsconfig.json and jsconfig.json and the files they extend, and exports, main, imports and browser from package.json, so a change there can make Wrangler bundle another module than the one the deploy checked. Unless you changed them yourself, find what wrote them, starting with the build scripts, and deploy from a fresh clone (operator guide, Troubleshooting)`,
    );
  }
  return changes.length > 0 ? changes.join("\n") : null;
}
