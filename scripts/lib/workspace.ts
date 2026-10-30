import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { join, relative } from "node:path";

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

export interface Sources {
  /** Symlinks, the directory itself included when it is one. */
  links: string[];
  /** node_modules directories other than the directory's own. */
  modules: string[];
}

/**
 * What a bundler reads through or resolves from under `dir`, outside its
 * own node_modules, where pnpm links every dependency as the lockfile says:
 * symlinks, whose targets it reads wherever they are, and other node_modules
 * directories, which it searches first for a package imported below them.
 */
export function walkSources(dir: string): Sources {
  if (lstatSync(dir, { throwIfNoEntry: false })?.isSymbolicLink()) {
    return { links: [dir], modules: [] };
  }
  const found: Sources = { links: [], modules: [] };
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
      }
    }
  }
  found.links.sort();
  found.modules.sort();
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

/**
 * Records the workspace packages apps/<app> bundles: each entry of the app's
 * node_modules/@virga, and of the node_modules/@virga of every workspace
 * package reached that way, must lead to packages/<name>, the package named
 * @virga/<name>. The packages reached hold no symlink and no node_modules
 * directory outside their own node_modules (as walkSources finds them), so
 * Wrangler bundles the files in packages/ and nothing a link or a planted
 * package puts in their place. Throws a WorkspaceError naming every problem.
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
  for (const [dir, via] of reached) {
    const where = `${shown(root, dir)}, which apps/${app} bundles through ${shown(root, via)},`;
    let found: Sources;
    try {
      found = walkSources(dir);
    } catch (error) {
      problems.push(
        `${where} cannot be read: ${error instanceof Error ? error.message : String(error)}`,
      );
      continue;
    }
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
  if (problems.length > 0) throw new WorkspaceError(problems.join("\n"));
  return { root, app, appDir, links };
}

/**
 * Why the workspace packages of `before.app` are no longer those recorded
 * before the builds, or null: a link added, removed or retargeted, or any
 * problem recordWorkspace finds now. Without a link, Wrangler would look for
 * the package in the node_modules directories further up.
 */
export function workspaceChanges(before: WorkspaceRecord): string | null {
  let now: WorkspaceRecord;
  try {
    now = recordWorkspace(before.root, before.app);
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  const changed = [...new Set([...before.links.keys(), ...now.links.keys()])]
    .filter((path) => before.links.get(path) !== now.links.get(path))
    .sort();
  if (changed.length === 0) return null;
  return `the workspace links of apps/${before.app} changed after the deploy recorded them before the builds: ${list(before.root, changed)}. Wrangler takes the workspace packages through them. Unless you changed them yourself, find what wrote them, starting with the build scripts, and deploy from a fresh clone (operator guide, Troubleshooting)`;
}
