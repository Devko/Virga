import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  lstatSync,
  openSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  readSync,
  realpathSync,
} from "node:fs";
import { createRequire } from "node:module";
import { basename, extname, isAbsolute, join, relative, sep } from "node:path";

/**
 * The Wrangler an app runs, as the deploy recorded it before the builds
 * (R6-01). The deploy runs `bin` with node, never the node_modules/.bin shim,
 * and only while `files` are unchanged.
 */
export interface WranglerInstall {
  /** apps/<app>, whose node_modules/wrangler this is. */
  appDir: string;
  /** Real path of the package. */
  dir: string;
  /** Real path of the package's bin file. */
  bin: string;
  version: string;
  /**
   * sha256 of every file Node can load for Wrangler, by path: the package and
   * every package it depends on, resolved as Node resolves them, plus the
   * app's Wrangler shims. A symlink is recorded as `link:` and its target.
   */
  files: ReadonlyMap<string, string>;
}

export class WranglerError extends Error {}

type Json = Record<string, unknown>;

const isRecord = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const CHUNK = 1 << 20;

/** sha256 of a file, read in chunks: workerd's binary alone is over 100 MB. */
function sha256(path: string): string {
  const hash = createHash("sha256");
  const buffer = Buffer.alloc(CHUNK);
  const fd = openSync(path, "r");
  try {
    for (
      let n = readSync(fd, buffer, 0, CHUNK, null);
      n > 0;
      n = readSync(fd, buffer, 0, CHUNK, null)
    ) {
      hash.update(buffer.subarray(0, n));
    }
  } finally {
    closeSync(fd);
  }
  return hash.digest("hex");
}

/** How an entry is recorded: its content's sha256, a symlink's target, or its kind. */
function fingerprint(path: string): string {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) return `link:${readlinkSync(path)}`;
  if (stat.isFile()) return sha256(path);
  return stat.isDirectory() ? "directory" : "other";
}

function readPackage(dir: string): Json | null {
  try {
    const pkg: unknown = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    return isRecord(pkg) ? pkg : null;
  } catch {
    return null;
  }
}

/** The directory Node loads `name` from when a module in `dir` requires it, with symlinks followed. */
function resolvePackage(dir: string, name: string): string | null {
  for (const base of createRequire(join(dir, "package.json")).resolve.paths(name) ?? []) {
    const candidate = join(base, name);
    if (existsSync(candidate)) return realpathSync(candidate);
  }
  return null;
}

/** The package and every package it depends on, by real path. */
function closure(dir: string): string[] {
  const seen = new Set<string>([dir]);
  for (const current of seen) {
    const pkg = readPackage(current);
    for (const field of ["dependencies", "optionalDependencies"]) {
      const deps = pkg?.[field];
      if (!isRecord(deps)) continue;
      for (const name of Object.keys(deps)) {
        const found = resolvePackage(current, name);
        if (found !== null) seen.add(found);
      }
    }
  }
  return [...seen];
}

/**
 * Every entry under a package, except the package's own node_modules, which
 * holds only links to its dependencies; those are packages of the closure.
 */
function packageFiles(dir: string, into: Map<string, string>) {
  const pending = [dir];
  for (let current = pending.pop(); current !== undefined; current = pending.pop()) {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (current === dir && entry.name === "node_modules") continue;
      if (entry.isDirectory()) pending.push(path);
      else into.set(path, fingerprint(path));
    }
  }
}

const inside = (dir: string, path: string) => {
  const rel = relative(dir, path);
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
};

/** Names of the package's bin files, as package.json declares them. */
function binNames(pkg: Json): Map<string, string> {
  if (typeof pkg.bin === "string") return new Map([["wrangler", pkg.bin]]);
  if (!isRecord(pkg.bin)) return new Map();
  return new Map(
    Object.entries(pkg.bin).flatMap(([name, file]) =>
      typeof file === "string" ? [[name, file] as const] : [],
    ),
  );
}

/**
 * Records the Wrangler of `appDir`: its node_modules/wrangler with symlinks
 * followed, and the hash of every file Wrangler can load. `cache` holds the
 * files of packages already hashed in this pass, so that apps sharing one
 * Wrangler hash it once.
 */
export function recordWrangler(
  appDir: string,
  cache: Map<string, Map<string, string>> = new Map(),
): WranglerInstall {
  const link = join(appDir, "node_modules", "wrangler");
  let dir: string;
  try {
    dir = realpathSync(link);
  } catch {
    throw new WranglerError(`${link} not found; run pnpm install first`);
  }
  const pkg = readPackage(dir);
  if (pkg?.name !== "wrangler" || typeof pkg.version !== "string") {
    throw new WranglerError(`${link} is not the wrangler package; run pnpm install first`);
  }
  const bins = binNames(pkg);
  const declared = bins.get("wrangler");
  let bin = "";
  try {
    bin = declared === undefined ? "" : realpathSync(join(dir, declared));
  } catch {}
  if (bin === "" || !inside(dir, bin)) {
    throw new WranglerError(
      `${link}: the wrangler bin file is missing or outside the package; run pnpm install first`,
    );
  }

  const files = new Map<string, string>();
  for (const pkgDir of closure(dir)) {
    let hashed = cache.get(pkgDir);
    if (hashed === undefined) {
      hashed = new Map();
      packageFiles(pkgDir, hashed);
      cache.set(pkgDir, hashed);
    }
    for (const [path, hash] of hashed) files.set(path, hash);
  }
  // The shims are not run by the deploy, but by `npx wrangler` in the operator guide.
  const shims = join(appDir, "node_modules", ".bin");
  for (const name of existsSync(shims) ? readdirSync(shims) : []) {
    if (bins.has(basename(name, extname(name)))) {
      files.set(join(shims, name), fingerprint(join(shims, name)));
    }
  }
  return { appDir, dir, bin, version: pkg.version, files };
}

/** Records the Wrangler of each app directory, hashing a shared package once. */
export function recordWranglers(appDirs: readonly string[]): Map<string, WranglerInstall> {
  const cache = new Map<string, Map<string, string>>();
  return new Map(appDirs.map((appDir) => [appDir, recordWrangler(appDir, cache)]));
}

const SHOWN = 5;

/**
 * What differs between `before` and the Wrangler of the same app now: files
 * added, removed or changed, another package or another bin file. Empty when
 * nothing changed.
 */
export function wranglerChanges(
  before: WranglerInstall,
  cache: Map<string, Map<string, string>> = new Map(),
): string[] {
  let now: WranglerInstall;
  try {
    now = recordWrangler(before.appDir, cache);
  } catch (error) {
    return [error instanceof Error ? error.message : String(error)];
  }
  const changes: string[] = [];
  if (now.dir !== before.dir) changes.push(`${before.dir} (now ${now.dir})`);
  if (now.bin !== before.bin) changes.push(`${before.bin} (now ${now.bin})`);
  for (const [path, hash] of now.files) {
    if (before.files.get(path) !== hash) changes.push(path);
  }
  for (const path of before.files.keys()) {
    if (!now.files.has(path)) changes.push(path);
  }
  return changes.sort();
}

/** The message for changed Wrangler files, or null when nothing changed. */
export function describeChanges(appDir: string, changes: readonly string[]): string | null {
  if (changes.length === 0) return null;
  const more = changes.length > SHOWN ? ` and ${changes.length - SHOWN} more` : "";
  return `the Wrangler of ${appDir} changed after the deploy recorded it before the builds: ${changes.slice(0, SHOWN).join(", ")}${more}. Something wrote to the files Wrangler runs, which the deploy refuses to run with or without the token. Reinstall with pnpm install --frozen-lockfile and find what changed them, starting with the build scripts`;
}
