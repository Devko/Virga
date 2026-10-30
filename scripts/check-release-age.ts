// Usage: node scripts/check-release-age.ts
//
// Checks that every package version in pnpm-lock.yaml (R4-07), and the pnpm
// version package.json pins in packageManager and devEngines.packageManager
// (R6-04), was published to the npm registry at least 14 days ago.
// minimumReleaseAge in pnpm-workspace.yaml applies only when pnpm resolves a
// version; an install from the lockfile, as in CI, takes whatever the lockfile
// holds, and pnpm/action-setup and corepack run whatever packageManager names.
// A version the check cannot date (not from the registry, no publish time,
// registry error) fails too, and so does a locked integrity that is not the
// registry's digest for the version dated (R6-03). pnpm also installs config
// dependencies outside the lockfile, so the check reads pnpm-workspace.yaml
// strictly and refuses them (R8-01), and corepack reads the nearest
// packageManager and any .corepack.env from the directory a command runs in,
// so only the root may name the package manager (R8-02). The root .npmrc is
// read as strictly, since lockfile-dir makes pnpm install from a lockfile the
// check never dated, and no directory below the root may hold one (R9-01,
// R9-02). Needs network access to registry.npmjs.org and nothing else; CI runs
// it before anything is installed.
import { type Dirent, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

export const MIN_AGE_DAYS = 14;

/**
 * A failure the project accepts (R8-03). An exception is bound to the failure
 * it names and, for a package not from the registry, to its exact resolution;
 * it never accepts an integrity mismatch or a version the check could not
 * verify.
 */
export type Exception =
  | {
      /** name@version from the registry, or pnpm@<version> for the pnpm package.json pins. */
      package: string;
      /**
       * Younger than 14 days. The check reaches this only after the locked
       * integrity matched the registry's, so it accepts only the registry's bytes.
       */
      accepts: "too_young";
      reason: string;
    }
  | {
      /** The lockfile key of a package not resolved from the npm registry. */
      package: string;
      accepts: "not_registry";
      /**
       * Its resolution exactly as the lockfile records it: the tarball and its
       * integrity, the repository and commit, or the directory.
       */
      resolution: Readonly<Record<string, string>>;
      reason: string;
    };

/**
 * Failures the project accepts, for example a security fix that cannot wait
 * 14 days. One entry per exact version, each with a comment and a reason. The
 * check names entries it no longer needs.
 */
export const EXCEPTIONS: readonly Exception[] = [];

const REGISTRY = "https://registry.npmjs.org";
const DAY_MS = 86_400_000;

/** An input the check refuses; main prints it and exits 1. */
export class CheckError extends Error {}

export class LockfileError extends CheckError {}

export interface LockedPackage {
  /** The key in the lockfile's packages section, for example `@types/node@22.20.5`. */
  key: string;
  name: string;
  version: string;
  /** Resolved from the npm registry by integrity, so the registry knows its publish time. */
  registry: boolean;
  /** For a registry package: the lockfile's integrity, compared with the registry's digest. */
  integrity?: string;
  /** For any other package: its resolution, which an exception must name exactly (R8-03). */
  resolution?: Readonly<Record<string, string>>;
}

const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const PACKAGE_NAME = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const INTEGRITY = /^sha(?:1|256|384|512)-[A-Za-z0-9+/]+={0,2}$/;

function unquote(value: string): string {
  if (value.startsWith("'") && value.endsWith("'") && value.length >= 2) {
    return value.slice(1, -1).replaceAll("''", "'");
  }
  if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
    return JSON.parse(value) as string;
  }
  return value;
}

// The lockfile is YAML, and CI runs this check before anything is installed,
// so no YAML library is at hand. The reader accepts the subset pnpm writes and
// refuses everything else (R6-03): a line it skipped could hold an entry that
// pnpm installs.

interface Line {
  /** 1-based, for messages. */
  number: number;
  indent: number;
  /** The line without its indentation. */
  text: string;
}

const preview = (text: string) => JSON.stringify(text.length > 60 ? `${text.slice(0, 60)}…` : text);

const lockfileError = (line: number, problem: string) =>
  new LockfileError(`pnpm-lock.yaml line ${line}: ${problem}`);

function scalar(value: string, line: number): string {
  try {
    return unquote(value);
  } catch {
    throw lockfileError(line, `a quoted value the check cannot read: ${preview(value)}`);
  }
}

/** Where the quoted scalar that starts at `start` ends, or -1 if it continues on the next line. */
function quoteEnd(text: string, start: number): number {
  const quote = text[start];
  for (let i = start + 1; i < text.length; i++) {
    if (quote === '"' && text[i] === "\\") i++;
    else if (text[i] === quote) {
      if (quote === "'" && text[i + 1] === "'") i++;
      else return i;
    }
  }
  return -1;
}

/** Characters that start an anchor, alias, tag, directive, reserved token or explicit key. */
const INDICATORS = "&*!%@`?";

/**
 * Checks a line, without its indentation, against the YAML pnpm writes:
 * `key: value`, `key:` or `- item`, with every value ending on its line. A
 * block scalar (`key: |-`) is the exception; its text follows on lines indented
 * deeper than the header.
 */
function lineShape(text: string): "line" | "block" | { problem: string } {
  let i = 0;
  while (text.startsWith("- ", i)) i += 2;
  if (text.slice(i) === "-") return "line";
  const closers: string[] = [];
  let tokenStart = true;
  while (i < text.length) {
    const c = text[i] as string;
    if (c === " ") {
      if (text[i + 1] === "#") return { problem: "a comment" };
      i++;
      continue;
    }
    if (c === "\t") return { problem: "a tab" };
    if (tokenStart) {
      tokenStart = false;
      if (c === "#") return { problem: "a comment" };
      if (c === "'" || c === '"') {
        const end = quoteEnd(text, i);
        if (end < 0) return { problem: "a quoted value that continues on the next line" };
        i = end + 1;
        continue;
      }
      if (c === "{" || c === "[") {
        closers.push(c === "{" ? "}" : "]");
        tokenStart = true;
        i++;
        continue;
      }
      if (c === "|" || c === ">") {
        const header = text.slice(i);
        if (closers.length === 0 && /^[|>](?:[1-9]?[-+]?|[-+][1-9])$/.test(header)) return "block";
        return { problem: `a block scalar header pnpm does not write: ${preview(header)}` };
      }
      if (INDICATORS.includes(c)) {
        return { problem: `"${c}", which starts an anchor, alias, tag, directive or explicit key` };
      }
    }
    if (closers.length > 0) {
      if (c === ",") {
        tokenStart = true;
        i++;
        continue;
      }
      if (c === "}" || c === "]") {
        if (closers.pop() !== c) return { problem: "mismatched brackets" };
        i++;
        continue;
      }
      if (c === "{" || c === "[") return { problem: "a bracket inside a flow value" };
    }
    const next = text[i + 1];
    if (
      c === ":" &&
      (next === undefined || next === " " || (closers.length > 0 && ",[]{}".includes(next)))
    ) {
      tokenStart = true;
    }
    i++;
  }
  if (closers.length > 0) return { problem: "a flow collection that continues on the next line" };
  return "line";
}

/** A plain key as pnpm writes one: no spaces, and no YAML indicator or `<<` (merge key) first. */
const PLAIN_KEY = /^[^\s'"#&*!|>%@`{}[\],?:<-]\S*$/;

function keyText(body: string): string | undefined {
  if (/^'(?:[^']|'')*'$/.test(body)) return body.slice(1, -1).replaceAll("''", "'");
  if (/^"(?:[^"\\]|\\.)*"$/.test(body)) {
    try {
      return JSON.parse(body) as string;
    } catch {
      return undefined;
    }
  }
  return PLAIN_KEY.test(body) ? body : undefined;
}

/** A key line, `key:` or `key: {}` (an empty entry), without its indentation. */
function keyOf(line: Line): { key: string; empty: boolean } {
  const shape = lineShape(line.text);
  if (typeof shape === "object") throw lockfileError(line.number, shape.problem);
  const empty = line.text.endsWith(": {}");
  const body = empty
    ? line.text.slice(0, -4)
    : line.text.endsWith(":")
      ? line.text.slice(0, -1)
      : undefined;
  if (body === undefined) {
    throw lockfileError(
      line.number,
      "a key and its value on one line; pnpm writes the fields on the lines below the key",
    );
  }
  const key = keyText(body);
  if (key === undefined) {
    throw lockfileError(line.number, `a key pnpm does not write: ${preview(body)}`);
  }
  return { key, empty };
}

interface Entry {
  key: string;
  number: number;
  /** Written as `key: {}`. */
  empty: boolean;
  /** Its lines, all at indent 4 or more. */
  lines: Line[];
}

/**
 * The entries of a top-level section: keys at indent 2, their values nested 2
 * spaces at a time. The lines have passed lineShape; block scalar text is left out.
 */
function readEntries(section: string, lines: readonly Line[]): Entry[] {
  const entries: Entry[] = [];
  const keys = new Set<string>();
  let entry: Entry | undefined;
  let previous = 0;
  for (const line of lines) {
    if (line.indent === 2) {
      const { key, empty } = keyOf(line);
      if (keys.has(key)) throw lockfileError(line.number, `${section} has ${key} twice`);
      keys.add(key);
      entry = { key, number: line.number, empty, lines: [] };
      entries.push(entry);
      previous = 2;
      continue;
    }
    if (
      entry === undefined ||
      entry.empty ||
      line.indent < 4 ||
      line.indent % 2 === 1 ||
      line.indent > previous + 2
    ) {
      throw lockfileError(
        line.number,
        `expected a key at indent 2 or a value nested 2 spaces deeper than the line above it under ${section}:, as pnpm writes them; found indent ${line.indent}`,
      );
    }
    entry.lines.push(line);
    previous = line.indent;
  }
  return entries;
}

const FIELD = /^([A-Za-z][A-Za-z0-9]*):(?: (.+))?$/;

/** An entry's own fields, its lines at indent 4, by name. */
function fieldsOf(entry: Entry): Map<string, { value: string | undefined; number: number }> {
  const fields = new Map<string, { value: string | undefined; number: number }>();
  for (const line of entry.lines) {
    if (line.indent !== 4) continue;
    const field = FIELD.exec(line.text);
    if (field?.[1] === undefined) {
      throw lockfileError(line.number, `expected a field such as "resolution:" in ${entry.key}`);
    }
    if (fields.has(field[1]))
      throw lockfileError(line.number, `${entry.key} has ${field[1]} twice`);
    fields.set(field[1], { value: field[2], number: line.number });
  }
  return fields;
}

/** A one-line flow map of scalars, as pnpm writes a resolution: `{integrity: …, tarball: …}`. */
function flowMap(text: string, line: number): Map<string, string> | undefined {
  if (!text.startsWith("{") || !text.endsWith("}")) return undefined;
  const body = text.slice(1, -1);
  const field =
    /\s*([A-Za-z][A-Za-z0-9]*): ('(?:[^']|'')*'|"(?:[^"\\]|\\.)*"|[^\s,{}[\]'"#&*!|>%@`?][^,{}[\]]*?)\s*(?:,|$)/y;
  const fields = new Map<string, string>();
  while (field.lastIndex < body.length) {
    const match = field.exec(body);
    const [, key, value] = match ?? [];
    if (key === undefined || value === undefined || fields.has(key)) return undefined;
    if (!/^['"]/.test(value) && /:(?: |$)/.test(value)) return undefined;
    fields.set(key, scalar(value, line));
  }
  return fields;
}

function lockedPackage(key: string, resolution: Map<string, string>): LockedPackage {
  const at = key.indexOf("@", 1);
  const name = at > 0 ? key.slice(0, at) : key;
  const version = at > 0 ? key.slice(at + 1) : "";
  const integrity = resolution.get("integrity");
  const tarball = resolution.get("tarball");
  // Anything else (git, a local directory, another registry such as JSR) has
  // no npm publish time, so the check cannot date it.
  const registry =
    PACKAGE_NAME.test(name) &&
    SEMVER.test(version) &&
    integrity !== undefined &&
    INTEGRITY.test(integrity) &&
    [...resolution.keys()].every((field) => field === "integrity" || field === "tarball") &&
    (tarball === undefined ||
      tarball === `${REGISTRY}/${name}/-/${name.slice(name.indexOf("/") + 1)}-${version}.tgz`);
  if (registry) return { key, name, version, registry, integrity };
  return { key, name, version, registry, resolution: Object.fromEntries(resolution) };
}

/** pnpm's removeSuffix: a dependency path without its peer and patch suffix (its packages key). */
function packageId(depPath: string): string {
  if (!depPath.endsWith(")")) return depPath;
  let open = 1;
  for (let i = depPath.length - 2; i >= 0; i--) {
    if (depPath[i] === "(") open--;
    else if (depPath[i] === ")") open++;
    else if (open === 0) return depPath.slice(0, i + 1);
  }
  return depPath;
}

/** pnpm's refToRelative: the dependency path an importer version names; undefined for a link. */
function dependencyPath(version: string, name: string): string | undefined {
  if (version.startsWith("link:")) return undefined;
  if (version.startsWith("@")) return version;
  const at = version.indexOf("@");
  if (at === -1) return `${name}@${version}`;
  const colon = version.indexOf(":");
  const bracket = version.indexOf("(");
  if ((colon === -1 || at < colon) && (bracket === -1 || at < bracket)) return version;
  return `${name}@${version}`;
}

const DEPENDENCY_GROUPS = new Set(["dependencies", "devDependencies", "optionalDependencies"]);

interface ImporterDependency {
  importer: string;
  name: string;
  version: string;
  /** The line of its version. */
  number: number;
}

function importerDependencies(importers: readonly Entry[]): ImporterDependency[] {
  const dependencies: ImporterDependency[] = [];
  for (const importer of importers) {
    fieldsOf(importer);
    let group = false;
    let name: string | undefined;
    let nameLine = 0;
    let version: { value: string; number: number } | undefined;
    const close = () => {
      if (name === undefined) return;
      if (version === undefined) {
        throw lockfileError(
          nameLine,
          `dependency ${name} of importer ${importer.key} has no version`,
        );
      }
      dependencies.push({
        importer: importer.key,
        name,
        version: version.value,
        number: version.number,
      });
      name = undefined;
      version = undefined;
    };
    for (const line of importer.lines) {
      if (line.indent === 4) {
        close();
        const [, field = "", value] = FIELD.exec(line.text) ?? [];
        group = DEPENDENCY_GROUPS.has(field);
        if (group && value !== undefined) {
          throw lockfileError(
            line.number,
            `write the ${field} of importer ${importer.key} as a block, as pnpm does`,
          );
        }
        continue;
      }
      if (!group) continue;
      if (line.indent === 6) {
        close();
        name = keyOf(line).key;
        nameLine = line.number;
        continue;
      }
      const field = line.indent === 8 && name !== undefined ? FIELD.exec(line.text) : null;
      if (field?.[1] === "version" && field[2] !== undefined && version === undefined) {
        version = { value: scalar(field[2], line.number), number: line.number };
        continue;
      }
      if (field?.[1] === "specifier" && field[2] !== undefined) continue;
      throw lockfileError(
        line.number,
        `expected the specifier and version of a dependency of importer ${importer.key}`,
      );
    }
    close();
  }
  return dependencies;
}

const TOP_LEVEL_KEY = /^([A-Za-z][A-Za-z0-9]*):(?: (.+))?$/;
const SECTIONS = new Set(["importers", "packages", "snapshots"]);

/**
 * The entries of the packages section of a pnpm lockfile (format 9). Reads
 * only the layout pnpm writes and refuses anything else rather than skip
 * entries (R6-03). Every snapshot and every importer dependency must lead to a
 * packages entry, since pnpm installs from those.
 */
export function parseLockfile(text: string): LockedPackage[] {
  // YAML breaks lines at a lone CR too; pnpm drops a byte order mark.
  const lines = text.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/);
  const sections = new Map<string, Line[]>();
  const seen = new Set<string>();
  let format: string | undefined;
  let section: Line[] | undefined;
  let blockScalar: number | undefined;
  for (const [index, content] of lines.entries()) {
    const number = index + 1;
    if (/^[ \t]*$/.test(content)) continue;
    const indent = content.length - content.replace(/^ +/, "").length;
    // Block scalar text is free-form and ends at a line no deeper than its header.
    if (blockScalar !== undefined && indent > blockScalar) continue;
    blockScalar = undefined;
    if (seen.size === 0 && (indent > 0 || !content.startsWith("lockfileVersion:"))) {
      throw lockfileError(number, "the lockfile must start with lockfileVersion");
    }
    const top = indent === 0 ? TOP_LEVEL_KEY.exec(content) : undefined;
    if (top === null) {
      throw lockfileError(
        number,
        `expected a top-level key such as "packages:"; found ${preview(content)}`,
      );
    }
    // Every line in every section: a value continued on the next line could
    // hide from YAML a line this reader takes as an entry, or the reverse.
    const shape = lineShape(content.slice(indent));
    if (typeof shape === "object") throw lockfileError(number, shape.problem);
    if (shape === "block") blockScalar = indent;
    if (top?.[1] === undefined) {
      section?.push({ number, indent, text: content.slice(indent) });
      continue;
    }
    const [, key, value] = top;
    if (seen.has(key)) throw lockfileError(number, `${key} appears twice`);
    seen.add(key);
    if (key === "lockfileVersion") format = value === undefined ? undefined : scalar(value, number);
    section = SECTIONS.has(key) ? [] : undefined;
    if (section !== undefined) {
      if (value !== undefined) {
        throw lockfileError(
          number,
          `${key} on one line; pnpm writes its entries on the lines below`,
        );
      }
      sections.set(key, section);
    }
  }
  if (format === undefined || !/^9\.\d+$/.test(format)) {
    throw new LockfileError(`unsupported lockfileVersion ${format ?? "(missing)"}; expected 9.x`);
  }

  const packages: LockedPackage[] = [];
  for (const entry of readEntries("packages", sections.get("packages") ?? [])) {
    const resolution = fieldsOf(entry).get("resolution");
    if (resolution === undefined) {
      throw lockfileError(entry.number, `lockfile entry ${entry.key} has no resolution`);
    }
    const fields =
      resolution.value === undefined ? undefined : flowMap(resolution.value, resolution.number);
    if (fields === undefined) {
      throw lockfileError(
        resolution.number,
        `the resolution of ${entry.key} is not a one-line flow map the check can read`,
      );
    }
    packages.push(lockedPackage(entry.key, fields));
  }

  // pnpm installs what the snapshots and importers name, and merges each
  // snapshot with the packages entry of its id; without one, it would take the
  // snapshot's own fields.
  const ids = new Set(packages.map((locked) => locked.key));
  for (const entry of readEntries("snapshots", sections.get("snapshots") ?? [])) {
    fieldsOf(entry);
    if (!ids.has(packageId(entry.key))) {
      throw lockfileError(
        entry.number,
        `snapshot ${entry.key} has no entry in packages, so the check cannot date it`,
      );
    }
  }
  const importers = readEntries("importers", sections.get("importers") ?? []);
  for (const dependency of importerDependencies(importers)) {
    const path = dependencyPath(dependency.version, dependency.name);
    if (path !== undefined && !ids.has(packageId(path))) {
      throw lockfileError(
        dependency.number,
        `dependency ${dependency.name} of importer ${dependency.importer} resolves to ${path}, which has no entry in packages`,
      );
    }
  }
  return packages;
}

export class WorkspaceError extends CheckError {}

/**
 * The settings of pnpm-workspace.yaml the check accepts, with the YAML each
 * takes: a block sequence of one-line values, or a value on the key's line.
 */
const WORKSPACE_SETTINGS: ReadonlyMap<string, "list" | "value"> = new Map([
  ["packages", "list"],
  ["onlyBuiltDependencies", "list"],
  ["minimumReleaseAge", "value"],
  ["minimumReleaseAgeExclude", "list"],
]);

const workspaceError = (line: number, problem: string) =>
  new WorkspaceError(`pnpm-workspace.yaml line ${line}: ${problem}`);

/** A plain value without spaces: no indicator first. */
const PLAIN_VALUE = /^[^\s'"#&*!|>%@`{}[\],?:<-]\S*$/;

/** A value on one line: quoted, or plain without spaces and without `:` last (which makes it a key). */
function oneLineValue(text: string): string | undefined {
  if (/^'(?:[^']|'')*'$/.test(text) || /^"(?:[^"\\]|\\.)*"$/.test(text)) return keyText(text);
  return PLAIN_VALUE.test(text) && !text.endsWith(":") ? text : undefined;
}

function unknownSetting(key: string): string {
  if (key === "configDependencies") {
    return "configDependencies: pnpm installs config dependencies outside the lockfile, and runs pnpm-plugin-* ones on every command, so the check cannot date them; the project declares none";
  }
  return `${key} is not a setting the check accepts (${[...WORKSPACE_SETTINGS.keys()].join(", ")}); a setting can make pnpm read another lockfile, or install or run code the check does not date, so extend the check before adding one`;
}

/**
 * The settings in pnpm-workspace.yaml (R8-01). pnpm installs config
 * dependencies declared there outside the lockfile, and other settings make it
 * read another lockfile or a pnpmfile, so the check accepts only the settings
 * the project uses, in block layout, and refuses anything else with its line
 * number: flow collections, anchors, aliases, tags, merge keys, quoted or
 * duplicate keys and values that continue on the next line. Whole-line
 * comments are allowed.
 */
export function parseWorkspace(text: string): Map<string, string | string[]> {
  const settings = new Map<string, string | string[]>();
  /** The list of the setting above, while its items follow. */
  let list: string[] | undefined;
  const lines = text.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/);
  for (const [index, line] of lines.entries()) {
    const number = index + 1;
    const content = line.replace(/ +$/, "");
    if (content === "" || /^ *#/.test(content)) continue;
    const indent = content.length - content.replace(/^ +/, "").length;
    const shape = lineShape(content.slice(indent));
    if (typeof shape === "object") {
      throw workspaceError(
        number,
        shape.problem === "a comment"
          ? "a comment after a value; write comments on their own line"
          : shape.problem,
      );
    }
    if (shape === "block")
      throw workspaceError(number, "a block scalar; write the value on one line");
    if (indent === 0) {
      const [, key, value] = TOP_LEVEL_KEY.exec(content) ?? [];
      if (key === undefined) {
        throw workspaceError(
          number,
          `expected a setting written as "name:" or "name: value", with a plain name; found ${preview(content)}`,
        );
      }
      if (settings.has(key)) throw workspaceError(number, `${key} appears twice`);
      const kind = WORKSPACE_SETTINGS.get(key);
      if (kind === undefined) throw workspaceError(number, unknownSetting(key));
      if (kind === "list") {
        if (value !== undefined) {
          throw workspaceError(number, `write ${key} as a block sequence, one "- " item per line`);
        }
        list = [];
        settings.set(key, list);
        continue;
      }
      const scalar = value === undefined ? undefined : oneLineValue(value);
      if (scalar === undefined) throw workspaceError(number, `${key} needs a value on its line`);
      settings.set(key, scalar);
      list = undefined;
      continue;
    }
    const item =
      list !== undefined && indent === 2 && content.startsWith("- ", 2)
        ? oneLineValue(content.slice(4))
        : undefined;
    if (list === undefined || item === undefined) {
      throw workspaceError(
        number,
        `expected a "- " item with a one-line value at indent 2, under a list setting such as packages:; found ${preview(content.slice(indent))}`,
      );
    }
    list.push(item);
  }
  return settings;
}

export class NpmrcError extends CheckError {}

/** The settings of the root .npmrc the check accepts, each with the one value it accepts (R9-01). */
const NPMRC_SETTINGS: ReadonlyMap<string, string> = new Map([
  ["save-exact", "true"],
  ["engine-strict", "true"],
]);

const npmrcError = (line: number, problem: string) =>
  new NpmrcError(`.npmrc line ${line}: ${problem}`);

/** A key shaped like a setting name, which the check prints; any other key could be a credential. */
const SETTING_NAME = /^@?[a-z0-9][a-z0-9._-]{0,63}(?::[a-z0-9._-]{1,63})?$/;

const LOCKFILE_SETTINGS = new Set([
  "lockfile",
  "lockfile-dir",
  "git-branch-lockfile",
  "merge-git-branch-lockfiles",
  "merge-git-branch-lockfiles-branch-pattern",
  "shared-workspace-lockfile",
]);
const RUNTIME_SETTINGS = new Set(["use-node-version", "node-version", "node-mirror"]);
const FETCH_SETTINGS = new Set([
  "registry",
  "strict-ssl",
  "proxy",
  "https-proxy",
  "noproxy",
  "no-proxy",
]);
const CODE_SETTINGS = new Set(["pnpmfile", "global-pnpmfile", "node-options", "script-shell"]);
const CREDENTIAL_SETTINGS =
  /(?:^|:)(?:_auth|_authtoken|_password|username|email|always-auth|certfile|keyfile|tokenhelper|ca|cafile|cert|key)$/;

/**
 * Why the check refuses a key of .npmrc. Never names a value, and names the
 * key only if it is shaped like a setting name.
 */
function npmrcKeyProblem(key: string): string {
  const accepted = [...NPMRC_SETTINGS].map(([name, value]) => `${name}=${value}`).join(" and ");
  const only = `the project's .npmrc holds only ${accepted}, so extend the check before adding a setting`;
  const lower = key.toLowerCase();
  if (lower.startsWith("//") || CREDENTIAL_SETTINGS.test(lower)) {
    return `a registry credential, token helper or client certificate (the check prints neither key nor value): the repository holds no credentials, and pnpm runs a token helper as a command; ${only}`;
  }
  if (!SETTING_NAME.test(key)) {
    return `the key on this line (not printed) is not a setting the check accepts; ${only}`;
  }
  const name = key.replace(/:.*$/, "");
  if (LOCKFILE_SETTINGS.has(key)) {
    return `${key} makes pnpm install from a lockfile other than the root pnpm-lock.yaml the check dates, or without one; ${only}`;
  }
  if (RUNTIME_SETTINGS.has(name)) {
    return `${key} makes pnpm download and run a Node.js runtime the check does not date; ${only}`;
  }
  if (FETCH_SETTINGS.has(key) || key.endsWith(":registry")) {
    return `${key} changes where or how pnpm fetches packages, and the check dates versions on registry.npmjs.org; ${only}`;
  }
  if (CODE_SETTINGS.has(key)) {
    return `${key} makes pnpm run code the check does not read: a pnpmfile, a shell or Node.js options for scripts; ${only}`;
  }
  return `${key} is not a setting the check accepts; a setting can make pnpm install from another lockfile, fetch from another registry or run code the check does not date; ${only}`;
}

/**
 * The settings of the root .npmrc (R9-01). pnpm reads it as an INI file, and
 * settings such as lockfile-dir make it install from a lockfile the check
 * never dated, or download a Node.js runtime, so the check accepts only the
 * settings the project uses, each with its one value, written as key=value
 * without spaces. Anything else is refused with its line number: sections,
 * quoted values, inline comments, variables and duplicate keys. Whole-line
 * comments (# or ;) are allowed. Values are never printed.
 */
export function parseNpmrc(text: string): Map<string, string> {
  const settings = new Map<string, string>();
  // pnpm's INI reader breaks lines at any CR or LF.
  const lines = text.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/);
  for (const [index, line] of lines.entries()) {
    const number = index + 1;
    const content = line.replace(/[ \t]+$/, "");
    if (content === "" || /^[ \t]*[#;]/.test(content)) continue;
    const equals = content.indexOf("=");
    if (equals < 0) {
      throw npmrcError(
        number,
        "expected one key=value per line; a line without = sets a key to true, and a [section] line starts a section",
      );
    }
    const key = content.slice(0, equals);
    if (key === "" || /^\s|\s$/.test(key)) {
      throw npmrcError(number, "write the setting as key=value, without spaces around the key");
    }
    const accepted = NPMRC_SETTINGS.get(key);
    if (accepted === undefined) throw npmrcError(number, npmrcKeyProblem(key));
    if (settings.has(key)) throw npmrcError(number, `${key} appears twice`);
    if (content.slice(equals + 1) !== accepted) {
      throw npmrcError(
        number,
        `${key} has a value the check does not accept; it accepts ${key}=${accepted} only`,
      );
    }
    settings.set(key, accepted);
  }
  return settings;
}

export class PackageJsonError extends CheckError {}

export interface PackageManagerPin {
  /** Where package.json names the version. */
  field: "packageManager" | "devEngines.packageManager";
  version: string;
  /** The hex digest of a corepack hash (`pnpm@10.28.0+sha512.<hex>`), compared with the registry's. */
  sha512?: string;
}

const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/** An exact pnpm version, with the corepack hash after `+` if there is one. */
function pnpmPin(field: PackageManagerPin["field"], value: string): PackageManagerPin {
  const plus = value.indexOf("+");
  const version = plus < 0 ? value : value.slice(0, plus);
  if (!EXACT_VERSION.test(version)) {
    throw new PackageJsonError(
      `package.json ${field} names pnpm ${preview(version)}, not an exact version, so the check cannot date the pnpm that runs; pin an exact version such as 10.28.0`,
    );
  }
  if (plus < 0) return { field, version };
  const hash = value.slice(plus + 1);
  const sha512 = /^sha512\.([0-9a-f]{128})$/i.exec(hash)?.[1];
  if (sha512 === undefined) {
    throw new PackageJsonError(
      `package.json ${field} pins pnpm ${version} with the hash ${preview(hash)}, which the check cannot compare: the registry publishes a sha512 digest for each version, so only a 128-digit sha512 hash can be checked; drop the hash or use the one "corepack use pnpm@${version}" writes`,
    );
  }
  return { field, version, sha512: sha512.toLowerCase() };
}

/**
 * The pnpm versions package.json pins (R6-04): packageManager, which
 * pnpm/action-setup in CI and corepack follow and which therefore must name
 * an exact pnpm version, and devEngines.packageManager if present. Refuses
 * config dependencies in the pnpm field (R8-01), which pnpm installs outside
 * the lockfile.
 */
export function parsePackageManager(text: string): PackageManagerPin[] {
  let manifest: unknown;
  try {
    manifest = JSON.parse(text);
  } catch {
    throw new PackageJsonError("package.json is not valid JSON");
  }
  if (!isRecord(manifest)) throw new PackageJsonError("package.json is not a JSON object");
  const { packageManager, devEngines, pnpm } = manifest;
  if (pnpm !== undefined) {
    if (!isRecord(pnpm)) {
      throw new PackageJsonError(
        "package.json pnpm is not an object, so the check cannot tell which settings pnpm reads from it",
      );
    }
    if (Object.hasOwn(pnpm, "configDependencies")) {
      throw new PackageJsonError(
        "package.json pnpm.configDependencies: pnpm installs config dependencies outside the lockfile, and runs pnpm-plugin-* ones on every command, so the check cannot date them; the project declares none",
      );
    }
  }
  if (typeof packageManager !== "string") {
    throw new PackageJsonError(
      'package.json names no packageManager; CI (pnpm/action-setup) and corepack take the pnpm version from it, so pin an exact one such as "pnpm@10.28.0"',
    );
  }
  if (!packageManager.startsWith("pnpm@")) {
    throw new PackageJsonError(
      `package.json packageManager names ${preview(packageManager)}, not pnpm; the check dates only pnpm, which this project uses`,
    );
  }
  const pins = [pnpmPin("packageManager", packageManager.slice("pnpm@".length))];
  if (devEngines === undefined) return pins;
  if (!isRecord(devEngines)) throw new PackageJsonError("package.json devEngines is not an object");
  const declared = devEngines.packageManager;
  if (declared === undefined) return pins;
  for (const entry of Array.isArray(declared) ? declared : [declared]) {
    if (!isRecord(entry) || entry.name !== "pnpm") {
      throw new PackageJsonError(
        `package.json devEngines.packageManager has an entry that does not name pnpm: ${preview(JSON.stringify(entry) ?? "")}; the check dates only pnpm, which this project uses`,
      );
    }
    if (typeof entry.version !== "string") {
      throw new PackageJsonError(
        "package.json devEngines.packageManager gives no pnpm version; give an exact one such as 10.28.0",
      );
    }
    pins.push(pnpmPin("devEngines.packageManager", entry.version));
  }
  return pins;
}

export class CheckoutError extends CheckError {}

/** ` (ENOENT)` for a Node file system error, for messages. */
const errorCode = (cause: unknown) =>
  isRecord(cause) && typeof cause.code === "string" ? ` (${cause.code})` : "";

const ONLY_ROOT =
  "only the root package.json may name the package manager: corepack takes the nearest package.json that names one, starting from the directory a command runs in";

/** The files main reads at the root, by their exact names. */
const ROOT_FILES = new Set(["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc"]);

/**
 * A file name as a case-insensitive file system may match it (L-1): with
 * full case folding, which toLowerCase alone does not do (U+017F, long s,
 * folds to s), with compatibility forms such as fullwidth letters normalized
 * and without default-ignorable characters such as U+200B, which some file
 * systems skip. Matching more names only refuses more.
 */
const foldedName = (name: string) =>
  name
    .normalize("NFKC")
    .replace(/\p{Default_Ignorable_Code_Point}/gu, "")
    .toUpperCase()
    .toLowerCase();

/** A package.json below the root: it must not name a package manager (R8-02). */
function checkNestedManifest(path: string, shown: string): void {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (cause) {
    throw new CheckoutError(`${shown} cannot be read${errorCode(cause)}`);
  }
  let manifest: unknown;
  try {
    manifest = JSON.parse(text);
  } catch {
    throw new CheckoutError(
      `${shown} is not valid JSON, so the check cannot tell whether it names a package manager`,
    );
  }
  if (!isRecord(manifest)) {
    throw new CheckoutError(
      `${shown} is not a JSON object, so the check cannot tell whether it names a package manager`,
    );
  }
  if (Object.hasOwn(manifest, "packageManager")) {
    throw new CheckoutError(`${shown} names packageManager; ${ONLY_ROOT}`);
  }
  const { devEngines } = manifest;
  if (devEngines === undefined) return;
  if (!isRecord(devEngines)) {
    throw new CheckoutError(
      `${shown} devEngines is not an object, so the check cannot tell whether it names a package manager`,
    );
  }
  if (Object.hasOwn(devEngines, "packageManager")) {
    throw new CheckoutError(`${shown} names devEngines.packageManager; ${ONLY_ROOT}`);
  }
}

/**
 * Package-manager inputs below the root (R8-02). Corepack takes the nearest
 * package.json that names packageManager or devEngines.packageManager, and
 * loads .corepack.env files, starting from the directory a command runs in;
 * pnpm takes the nearest pnpm-workspace.yaml in the same way, and reads the
 * .npmrc of that directory too (R9-02). So only the root package.json may name
 * the package manager, only the root may hold pnpm-workspace.yaml and .npmrc,
 * and no directory may hold .corepack.env. Walks the checkout without
 * node_modules and .git, and refuses symbolic links rather than follow them,
 * since corepack and pnpm would. Names are compared as a case-insensitive file
 * system may open them (L-1), and at the root the files main reads must have
 * their exact names.
 */
export function checkCheckout(root: string): void {
  const top = resolve(root);
  const shownPath = (path: string) => relative(top, path).split(sep).join("/") || ".";
  const walk = (dir: string) => {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (cause) {
      throw new CheckoutError(`${shownPath(dir)} cannot be read${errorCode(cause)}`);
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      const path = join(dir, entry.name);
      const shown = shownPath(path);
      const name = foldedName(entry.name);
      const atRoot = dir === top;
      if (entry.isSymbolicLink()) {
        throw new CheckoutError(
          `${shown} is a symbolic link, which the check does not follow; corepack and pnpm would`,
        );
      }
      if (name === ".corepack.env") {
        throw new CheckoutError(
          `${shown}: corepack loads .corepack.env files from the directories it walks, and their variables change which pnpm it runs and where it fetches it from; the project uses none`,
        );
      }
      if (atRoot && ROOT_FILES.has(name) && entry.name !== name) {
        throw new CheckoutError(
          `${shown}: a case-insensitive file system opens this name as ${name}, which the check reads by that exact name only; rename or remove it`,
        );
      }
      if (name === "pnpm-workspace.yaml" && !atRoot) {
        throw new CheckoutError(
          `${shown}: only the root may hold pnpm-workspace.yaml; pnpm takes the nearest one, starting from the directory a command runs in, with its settings and config dependencies`,
        );
      }
      if (name === ".npmrc" && !atRoot) {
        throw new CheckoutError(
          `${shown}: only the root may hold .npmrc; pnpm also reads the .npmrc of the directory a command runs in, where use-node-version and node-mirror make it download and run a Node.js runtime and lockfile-dir makes it install from another lockfile (R9-02)`,
        );
      }
      if (entry.isDirectory()) {
        walk(path);
      } else if (name === "package.json" && !atRoot) {
        if (!entry.isFile()) throw new CheckoutError(`${shown} is not a regular file`);
        checkNestedManifest(path, shown);
      }
    }
  };
  walk(top);
}

export interface CheckOptions {
  /** package.json's text, whose pnpm versions are dated too; main always passes it. */
  packageJson?: string;
  fetch?: typeof fetch;
  now?: Date;
  minAgeDays?: number;
  exceptions?: readonly Exception[];
  /** Registry requests in flight at once. */
  concurrency?: number;
  /** Per request, including reading the body. */
  timeoutMs?: number;
  /** Tries per package name; network errors, timeouts, 408, 429 and 5xx are retried. */
  attempts?: number;
  retryDelayMs?: number;
}

export interface Failure {
  package: string;
  /**
   * `mismatch`: the integrity is not the registry's, or not of the strongest
   * algorithm the registry publishes. No exception accepts a mismatch or
   * `unverified` (R8-03).
   */
  reason: "too_young" | "not_registry" | "unverified" | "mismatch";
  detail: string;
}

export interface CheckResult {
  /** Every locked package version, from the registry or not, and every pnpm version pinned. */
  checked: number;
  /** The pnpm versions package.json pins, among those checked. */
  packageManager: PackageManagerPin[];
  failures: Failure[];
  /** Failures the exception list accepts. */
  excepted: { package: string; detail: string }[];
  /** Exceptions that match no problem: the version is gone or old enough. */
  unusedExceptions: string[];
}

type RegistryDocument =
  | { times: Record<string, unknown>; dists: Map<string, unknown> }
  | { error: string };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function requestError(error: unknown): string {
  if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) {
    return "registry request timed out";
  }
  const message = error instanceof Error ? error.message : String(error);
  const cause = error instanceof Error && isRecord(error.cause) ? error.cause.code : undefined;
  return `registry request failed: ${message.slice(0, 200)}${typeof cause === "string" ? ` (${cause})` : ""}`;
}

/** Publish times, and the `dist` of each version in `versions`, from the full registry document. */
async function fetchDocument(
  name: string,
  versions: ReadonlySet<string>,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  attempts: number,
  retryDelayMs: number,
): Promise<RegistryDocument> {
  // Only the full document has `time`; the abbreviated install document does not.
  const url = `${REGISTRY}/${name.replace("/", "%2F")}`;
  let error = "registry request failed";
  for (let attempt = 1; attempt <= attempts; attempt++) {
    if (attempt > 1 && retryDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs * (attempt - 1)));
    }
    let response: Response;
    try {
      response = await fetchImpl(url, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (cause) {
      error = requestError(cause);
      continue;
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      if (response.status === 404) return { error: "not found in the registry" };
      error = `registry responded ${response.status}`;
      if (response.status === 408 || response.status === 429 || response.status >= 500) continue;
      return { error };
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch (cause) {
      if (cause instanceof SyntaxError) return { error: "the registry response is not JSON" };
      error = requestError(cause);
      continue;
    }
    if (!isRecord(body) || !isRecord(body.time)) {
      return { error: "the registry document has no publish times" };
    }
    const manifests = isRecord(body.versions) ? body.versions : {};
    const dists = new Map<string, unknown>();
    for (const version of versions) {
      const manifest = Object.hasOwn(manifests, version) ? manifests[version] : undefined;
      if (isRecord(manifest)) dists.set(version, manifest.dist);
    }
    return { times: body.time, dists };
  }
  return { error };
}

interface Digest {
  algorithm: string;
  hex: string;
}

/** A subresource integrity hash as pnpm records it: `sha512-<base64>`. */
function sriDigest(value: string): Digest | undefined {
  const [, algorithm, base64] =
    /^(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$/.exec(value) ?? [];
  if (algorithm === undefined || base64 === undefined) return undefined;
  return { algorithm, hex: Buffer.from(base64, "base64").toString("hex") };
}

/** The digests the registry publishes for a version: dist.integrity and the sha1 dist.shasum. */
function publishedDigests(dist: unknown): Digest[] {
  if (!isRecord(dist)) return [];
  const digests: Digest[] = [];
  if (typeof dist.integrity === "string") {
    for (const part of dist.integrity.split(/\s+/)) {
      const digest = sriDigest(part);
      if (digest) digests.push(digest);
    }
  }
  if (typeof dist.shasum === "string" && /^[0-9a-f]{40}$/i.test(dist.shasum)) {
    digests.push({ algorithm: "sha1", hex: dist.shasum.toLowerCase() });
  }
  return digests;
}

/** Digest algorithms, weakest first. */
const ALGORITHMS = ["sha1", "sha256", "sha384", "sha512"];

/**
 * Whether `digest` names the bytes the registry publishes for the version
 * checked. pnpm installs whatever matches the lockfile's integrity, from
 * whichever registry or tarball URL it ends up using (.npmrc, a version field
 * in the entry), so only this ties the installed bytes to the publish time.
 * pnpm verifies only the algorithm the lockfile names, so that must be the
 * strongest one the registry publishes for the version: a sha1 that equals
 * dist.shasum fails when dist.integrity has sha512.
 */
function digestProblem(
  digest: Digest,
  dist: unknown,
  what: string,
): Omit<Failure, "package"> | undefined {
  const all = publishedDigests(dist);
  const published = all.filter((d) => d.algorithm === digest.algorithm);
  if (published.length === 0) {
    return {
      reason: "unverified",
      detail: `the registry publishes no ${digest.algorithm} digest for this version to compare`,
    };
  }
  if (!published.some((d) => d.hex === digest.hex)) {
    return {
      reason: "mismatch",
      detail: `${what} is not the ${digest.algorithm} digest the registry publishes for this version, so the bytes installed would not be the version checked`,
    };
  }
  const strongest = all.reduce(
    (best, d) => (ALGORITHMS.indexOf(d.algorithm) > ALGORITHMS.indexOf(best) ? d.algorithm : best),
    digest.algorithm,
  );
  if (strongest === digest.algorithm) return undefined;
  return {
    reason: "mismatch",
    detail: `${what} is ${digest.algorithm}, but the registry publishes a ${strongest} digest for this version; pnpm verifies only the algorithm the lockfile names, so lock the ${strongest} integrity`,
  };
}

async function forEachLimited<T>(
  items: readonly T[],
  limit: number,
  task: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const worker = async () => {
    for (let index = next++; index < items.length; index = next++) await task(items[index] as T);
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}

function ageProblem(
  published: unknown,
  now: number,
  minAgeMs: number,
): Omit<Failure, "package"> | undefined {
  const time =
    typeof published === "string" && ISO_TIME.test(published) ? new Date(published) : undefined;
  if (time === undefined || Number.isNaN(time.getTime())) {
    return {
      reason: "unverified",
      detail: "the registry has no valid publish time for this version",
    };
  }
  const age = now - time.getTime();
  if (age >= minAgeMs) return undefined;
  const when = age < 0 ? "after the time of the check" : `${(age / DAY_MS).toFixed(1)} days ago`;
  return { reason: "too_young", detail: `published ${time.toISOString()}, ${when}` };
}

/** Why a registry version fails: no publish time, a digest that is not the registry's, or its age. */
function versionProblem(
  document: RegistryDocument | undefined,
  version: string,
  digest: Digest | undefined,
  what: string,
  now: number,
  minAgeMs: number,
): Omit<Failure, "package"> | undefined {
  if (document === undefined || "error" in document) {
    return { reason: "unverified", detail: document?.error ?? "registry request failed" };
  }
  const age = ageProblem(document.times[version], now, minAgeMs);
  if (age?.reason === "unverified" || digest === undefined) return age;
  return digestProblem(digest, document.dists.get(version), what) ?? age;
}

const byPackage = (a: { package: string }, b: { package: string }) =>
  a.package < b.package ? -1 : a.package > b.package ? 1 : 0;

export class ExceptionError extends CheckError {}

const EXCEPTION_KEY = /^(@[^@/]+\/)?[^@/]+@\S+$/;

/** Why the check cannot apply an exception, or undefined (R8-03). */
function exceptionProblem(exception: Record<string, unknown>): string | undefined {
  const { package: key, accepts, resolution, reason } = exception;
  if (typeof key !== "string" || !EXCEPTION_KEY.test(key)) {
    return "does not name an exact lockfile key (name@version) or pnpm@<version>";
  }
  if (accepts === "too_young") {
    if (Object.hasOwn(exception, "resolution")) {
      return "accepts too_young, which applies to the registry's version only, and names a resolution; an exception for a package not from the registry accepts not_registry";
    }
  } else if (accepts === "not_registry") {
    if (!isRecord(resolution)) {
      return "names no resolution; an exception for a package not from the registry names its resolution exactly as the lockfile records it";
    }
    if (Object.values(resolution).some((value) => typeof value !== "string")) {
      return "names a resolution with a value that is not a string";
    }
    if (!["tarball", "commit", "directory"].some((field) => Object.hasOwn(resolution, field))) {
      return "names no tarball, commit or directory in its resolution";
    }
    if (Object.hasOwn(resolution, "tarball") && !Object.hasOwn(resolution, "integrity")) {
      return "names a tarball without its integrity, so it would accept whatever that URL serves";
    }
  } else {
    return 'must accept "too_young" or "not_registry"; no exception accepts an integrity mismatch or a version the check could not verify';
  }
  if (typeof reason !== "string" || reason.trim() === "") return "gives no reason";
  return undefined;
}

function checkExceptions(exceptions: readonly Exception[]): void {
  for (const exception of exceptions) {
    const fields: Record<string, unknown> = isRecord(exception) ? exception : {};
    const problem = exceptionProblem(fields);
    if (problem === undefined) continue;
    const key = fields.package;
    const shown =
      typeof key === "string" && EXCEPTION_KEY.test(key) ? key : preview(String(key ?? ""));
    throw new ExceptionError(`EXCEPTIONS: the exception for ${shown} ${problem}`);
  }
}

function sameResolution(
  a: Readonly<Record<string, string>>,
  b: Readonly<Record<string, string>>,
): boolean {
  const keys = Object.keys(a);
  return (
    keys.length === Object.keys(b).length &&
    keys.every((key) => Object.hasOwn(b, key) && a[key] === b[key])
  );
}

/**
 * Whether `exception` accepts `problem` (R8-03): the same package and the
 * failure it names, and for a package not from the registry the resolution
 * locked (`resolution`) exactly. An integrity mismatch or a version the check
 * could not verify is never accepted.
 */
function excepts(
  exception: Exception,
  problem: Failure,
  resolution: Readonly<Record<string, string>> | undefined,
): boolean {
  if (problem.reason === "mismatch" || problem.reason === "unverified") return false;
  if (exception.package !== problem.package || exception.accepts !== problem.reason) return false;
  if (exception.accepts === "too_young") return true;
  return resolution !== undefined && sameResolution(exception.resolution, resolution);
}

export async function checkReleaseAge(
  lockfile: string,
  options: CheckOptions = {},
): Promise<CheckResult> {
  const now = (options.now ?? new Date()).getTime();
  const minAgeMs = (options.minAgeDays ?? MIN_AGE_DAYS) * DAY_MS;
  const exceptions = options.exceptions ?? EXCEPTIONS;
  const fetchImpl = options.fetch ?? fetch;
  const concurrency = Math.max(1, Math.floor(options.concurrency ?? 8));
  const timeoutMs = options.timeoutMs ?? 30_000;
  const attempts = Math.max(1, Math.floor(options.attempts ?? 3));
  const retryDelayMs = options.retryDelayMs ?? 1_000;

  checkExceptions(exceptions);
  const packages = parseLockfile(lockfile);
  const pins = options.packageJson === undefined ? [] : parsePackageManager(options.packageJson);
  const wanted = new Map<string, Set<string>>();
  const want = (name: string, version: string) =>
    wanted.set(name, (wanted.get(name) ?? new Set<string>()).add(version));
  for (const locked of packages) if (locked.registry) want(locked.name, locked.version);
  for (const pin of pins) want("pnpm", pin.version);
  const documents = new Map<string, RegistryDocument>();
  await forEachLimited([...wanted], concurrency, async ([name, versions]) => {
    documents.set(
      name,
      await fetchDocument(name, versions, fetchImpl, timeoutMs, attempts, retryDelayMs),
    );
  });

  const problems: Failure[] = [];
  for (const locked of packages) {
    if (!locked.registry) {
      problems.push({
        package: locked.key,
        reason: "not_registry",
        detail: "not resolved from the npm registry, so its release age is unknown",
      });
      continue;
    }
    const digest = sriDigest(locked.integrity ?? "");
    const problem =
      digest === undefined
        ? { reason: "unverified" as const, detail: "the lockfile's integrity cannot be read" }
        : versionProblem(
            documents.get(locked.name),
            locked.version,
            digest,
            "the lockfile's integrity",
            now,
            minAgeMs,
          );
    if (problem) problems.push({ package: locked.key, ...problem });
  }
  for (const pin of pins) {
    // Without a hash, corepack and pnpm/action-setup fetch the version from
    // the registry, so its publish time is what counts.
    const digest = pin.sha512 === undefined ? undefined : { algorithm: "sha512", hex: pin.sha512 };
    const what = `the hash in ${pin.field}`;
    const problem = versionProblem(documents.get("pnpm"), pin.version, digest, what, now, minAgeMs);
    if (problem) {
      problems.push({
        package: `pnpm@${pin.version}`,
        reason: problem.reason,
        detail: `${pin.field} in package.json: ${problem.detail}`,
      });
    }
  }

  const resolutions = new Map(packages.map((locked) => [locked.key, locked.resolution]));
  const isExcepted = (problem: Failure) =>
    exceptions.some((exception) => excepts(exception, problem, resolutions.get(problem.package)));
  const failures = problems.filter((problem) => !isExcepted(problem)).sort(byPackage);
  const excepted = problems
    .filter(isExcepted)
    .map((problem) => ({ package: problem.package, detail: problem.detail }))
    .sort(byPackage);
  const used = new Set(problems.map((problem) => problem.package));
  const unusedExceptions = exceptions
    .map((exception) => exception.package)
    .filter((key) => !used.has(key))
    .sort();
  return {
    checked: packages.length + pins.length,
    packageManager: pins,
    failures,
    excepted,
    unusedExceptions,
  };
}

export interface MainOptions extends CheckOptions {
  /** The checkout to check; by default the repository root. */
  root?: string;
  /** The lockfile's text; by default pnpm-lock.yaml under root. */
  lockfile?: string;
  /** By default package.json under root. */
  packageJson?: string;
  log?: (line: string) => void;
  error?: (line: string) => void;
}

const REPOSITORY = fileURLToPath(new URL("..", import.meta.url));

function readText(root: string, name: string): string {
  try {
    return readFileSync(join(root, name), "utf8");
  } catch (cause) {
    throw new CheckError(`${name} cannot be read${errorCode(cause)}`);
  }
}

/** Like readText, but undefined if the file does not exist. */
function readOptional(root: string, name: string): string | undefined {
  try {
    return readFileSync(join(root, name), "utf8");
  } catch (cause) {
    if (isRecord(cause) && cause.code === "ENOENT") return undefined;
    throw new CheckError(`${name} cannot be read${errorCode(cause)}`);
  }
}

const LABELS: Record<Failure["reason"], string> = {
  too_young: "too young",
  not_registry: "not checked",
  unverified: "not verified",
  mismatch: "integrity mismatch",
};

export async function main(options: MainOptions = {}): Promise<number> {
  const log = options.log ?? console.log;
  const error = options.error ?? console.error;
  const now = options.now ?? new Date();
  const minAgeDays = options.minAgeDays ?? MIN_AGE_DAYS;
  const root = options.root ?? REPOSITORY;

  let result: CheckResult;
  try {
    const lockfile = options.lockfile ?? readText(root, "pnpm-lock.yaml");
    const packageJson = options.packageJson ?? readText(root, "package.json");
    // R8-01: config dependencies and settings that make pnpm read another
    // lockfile or a pnpmfile are refused before anything is fetched.
    parseWorkspace(readText(root, "pnpm-workspace.yaml"));
    // R8-02, R9-02: corepack and pnpm read these from the directory a command
    // runs in. The walk also refuses a root .npmrc that is a symbolic link.
    checkCheckout(root);
    // R9-01: settings such as lockfile-dir make pnpm install from a lockfile
    // the check never dated.
    const npmrc = readOptional(root, ".npmrc");
    if (npmrc !== undefined) parseNpmrc(npmrc);
    result = await checkReleaseAge(lockfile, { ...options, packageJson, now, minAgeDays });
  } catch (cause) {
    if (!(cause instanceof CheckError)) throw cause;
    error(`error: ${cause.message}`);
    return 1;
  }
  for (const entry of result.excepted) log(`excepted: ${entry.package} (${entry.detail})`);
  for (const key of result.unusedExceptions) {
    log(`note: the exception for ${key} is no longer needed; remove it`);
  }
  for (const failure of result.failures) {
    error(`${LABELS[failure.reason]}: ${failure.package} (${failure.detail})`);
  }
  if (result.failures.length > 0) {
    error(
      `error: ${result.failures.length} of ${result.checked} package versions fail the ${minAgeDays}-day release age check; re-resolve them or add a commented exception in scripts/check-release-age.ts`,
    );
    return 1;
  }
  const pinned = new Map<string, string[]>();
  for (const pin of result.packageManager) {
    pinned.set(pin.version, [...(pinned.get(pin.version) ?? []), pin.field]);
  }
  const locked = result.checked - result.packageManager.length;
  const pnpm = [...pinned].map(
    ([version, fields]) => ` and pnpm ${version} (${fields.join(", ")})`,
  );
  log(
    `ok: all ${locked} locked package versions${pnpm.join("")} were published at least ${minAgeDays} days before ${now.toISOString()}`,
  );
  return 0;
}

const USAGE = "usage: node scripts/check-release-age.ts";

async function cli(): Promise<number> {
  try {
    if (parseArgs({ options: { help: { type: "boolean" } } }).values.help) {
      console.log(USAGE);
      return 0;
    }
  } catch {
    console.error(USAGE);
    return 2;
  }
  try {
    return await main();
  } catch (cause) {
    console.error(`error: ${cause instanceof Error ? (cause.stack ?? cause.message) : cause}`);
    return 1;
  }
}

if (import.meta.main) process.exitCode = await cli();
