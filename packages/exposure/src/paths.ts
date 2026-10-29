import { LIMITS } from "@virga/graph";

/**
 * A set of request paths. `prefix` holds every path that starts with `value`
 * (`/` is every path). `segment` holds `value` and every path below
 * `value + "/"`. Any two sets of these kinds are nested or disjoint, so the
 * sets that contain a given set form a chain ordered by `specificity`.
 */
export type PathSet = { kind: "prefix"; value: string } | { kind: "segment"; value: string };

/** A pattern the evaluator cannot turn into a set. Every path it matches lies in `hull`. */
export interface OpaquePath {
  kind: "opaque";
  hull: PathSet;
}

export type PathPattern = PathSet | OpaquePath;

export const ALL_PATHS: PathSet = { kind: "prefix", value: "/" };

const prefix = (value: string): PathSet =>
  value === "" || value === "/" ? ALL_PATHS : { kind: "prefix", value };

function segment(value: string): PathSet {
  const trimmed = value.replace(/\/+$/, "");
  return trimmed === "" ? ALL_PATHS : { kind: "segment", value: trimmed };
}

const opaque = (before: string): OpaquePath => ({ kind: "opaque", hull: prefix(before) });

/** The `path_prefix` value stored for a set: `/`, `/admin` (segment) or `/api*` (prefix). */
export function pathLabel(set: PathSet): string {
  if (set.kind === "segment") return set.value;
  return set.value === "/" ? "/" : `${set.value}*`;
}

/** Whether every path in `b` is also in `a`. */
export function containsPath(a: PathSet, b: PathSet): boolean {
  if (a.kind === "prefix") return b.value.startsWith(a.value);
  if (b.kind === "segment" && b.value === a.value) return true;
  return b.value.startsWith(`${a.value}/`);
}

export const samePath = (a: PathSet, b: PathSet): boolean =>
  a.kind === b.kind && a.value === b.value;

/** Higher is narrower. Consistent with `containsPath` for sets on one chain. */
export const specificity = (set: PathSet): number =>
  set.value.length * 2 + (set.kind === "segment" ? 1 : 0);

export const hull = (pattern: PathPattern): PathSet =>
  pattern.kind === "opaque" ? pattern.hull : pattern;

function withSlash(value: string): string {
  return value.startsWith("/") ? value : `/${value}`;
}

function wildcardPath(path: string, exact: (value: string) => PathPattern): PathPattern {
  if (path.length > LIMITS.name) return opaque("");
  const value = withSlash(path);
  const star = value.indexOf("*");
  if (star < 0) return exact(value);
  if (star === value.length - 1) return prefix(value.slice(0, -1));
  return opaque(value.slice(0, star));
}

/**
 * An Access application path, as configured. Without a wildcard the path
 * covers itself and its subpaths; a trailing `*` makes it a prefix, so
 * `/alpha/*` covers `/alpha/one` but not `/alpha`, and `/*` covers the whole
 * host; a wildcard elsewhere cannot be placed. The docs do not say whether
 * `/alpha/` covers `/alpha`, so a trailing slash cannot be placed either.
 * developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/
 */
export function parseAccessPath(path: unknown): PathPattern {
  if (path === null || path === undefined || path === "") return ALL_PATHS;
  if (typeof path !== "string") return opaque("");
  return wildcardPath(path.trim(), (value) =>
    value.length > 1 && value.endsWith("/")
      ? { kind: "opaque", hull: segment(value) }
      : segment(value),
  );
}

/**
 * A destination override's `path_pattern`. Unlike application paths, an
 * override without a wildcard matches that exact path only. Read as a
 * segment, it also covers the subpaths, which errs toward `public`.
 * developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/
 */
export function parseOverridePath(path: string): PathPattern {
  return path === "" ? ALL_PATHS : wildcardPath(path.trim(), segment);
}

/**
 * The path part of a Workers route pattern. A trailing `*` matches any suffix;
 * without it the route matches that exact path, which is read as a segment.
 * Infix wildcards are not valid in routes.
 * developers.cloudflare.com/workers/configuration/routing/routes/
 */
export function parseRoutePath(path: string): PathPattern {
  return path === "" ? ALL_PATHS : wildcardPath(path, segment);
}

const REGEX_META = new Set([".", "[", "]", "(", ")", "*", "+", "?", "{", "}", "|", "^", "$"]);
const QUANTIFIERS = new Set(["*", "+", "?", "{"]);

/**
 * A tunnel ingress `path`, which cloudflared reads as an unanchored Go regular
 * expression. Only the literal start of a `^`-anchored expression narrows the
 * set; everything else is read as all paths. `approximate` tells whether the
 * set is wider than what the expression matches.
 * developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/
 */
export function parseTunnelPath(regex: string): { set: PathSet; approximate: boolean } {
  if (regex === "") return { set: ALL_PATHS, approximate: false };
  if (!regex.startsWith("^") || regex.includes("|") || regex.length > LIMITS.name) {
    return { set: ALL_PATHS, approximate: true };
  }
  let literal = "";
  for (let i = 1; i < regex.length; i++) {
    const c = regex.charAt(i);
    if (c === "\\") {
      const next = regex.charAt(i + 1);
      // Escaped punctuation is literal; \d, \w and the like are classes.
      if (next === "" || /[A-Za-z0-9]/.test(next)) break;
      literal += next;
      i++;
      continue;
    }
    if (c === "$" && i === regex.length - 1) {
      return { set: literal.startsWith("/") ? segment(literal) : ALL_PATHS, approximate: true };
    }
    if (REGEX_META.has(c)) {
      if (QUANTIFIERS.has(c)) literal = literal.slice(0, -1);
      break;
    }
    literal += c;
  }
  return { set: literal.startsWith("/") ? prefix(literal) : ALL_PATHS, approximate: true };
}
