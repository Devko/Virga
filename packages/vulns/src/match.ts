import type { NpmAffected, OsvAdvisory, OsvEvent, OsvRange } from "./osv.ts";
import { compareSemver, parseSemver, type SemVer } from "./semver.ts";

/** Whether a package version is affected. `unknown` is never read as not affected. */
export type Decision = "affected" | "not_affected" | "unknown";

/** `introduced: "0"` sorts before every version; `limit: "*"` is infinity. */
type Point = SemVer | "zero" | "infinity";

function pointOf(event: OsvEvent): Point | null {
  if (event.kind === "introduced" && event.version === "0") return "zero";
  if (event.kind === "limit" && event.version === "*") return "infinity";
  return parseSemver(event.version);
}

function comparePoints(a: Point, b: Point): number {
  if (a === b) return 0;
  if (a === "zero" || b === "infinity") return -1;
  if (a === "infinity" || b === "zero") return 1;
  return compareSemver(a, b);
}

/** At equal versions an `introduced` comes first, so `introduced: X, fixed: X` is empty. */
const KIND_ORDER: Record<OsvEvent["kind"], number> = {
  introduced: 0,
  fixed: 1,
  last_affected: 1,
  limit: 2,
};

/**
 * Evaluates one OSV range for an npm version, following the schema's
 * pseudocode: the version must be below one `limit` when there are limits,
 * then the events are walked in version order (`introduced` at or below the
 * version starts an affected span, `fixed` at or below it or `last_affected`
 * below it ends one). `SEMVER` and `ECOSYSTEM` ranges are evaluated alike,
 * because npm versions are SemVer and npm orders them by SemVer precedence.
 * A prerelease is affected when it falls inside a span by precedence: npm's
 * rule that ranges skip prereleases does not apply to advisories. Any event
 * version that does not parse, and any `GIT` range, gives `unknown`.
 */
export function evaluateRange(range: OsvRange, version: SemVer): Decision {
  if (range.type === "GIT") return "unknown";
  const events: { kind: OsvEvent["kind"]; at: Point }[] = [];
  for (const event of range.events) {
    const at = pointOf(event);
    if (at === null) return "unknown";
    events.push({ kind: event.kind, at });
  }
  const limits = events.filter((e) => e.kind === "limit");
  if (limits.length > 0 && !limits.some((l) => comparePoints(version, l.at) < 0)) {
    return "not_affected";
  }
  const walk = events
    .filter((e) => e.kind !== "limit")
    .sort((a, b) => comparePoints(a.at, b.at) || KIND_ORDER[a.kind] - KIND_ORDER[b.kind]);
  let affected = false;
  for (const { kind, at } of walk) {
    const order = comparePoints(version, at);
    if (kind === "introduced" && order >= 0) affected = true;
    else if (kind === "fixed" && order >= 0) affected = false;
    else if (kind === "last_affected" && order > 0) affected = false;
  }
  return affected ? "affected" : "not_affected";
}

/** Parsed `versions` lists, kept per entry: a list can hold tens of thousands of versions. */
const parsedLists = new WeakMap<NpmAffected, (SemVer | null)[]>();

function parsedVersions(entry: NpmAffected): (SemVer | null)[] {
  let list = parsedLists.get(entry);
  if (!list) {
    list = entry.versions.map(parseSemver);
    parsedLists.set(entry, list);
  }
  return list;
}

/**
 * One npm entry: affected if the version is in `versions` (SemVer equality,
 * build metadata ignored) or in any range. An entry with neither ranges nor
 * versions, a listed version that does not parse or a range that cannot be
 * evaluated make it `unknown` unless something else decides `affected`.
 */
function evaluateEntry(entry: NpmAffected, version: SemVer): Decision {
  if (entry.ranges.length === 0 && entry.versions.length === 0) return "unknown";
  let unknown = false;
  if (entry.versions.includes(version.text)) return "affected";
  for (const listed of parsedVersions(entry)) {
    if (listed === null) unknown = true;
    else if (compareSemver(listed, version) === 0) return "affected";
  }
  for (const range of entry.ranges) {
    const decision = evaluateRange(range, version);
    if (decision === "affected") return "affected";
    if (decision === "unknown") unknown = true;
  }
  return unknown ? "unknown" : "not_affected";
}

export interface AdvisoryMatch {
  decision: Decision;
  /** The lowest `fixed` version above the installed one in the entries that matched. */
  fixedIn: string | null;
  /** The entries that decided `affected`; their severity applies. */
  entries: NpmAffected[];
}

function lowestFixed(entries: readonly NpmAffected[], version: SemVer): string | null {
  let best: SemVer | null = null;
  for (const entry of entries) {
    for (const range of entry.ranges) {
      if (range.type === "GIT") continue;
      for (const event of range.events) {
        if (event.kind !== "fixed") continue;
        const fixed = parseSemver(event.version);
        if (fixed && compareSemver(fixed, version) > 0) {
          if (best === null || compareSemver(fixed, best) < 0) best = fixed;
        }
      }
    }
  }
  return best?.text ?? null;
}

/**
 * Matches an advisory against an npm package. Entries apply when their name
 * equals the package name exactly, or is the wildcard `*`. `affected` wins
 * over `unknown`, and `unknown` over `not_affected`.
 */
export function matchAdvisory(advisory: OsvAdvisory, name: string, version: SemVer): AdvisoryMatch {
  const entries: NpmAffected[] = [];
  let unknown = false;
  for (const entry of advisory.affected) {
    if (entry.name !== name && entry.name !== "*") continue;
    const decision = evaluateEntry(entry, version);
    if (decision === "affected") entries.push(entry);
    else if (decision === "unknown") unknown = true;
  }
  if (entries.length > 0) {
    return { decision: "affected", fixedIn: lowestFixed(entries, version), entries };
  }
  return { decision: unknown ? "unknown" : "not_affected", fixedIn: null, entries: [] };
}
