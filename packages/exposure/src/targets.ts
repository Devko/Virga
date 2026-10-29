import { type HostPattern, parseHost } from "./hosts.ts";
import { type PathPattern, parseAccessPath } from "./paths.ts";
import { isObject, str } from "./read.ts";

/**
 * A destination override. The API documents `behavior: "public"` only; any
 * other behavior is kept so the evaluator can return `unknown` for it.
 * developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/
 */
export interface Override {
  path: PathPattern;
  makesPublic: boolean;
}

export type Scope = "all" | "previews";

export type Target =
  | { kind: "hostname"; host: HostPattern; path: PathPattern; overrides: Override[] }
  | { kind: "worker"; script: string; scope: Scope; overrides: Override[] }
  /** Every Worker in the account: the API's `all_workers` and `all_preview_workers`. */
  | { kind: "account"; scope: Scope; overrides: Override[] }
  | { kind: "other"; raw: unknown };

// A Map, because the key is an untrusted string.
const ACCOUNT_SCOPES = new Map<unknown, Scope>([
  ["all_workers", "all"],
  ["all_preview_workers", "previews"],
]);

/** Overrides are not in the graph contract yet; read them when a target carries them. */
function parseOverrides(value: unknown): Override[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return null;
  return value.map((o) =>
    isObject(o)
      ? { path: parseAccessPath(o.path_pattern), makesPublic: o.behavior === "public" }
      : { path: parseAccessPath(undefined), makesPublic: false },
  );
}

/**
 * Turns one `Target` of an `access_app` into what the evaluator works with.
 * Anything it cannot read becomes `other`, so it ends in `unknown`, never in
 * `public`. Private destinations do not protect public entry points and are
 * dropped.
 */
export function parseTarget(target: unknown): Target | null {
  if (!isObject(target)) return { kind: "other", raw: target };
  const other: Target = { kind: "other", raw: target };
  if (target.kind === "private") return null;
  if (target.kind === "hostname") {
    const host = parseHost(target.host);
    const overrides = parseOverrides(target.overrides);
    if (!host || !overrides) return other;
    return { kind: "hostname", host, path: parseAccessPath(target.path), overrides };
  }
  if (target.kind === "worker") {
    const script = str(target.script);
    const overrides = parseOverrides(target.overrides);
    if (!script || !overrides || (target.scope !== "all" && target.scope !== "previews")) {
      return other;
    }
    return { kind: "worker", script, scope: target.scope, overrides };
  }
  if (target.kind === "other") {
    const raw = target.raw;
    const scope = isObject(raw) ? ACCOUNT_SCOPES.get(raw.type) : undefined;
    const overrides = isObject(raw) ? parseOverrides(raw.overrides) : null;
    if (scope && overrides) return { kind: "account", scope, overrides };
    return { kind: "other", raw };
  }
  return other;
}

export function parseTargets(value: unknown): Target[] {
  if (!Array.isArray(value)) return [{ kind: "other", raw: value }];
  return value.map(parseTarget).filter((t): t is Target => t !== null);
}
