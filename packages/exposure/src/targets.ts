import { type HostPattern, parseHost } from "./hosts.ts";
import { type PathPattern, parseAccessPath, parseOverridePath } from "./paths.ts";
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
  | { kind: "all_workers"; scope: Scope; overrides: Override[] }
  | { kind: "other"; raw: unknown };

const isScope = (value: unknown): value is Scope => value === "all" || value === "previews";

/** The `{ behavior, path_pattern }[]` of a target, or null if it is not one. */
function parseOverrides(value: unknown): Override[] | null {
  if (!Array.isArray(value)) return null;
  const overrides: Override[] = [];
  for (const o of value) {
    const pattern = isObject(o) ? str(o.path_pattern) : null;
    if (!isObject(o) || !pattern || typeof o.behavior !== "string") return null;
    overrides.push({ path: parseOverridePath(pattern), makesPublic: o.behavior === "public" });
  }
  return overrides;
}

/**
 * Turns one `Target` of an `access_app` into what the evaluator works with.
 * Anything that does not have the contract's shape becomes `other`, so it
 * ends in `unknown`, never in `public`. Private destinations do not protect
 * public entry points and are dropped.
 */
export function parseTarget(target: unknown): Target | null {
  if (!isObject(target)) return { kind: "other", raw: target };
  const other: Target = { kind: "other", raw: target };
  if (target.kind === "private") return null;
  if (target.kind === "other") return { kind: "other", raw: target.raw };
  const overrides = parseOverrides(target.overrides);
  if (!overrides) return other;
  if (target.kind === "hostname") {
    const host = parseHost(target.host);
    if (!host || typeof target.path !== "string") return other;
    return { kind: "hostname", host, path: parseAccessPath(target.path), overrides };
  }
  if (target.kind === "worker") {
    const script = str(target.script);
    if (!script || !isScope(target.scope)) return other;
    return { kind: "worker", script, scope: target.scope, overrides };
  }
  if (target.kind === "all_workers") {
    if (!isScope(target.scope)) return other;
    return { kind: "all_workers", scope: target.scope, overrides };
  }
  return other;
}

export function parseTargets(value: unknown): Target[] {
  if (!Array.isArray(value)) return [{ kind: "other", raw: value }];
  return value.map(parseTarget).filter((t): t is Target => t !== null);
}
