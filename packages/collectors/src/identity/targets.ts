import { isObject, str } from "../platform/util.ts";
import { bounded, canonicalList } from "./util.ts";

// Destinations of Access applications, normalized to the Target union of the
// graph contract. Sources:
// developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list
// developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/
// developers.cloudflare.com/workers/configuration/cloudflare-access/

/** A destination override as the API returns it; `behavior` is documented as `public` only. */
export interface Override {
  behavior: string;
  path_pattern: string;
}

export type Scope = "all" | "previews";

export type Target =
  | { kind: "hostname"; host: string; path: string; overrides: Override[] }
  | { kind: "worker"; script: string; scope: Scope; overrides: Override[] }
  | { kind: "all_workers"; scope: Scope; overrides: Override[] }
  | { kind: "private"; cidr: string | null; hostname: string | null; port_range: string | null }
  | { kind: "other"; raw: unknown };

const other = (raw: unknown): Target => ({ kind: "other", raw: bounded(raw) });

const LABEL = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/;
const MAX_PATH = 1024;
// The API caps path_pattern at 512 characters.
const MAX_OVERRIDE_PATH = 512;
const MAX_BEHAVIOR = 64;
const MAX_OVERRIDES = 100;

const isHostname = (host: string): boolean =>
  host.length <= 253 && host.split(".").every((label) => label.length <= 63 && LABEL.test(label));

/**
 * `host[/path]` as used by `domain`, `self_hosted_domains` and public
 * destination URIs. A leading `*.` is the only host wildcard the contract can
 * express. The path stays as configured, wildcards and trailing slashes
 * included: evaluators apply Access path semantics to it. A port, a query or
 * a fragment is not supported by Access and becomes `other`, like any other
 * host wildcard.
 */
export function hostTarget(
  value: string,
  overrides: Override[] = [],
  raw: unknown = value,
): Target {
  const text = value.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const slash = text.indexOf("/");
  const host = (slash < 0 ? text : text.slice(0, slash)).toLowerCase();
  const path = slash < 0 ? "" : text.slice(slash);
  const bare = host.startsWith("*.") ? host.slice(2) : host;
  if (!isHostname(bare) || /[?#]/.test(path) || path.length > MAX_PATH) return other(raw);
  return { kind: "hostname", host, path, overrides };
}

/**
 * The overrides of a destination, sorted, or null if any of them cannot be
 * read: dropping one would hide a public path, so the caller emits `other`.
 */
function readOverrides(value: unknown): Override[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > MAX_OVERRIDES) return null;
  const overrides: Override[] = [];
  for (const item of value) {
    const behavior = isObject(item) ? str(item.behavior) : null;
    const pathPattern = isObject(item) ? str(item.path_pattern) : null;
    if (!behavior || behavior.length > MAX_BEHAVIOR) return null;
    if (!pathPattern || pathPattern.length > MAX_OVERRIDE_PATH) return null;
    overrides.push({ behavior, path_pattern: pathPattern });
  }
  return canonicalList(overrides);
}

// Maps, because the keys are untrusted strings.
const WORKER_SCOPES = new Map<unknown, Scope>([
  ["worker", "all"],
  ["preview_worker", "previews"],
]);
const ALL_WORKERS_SCOPES = new Map<unknown, Scope>([
  ["all_workers", "all"],
  ["all_preview_workers", "previews"],
]);

/**
 * One destination. Worker destinations name the Worker by its ID; `scripts`
 * maps IDs to script names and is null when the Worker list was not readable.
 */
function destinationTarget(dest: unknown, scripts: Map<string, string> | null): Target {
  if (!isObject(dest)) return other(dest);
  // The type is optional for public and private destinations.
  const type = str(dest.type);
  const uri = str(dest.uri);
  if (
    type === "private" ||
    (type === null && uri === null && ("cidr" in dest || "hostname" in dest))
  ) {
    return {
      kind: "private",
      cidr: str(dest.cidr),
      hostname: str(dest.hostname)?.toLowerCase() ?? null,
      port_range: str(dest.port_range),
    };
  }
  const overrides = readOverrides(dest.overrides);
  if (overrides === null) return other(dest);
  if (type === "public" || type === null) {
    return uri === null ? other(dest) : hostTarget(uri, overrides, dest);
  }
  const workerScope = WORKER_SCOPES.get(type);
  if (workerScope) {
    const id = str(dest.worker_id);
    const script = id === null ? undefined : scripts?.get(id);
    return script ? { kind: "worker", script, scope: workerScope, overrides } : other(dest);
  }
  const allScope = ALL_WORKERS_SCOPES.get(type);
  if (allScope) return { kind: "all_workers", scope: allScope, overrides };
  // via_mcp_server_portal and types added later.
  return other(dest);
}

/** True if any destination of the app is a single Worker, which needs the Worker list. */
export function needsWorkerScripts(app: Record<string, unknown>): boolean {
  const destinations = Array.isArray(app.destinations) ? app.destinations : [];
  return destinations.some((d) => isObject(d) && WORKER_SCOPES.has(d.type));
}

/**
 * Normalized targets of an app. `destinations` supersede `self_hosted_domains`,
 * which supersede `domain`. A bookmark's domain is a link, not a protected
 * destination, and SaaS apps have none.
 */
export function appTargets(
  app: Record<string, unknown>,
  scripts: Map<string, string> | null,
): Target[] {
  if (str(app.type) === "bookmark") return [];
  const destinations = Array.isArray(app.destinations) ? app.destinations : [];
  if (destinations.length > 0) {
    return canonicalList(destinations.map((d) => destinationTarget(d, scripts)));
  }
  const domains = Array.isArray(app.self_hosted_domains) ? app.self_hosted_domains : [];
  if (domains.length > 0) {
    return canonicalList(
      domains.map((d) => (typeof d === "string" && d.trim() !== "" ? hostTarget(d) : other(d))),
    );
  }
  const domain = str(app.domain);
  return domain ? [hostTarget(domain)] : [];
}
