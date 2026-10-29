import { isObject, str } from "../platform/util.ts";
import { bounded, canonicalList } from "./util.ts";

// Destinations of Access applications, normalized to the Target union of the
// graph contract. Sources:
// developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list
// developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/
// developers.cloudflare.com/workers/configuration/cloudflare-access/

export type Target =
  | { kind: "hostname"; host: string; path: string }
  | { kind: "worker"; script: string; scope: "all" | "previews" }
  | { kind: "private"; cidr: string | null; hostname: string | null; port_range: string | null }
  | { kind: "other"; raw: unknown };

const other = (raw: unknown): Target => ({ kind: "other", raw: bounded(raw) });

const LABEL = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/;
const MAX_PATH = 1024;

const isHostname = (host: string): boolean =>
  host.length <= 253 && host.split(".").every((label) => label.length <= 63 && LABEL.test(label));

/**
 * `host[/path]` as used by `domain`, `self_hosted_domains` and public
 * destination URIs. A leading `*.` is the only host wildcard the contract can
 * express, and a trailing `/*` is the same prefix as the path without it
 * (Access covers subpaths implicitly). Any other wildcard, a port, a query or
 * a fragment cannot be placed and becomes `other`.
 */
export function hostTarget(value: string, raw: unknown = value): Target {
  const text = value.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const slash = text.indexOf("/");
  const host = (slash < 0 ? text : text.slice(0, slash)).toLowerCase();
  let path = slash < 0 ? "" : text.slice(slash);
  const bare = host.startsWith("*.") ? host.slice(2) : host;
  if (!isHostname(bare) || /[?#]/.test(path) || path.length > MAX_PATH) return other(raw);
  if (path.endsWith("/*")) path = path.slice(0, -2);
  if (path.includes("*")) return other(raw);
  path = path.replace(/\/+$/, "");
  return { kind: "hostname", host, path };
}

/** Scope of a single-Worker destination type; the account-wide types are not single Workers. */
function workerScope(type: string | null): "all" | "previews" | null {
  if (type === "worker") return "all";
  if (type === "preview_worker") return "previews";
  return null;
}

/**
 * One destination. Worker destinations name the Worker by its ID; `scripts`
 * maps IDs to script names and is null when the Worker list was not readable.
 * Destination overrides make paths public and have no place in the contract,
 * so a destination with overrides also yields an `other` target.
 */
function destinationTargets(dest: unknown, scripts: Map<string, string> | null): Target[] {
  if (!isObject(dest)) return [other(dest)];
  // The type is optional for public and private destinations.
  const type = str(dest.type);
  const uri = str(dest.uri);
  const scope = workerScope(type);
  const targets: Target[] = [];
  if (uri !== null && (type === "public" || type === null)) {
    targets.push(hostTarget(uri, dest));
  } else if (type === "private" || (type === null && ("cidr" in dest || "hostname" in dest))) {
    targets.push({
      kind: "private",
      cidr: str(dest.cidr),
      hostname: str(dest.hostname)?.toLowerCase() ?? null,
      port_range: str(dest.port_range),
    });
  } else if (scope !== null) {
    const id = str(dest.worker_id);
    const script = id === null ? undefined : scripts?.get(id);
    targets.push(script ? { kind: "worker", script, scope } : other(dest));
  } else {
    // all_workers, all_preview_workers, via_mcp_server_portal and types added later.
    return [other(dest)];
  }
  if (Array.isArray(dest.overrides) && dest.overrides.length > 0) targets.push(other(dest));
  return targets;
}

/** True if any destination of the app is a single Worker, which needs the Worker list. */
export function needsWorkerScripts(app: Record<string, unknown>): boolean {
  const destinations = Array.isArray(app.destinations) ? app.destinations : [];
  return destinations.some((d) => isObject(d) && workerScope(str(d.type)) !== null);
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
    return canonicalList(destinations.flatMap((d) => destinationTargets(d, scripts)));
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
