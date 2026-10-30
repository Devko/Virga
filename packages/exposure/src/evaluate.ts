import type { Confidence, ExposureDecision, ExposureRow, SqlRunner } from "@virga/graph";
import {
  type HostPattern,
  hostSpecificity,
  hostText,
  isWildcard,
  mayShareHost,
  parseHost,
  relateHost,
} from "./hosts.ts";
import {
  ALL_PATHS,
  containsPath,
  hull,
  type PathSet,
  parseRoutePath,
  parseTunnelPath,
  pathLabel,
  samePath,
  specificity,
} from "./paths.ts";
import { appVerdict, type Verdict } from "./policy.ts";
import { type GraphInput, type GraphNode, isObject, readGraph, str } from "./read.ts";
import { type Override, parseTargets, type Target } from "./targets.ts";

interface Result extends Verdict {
  confidence: Confidence;
}

interface Entry {
  node: GraphNode;
  hosts: HostPattern[];
  path: PathSet;
  /** The path set is wider than what the entry point serves (tunnel path regex). */
  approximate: boolean;
  scripts: Set<string>;
  /** One of `scripts` has no known Worker ID. */
  unidentified: boolean;
  preview: boolean;
  /** Served by a Worker, so Worker-level Access can apply. */
  worker: boolean;
  /** A tunnel hostname whose cloudflared requires an Access token (`access_required`). */
  originAccess: boolean;
}

type Built = { entry: Entry } | { problem: string } | null;

interface App {
  node: GraphNode;
  targets: Target[];
  verdict: () => Verdict;
}

type Candidate<T extends Target = Target> = { app: App; target: T };
type HostnameTarget = Extract<Target, { kind: "hostname" }>;
type WorkerTarget = Extract<Target, { kind: "worker" | "all_workers" }>;

const WORKER_ENTRIES = new Set([
  "worker_route",
  "worker_custom_domain",
  "workers_dev",
  "worker_preview_url",
]);

const unknown = (reasonId: string | null, reason: string): Result => ({
  decision: "unknown",
  confidence: 0,
  reasonId,
  reason,
});

const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Computes exposure for every live entry point in the graph from the nodes
 * described in docs/architecture/graph-contract.md. Pure read: the caller
 * writes the result with `replaceExposure`.
 *
 * Contract: an entry point whose decision cannot be determined gets
 * `unknown`, never `public`.
 *
 * Reasons are fixed texts: names and hostnames from the scanned account never
 * enter them. `reason_id` points to the deciding app or policy instead.
 */
export function evaluateExposure(db: SqlRunner): ExposureRow[] {
  const graph = readGraph(db);
  const gap = coverageGap(graph);
  const apps: App[] = graph.apps.map((node) => {
    let cached: Verdict | undefined;
    return {
      node,
      targets: parseTargets(node.props.targets),
      verdict: () => {
        cached ??= appVerdict(node, graph);
        return cached;
      },
    };
  });
  const refs = scriptRefs(graph);

  const rows: ExposureRow[] = [];
  for (const node of graph.entries) {
    const built = buildEntry(node, graph);
    if (!built) continue;
    const results =
      "problem" in built
        ? new Map([["/", unknown(null, built.problem)]])
        : gap
          ? new Map([[pathLabel(built.entry.path), unknown(null, gap)]])
          : evaluateEntry(built.entry, apps, refs);
    for (const [pathPrefix, r] of results) {
      rows.push({
        entryId: node.id,
        pathPrefix,
        decision: r.decision,
        confidence: r.confidence,
        reasonId: r.reasonId,
        reason: r.reason,
      });
    }
  }
  return rows;
}

function coverageGap(graph: GraphInput): string | null {
  const coverage = graph.accessCoverage;
  if (!coverage) return "no current scan, so access coverage is unknown";
  if (coverage.status === "complete") return null;
  return `access coverage is ${coverage.status ?? "missing"} in the current scan`;
}

/** Worker references in targets are script names or Worker IDs. */
function scriptRefs(graph: GraphInput): Map<string, string> {
  const refs = new Map<string, string>();
  for (const s of graph.scripts.values()) if (s.workerId) refs.set(s.workerId, s.id);
  for (const s of graph.scripts.values()) refs.set(s.nativeId, s.id);
  return refs;
}

function servesWorker(entry: Entry, ref: string, refs: Map<string, string>): boolean {
  return entry.scripts.has(refs.get(ref) ?? `worker_script:${ref}`);
}

function entryScripts(node: GraphNode, graph: GraphInput): Set<string> {
  const scripts = new Set<string>();
  if (!WORKER_ENTRIES.has(node.type)) return scripts;
  for (const dst of graph.routesTo.get(node.id) ?? []) {
    if (dst.startsWith("worker_script:")) scripts.add(dst);
    const viaVersion = graph.versionScripts.get(dst);
    if (viaVersion) scripts.add(viaVersion);
  }
  if (scripts.size === 0) {
    const name = str(node.props.script) ?? str(node.props.service);
    if (name) scripts.add(`worker_script:${name}`);
  }
  return scripts;
}

/**
 * Workers route hosts: `*.zone` matches subhosts at any depth, `*zone`
 * matches the host itself, its subhosts and, inside the zone, hosts whose
 * first label ends with it. An Access app never covers the any-depth part.
 * developers.cloudflare.com/workers/configuration/routing/routes/#matching-behavior
 */
function routeHosts(host: string, zone: string | undefined): HostPattern[] | null {
  if (host.startsWith("*.")) {
    const pattern = parseHost(host, true);
    return pattern && !pattern.labels.slice(1).some((l) => l.includes("*")) ? [pattern] : null;
  }
  const base = parseHost(host.startsWith("*") ? host.slice(1) : host);
  if (!base || isWildcard(base)) return null;
  if (!host.startsWith("*")) return [base];
  const hosts: HostPattern[] = [base, { labels: ["*", ...base.labels], multiLevel: true }];
  const [first, ...rest] = base.labels;
  const parent = rest.join(".");
  if (zone && first && (parent === zone || parent.endsWith(`.${zone}`))) {
    hosts.push({ labels: [`*${first}`, ...rest], multiLevel: false });
  }
  return hosts;
}

function exactHost(value: unknown): HostPattern[] | null {
  const host = parseHost(value);
  return host && !isWildcard(host) ? [host] : null;
}

function buildEntry(node: GraphNode, graph: GraphInput): Built {
  const p = node.props;
  const scripts = entryScripts(node, graph);
  const flag = (key: "workersDev" | "previewUrls") =>
    [...scripts].some((s) => graph.scripts.get(s)?.[key] === false);
  let hosts: HostPattern[] | null;
  let path = ALL_PATHS;
  let approximate = false;
  let originAccess = false;

  switch (node.type) {
    case "worker_route": {
      const pattern = (str(p.pattern) ?? node.name ?? "").trim().replace(/^https?:\/\//i, "");
      const slash = pattern.indexOf("/");
      const host = (slash < 0 ? pattern : pattern.slice(0, slash)).toLowerCase();
      const routePath = parseRoutePath(slash < 0 ? "" : pattern.slice(slash));
      hosts = routeHosts(host, graph.zoneNames.get(str(p.zone_id) ?? ""));
      if (routePath.kind === "opaque") hosts = null;
      else path = routePath;
      break;
    }
    case "worker_custom_domain":
      hosts = exactHost(str(p.hostname) ?? node.nativeId);
      break;
    case "workers_dev":
      // A stale node of a script that has turned workers.dev off.
      if (flag("workersDev")) return null;
      hosts = exactHost(node.nativeId);
      break;
    case "worker_preview_url":
      if (flag("previewUrls")) return null;
      hosts = exactHost(node.nativeId);
      break;
    case "pages_domain":
      hosts = exactHost(node.nativeId);
      break;
    case "pages_preview": {
      // One label per preview deployment or branch alias.
      const host = parseHost(node.nativeId);
      hosts = host ? [host] : null;
      break;
    }
    case "r2_public_domain":
      if (p.enabled === false) return null;
      if (p.enabled !== true) return { problem: "R2 public domain with unknown enabled state" };
      hosts = exactHost(node.nativeId);
      break;
    case "tunnel_hostname": {
      const hostname = str(p.hostname) ?? node.name ?? "";
      const multiLevel = hostname.startsWith("*.");
      const host = parseHost(hostname, multiLevel);
      const wildcardInside = host?.labels.slice(multiLevel ? 1 : 0).some((l) => l.includes("*"));
      hosts = host && !wildcardInside ? [host] : null;
      const tunnelPath = parseTunnelPath(typeof p.path === "string" ? p.path : "");
      path = tunnelPath.set;
      approximate = tunnelPath.approximate;
      // Per node: a `via_fallthrough` node carries the token check of the rule
      // that takes its requests, and Access decides by host and path alike.
      originAccess = p.access_required === true;
      break;
    }
    default:
      return null;
  }
  if (!hosts) return { problem: "entry point host or path cannot be parsed" };
  return {
    entry: {
      node,
      hosts,
      path,
      approximate,
      scripts,
      unidentified: [...scripts].some((s) => !graph.scripts.get(s)?.workerId),
      preview: node.type === "worker_preview_url",
      worker: scripts.size > 0,
      originAccess,
    },
  };
}

const HOST_LIKE = /^[a-z0-9*_-]+(\.[a-z0-9*_-]+)+$/;

/** Hostnames mentioned anywhere in an uninterpreted target. */
function hostTokens(value: unknown, depth = 0, out: string[] = []): string[] {
  if (depth > 4 || out.length > 64) return out;
  if (typeof value === "string") {
    const text = value
      .trim()
      .toLowerCase()
      .replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
    const host = (text.split("/")[0] ?? "").replace(/:\d+$/, "");
    if (HOST_LIKE.test(host)) out.push(host);
  } else if (Array.isArray(value)) {
    for (const v of value) hostTokens(v, depth + 1, out);
  } else if (isObject(value)) {
    for (const v of Object.values(value)) hostTokens(v, depth + 1, out);
  }
  return out;
}

/**
 * Whether a target the evaluator cannot interpret might cover the entry
 * point. Only a target that clearly names another Worker, Workers in general
 * or other hosts is ruled out. A Worker ID that no script in the graph has
 * may belong to a script whose ID is not known.
 */
function couldApply(raw: unknown, entry: Entry, refs: Map<string, string>): boolean {
  if (isObject(raw)) {
    const type = str(raw.type);
    if (type === "private" || type === "via_mcp_server_portal") return false;
    if (type === "all_workers") return entry.worker;
    if (type === "all_preview_workers") return entry.preview;
    const id = str(raw.worker_id);
    const ref = id ?? str(raw.script);
    if (ref) {
      if (type === "preview_worker" && !entry.preview) return false;
      if (servesWorker(entry, ref, refs)) return true;
      return id !== null && !refs.has(id) && entry.unidentified;
    }
  }
  const hosts = hostTokens(raw);
  return hosts.length === 0 || hosts.some((h) => entry.hosts.some((k) => mayShareHost(h, k)));
}

function overrideVerdict(app: App, overrides: Override[], label: PathSet): Verdict {
  const applicable = overrides.filter((o) => containsPath(hull(o.path), label));
  if (applicable.some((o) => o.makesPublic && o.path.kind !== "opaque")) {
    return {
      decision: "public",
      reasonId: app.node.id,
      reason: "a destination override makes this path public",
    };
  }
  const verdict = app.verdict();
  if (applicable.length === 0 || verdict.decision === "public") return verdict;
  return {
    decision: "unknown",
    reasonId: app.node.id,
    reason: applicable.some((o) => !o.makesPublic)
      ? "destination override behavior not supported"
      : "a destination override path with a wildcard cannot be placed",
  };
}

/**
 * The verdict that speaks for candidates whose decisions agree. One that
 * comes with an Access token does, so an origin check cannot hide it.
 */
const agreed = (verdicts: Verdict[]): Verdict | undefined =>
  verdicts.find((v) => v.token) ?? verdicts[0];

function ranked<T>(items: T[], primary: (t: T) => number, secondary: (t: T) => number): T[] {
  const sorted = [...items].sort((a, b) => primary(b) - primary(a) || secondary(b) - secondary(a));
  const first = sorted[0];
  if (!first) return [];
  return sorted.filter((t) => primary(t) === primary(first) && secondary(t) === secondary(first));
}

/**
 * The most specific hostname app decides: an exact host beats a wildcard and
 * a longer path beats a shorter one. The docs do not say which of the two
 * wins when they point to different apps, so disagreement is `unknown`.
 */
function decideHostname(
  candidates: Candidate<HostnameTarget>[],
  key: HostPattern,
  label: PathSet,
): Result | null {
  const covering = candidates.filter(
    (c) => relateHost(c.target.host, key) === "covers" && containsPath(hull(c.target.path), label),
  );
  if (covering.length === 0) return null;
  const opaque = covering.find((c) => c.target.path.kind === "opaque");
  if (opaque) {
    return unknown(opaque.app.node.id, "an Access application path wildcard cannot be placed");
  }
  const host = (c: Candidate<HostnameTarget>) => hostSpecificity(c.target.host);
  const path = (c: Candidate<HostnameTarget>) => specificity(hull(c.target.path));
  const hostFirst = ranked(covering, host, path);
  const pathFirst = ranked(covering, path, host);
  const verdicts = [...hostFirst, ...pathFirst].map((c) =>
    overrideVerdict(c.app, c.target.overrides, label),
  );
  const winner = agreed(verdicts);
  const top = hostFirst[0];
  if (!winner || !top) return null;
  if (verdicts.some((v) => v.decision !== winner.decision)) {
    return unknown(
      top.app.node.id,
      top === pathFirst[0]
        ? "Access applications with the same destination disagree"
        : "host and path precedence select applications that disagree",
    );
  }
  if (winner.decision === "unknown") return { ...winner, confidence: 0 };
  return {
    ...winner,
    confidence: isWildcard(key) || isWildcard(top.target.host) ? 1 : 2,
    reason: `hostname application: ${winner.reason}`,
  };
}

/**
 * Worker-level Access applies where no hostname app does. A target for the
 * previews of one Worker beats one for all its traffic; a target for one
 * Worker beats one for every Worker in the account, and on preview URLs an
 * `all_preview_workers` target beats an `all_workers` one.
 * developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/
 * developers.cloudflare.com/workers/configuration/cloudflare-access/
 */
function decideWorker(
  candidates: Candidate<WorkerTarget>[],
  entry: Entry,
  label: PathSet,
): Result | null {
  const tier = (kind: WorkerTarget["kind"], scope: WorkerTarget["scope"]) =>
    candidates.filter((c) => c.target.kind === kind && c.target.scope === scope);
  const tiers = entry.preview
    ? [tier("worker", "previews"), tier("worker", "all"), tier("all_workers", "previews")]
    : [tier("worker", "all")];
  tiers.push(tier("all_workers", "all"));
  for (const group of tiers) {
    const first = group[0];
    if (!first) continue;
    const verdicts = group.map((c) => overrideVerdict(c.app, c.target.overrides, label));
    const winner = agreed(verdicts);
    if (!winner) continue;
    if (verdicts.some((v) => v.decision !== winner.decision)) {
      return unknown(first.app.node.id, "Worker-level Access applications disagree");
    }
    if (winner.decision === "unknown") return { ...winner, confidence: 0 };
    const account = first.target.kind === "all_workers";
    return {
      ...winner,
      confidence: account ? 1 : 2,
      reason: `${account ? "account" : "Worker"}-level application: ${winner.reason}`,
    };
  }
  return null;
}

/**
 * cloudflared validates the Access token of every request to a tunnel
 * hostname with `access_required` and rejects requests without one. Access
 * issues that token only when an Allow or Service Auth policy admits the
 * request; Bypass enforces nothing. Where Access alone would leave such a
 * hostname public, the policies that give a token without a login decide,
 * whichever policy named the public verdict (review R4-01): Service Auth for
 * every address keeps it `public`, and one that cannot be decided makes it
 * `unknown`. Without such a policy it is `access`, decided by the tunnel
 * hostname; the audience tags cloudflared checks are not collected, so that
 * decision has at most medium confidence. `access`, `service_auth` and
 * `unknown` stay as they are.
 * developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/origin-parameters/#access
 */
function withOriginAccess(result: Result, entryId: string): Result {
  if (result.decision !== "public") return result;
  const { token } = result;
  if (token?.decision === "public") {
    return {
      decision: "public",
      confidence: result.confidence,
      reasonId: token.reasonId,
      reason: `${token.reason}, so requests get the Access token cloudflared requires`,
    };
  }
  if (token) {
    return unknown(
      token.reasonId,
      `cloudflared requires an Access token, and a policy that may give one without a login cannot be decided: ${token.reason}`,
    );
  }
  return {
    decision: "access",
    confidence: Math.min(result.confidence, 1) as Confidence,
    reasonId: entryId,
    reason: "cloudflared requires an Access token before it forwards requests to the origin",
  };
}

const EXPOSURE_RANK: Record<ExposureDecision, number> = {
  public: 0,
  unknown: 1,
  access: 2,
  service_auth: 3,
  private: 4,
  blocked: 5,
};

/**
 * Combines the decisions for the hosts a wildcard entry point serves. A
 * public host makes the entry point public; otherwise an unknown host makes
 * it unknown.
 */
function combine(results: Result[]): Result {
  const [first] = results;
  if (!first) return unknown(null, "no hosts");
  if (results.every((r) => r.decision === first.decision)) {
    return { ...first, confidence: Math.min(...results.map((r) => r.confidence)) as Confidence };
  }
  const worst = [...results].sort(
    (a, b) => EXPOSURE_RANK[a.decision] - EXPOSURE_RANK[b.decision],
  )[0] as Result;
  if (worst.decision === "unknown") return { ...worst, confidence: 0 };
  return {
    ...worst,
    confidence: Math.min(worst.confidence, 1) as Confidence,
    reason: `${worst.reason} (on part of the hosts this entry point matches)`,
  };
}

function evaluateEntry(entry: Entry, apps: App[], refs: Map<string, string>): Map<string, Result> {
  const hostCandidates: Candidate<HostnameTarget>[] = [];
  const workerCandidates: Candidate<WorkerTarget>[] = [];
  for (const app of apps) {
    for (const target of app.targets) {
      if (target.kind === "hostname") {
        if (entry.hosts.some((k) => relateHost(target.host, k) !== "disjoint")) {
          hostCandidates.push({ app, target });
        }
      } else if (target.kind === "worker") {
        if (entry.worker && servesWorker(entry, target.script, refs)) {
          if (target.scope === "all" || entry.preview) workerCandidates.push({ app, target });
        }
      } else if (target.kind === "all_workers") {
        if (entry.worker && (target.scope === "all" || entry.preview)) {
          workerCandidates.push({ app, target });
        }
      } else if (couldApply(target.raw, entry, refs)) {
        const reason = "an Access target the evaluator cannot interpret may apply";
        return new Map([[pathLabel(entry.path), unknown(app.node.id, reason)]]);
      }
    }
  }

  // Hosts of a wildcard entry point that some app covers on its own are
  // decided separately, then combined.
  const keys = new Map(entry.hosts.map((h) => [hostText(h), h]));
  for (const { target } of hostCandidates) {
    if (entry.hosts.some((k) => relateHost(target.host, k) === "inside")) {
      keys.set(hostText(target.host), target.host);
    }
  }

  const labels = new Map<string, PathSet>([[pathLabel(entry.path), entry.path]]);
  const addLabel = (set: PathSet) => {
    if (containsPath(entry.path, set) && !samePath(entry.path, set))
      labels.set(pathLabel(set), set);
  };
  for (const { target } of hostCandidates) addLabel(hull(target.path));
  for (const { target } of [...hostCandidates, ...workerCandidates]) {
    for (const o of target.overrides) addLabel(hull(o.path));
  }

  const results = new Map<string, Result>();
  const ordered = [...labels.entries()].sort(
    ([a, x], [b, y]) => specificity(x) - specificity(y) || byText(a, b),
  );
  // An Access wildcard spans one label, so no hostname app covers a key that
  // matches any depth; the hosts below the apps' depth stay uncovered.
  const deeper = (key: HostPattern) =>
    key.multiLevel && hostCandidates.some((c) => relateHost(c.target.host, key) === "inside");
  for (const [text, label] of ordered) {
    const perHost = [...keys.values()].map((key): Result => {
      const result = decideHostname(hostCandidates, key, label) ??
        decideWorker(workerCandidates, entry, label) ?? {
          decision: "public",
          confidence: 2,
          reasonId: null,
          reason: deeper(key)
            ? "Access wildcards match one subdomain level; deeper hosts are not covered"
            : "no Access application covers this entry point",
        };
      return entry.originAccess ? withOriginAccess(result, entry.node.id) : result;
    });
    const result = combine(perHost);
    if (entry.approximate && labels.size > 1 && result.confidence > 1) result.confidence = 1;
    results.set(text, result);
  }
  return results;
}
