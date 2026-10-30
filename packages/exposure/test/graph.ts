// Graph scenarios for the exposure evaluator. Node and edge shapes follow
// docs/architecture/graph-contract.md; the semantics the cases encode come from
// https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/
// https://developers.cloudflare.com/cloudflare-one/access-controls/policies/
// https://developers.cloudflare.com/workers/configuration/cloudflare-access/
// https://developers.cloudflare.com/workers/configuration/routing/routes/
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list/
// https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/cloudflared/subresources/configurations/methods/get/
import {
  applyBatch,
  beginScan,
  type CoverageStatus,
  type EdgeInput,
  type ExposureRow,
  type JsonObject,
  migrate,
  type NodeInput,
  type NodeType,
  nodeId,
  prepareBatch,
  recordCoverage,
  type SqlRunner,
} from "@virga/graph";
import { type NodeSqlRunner, openNodeDatabase } from "@virga/graph/node";

export const SCAN = "scan-1";

const CLASS_OF: Partial<Record<NodeType, string>> = {
  zone: "zones",
  worker_script: "workers",
  worker_version: "workers",
  worker_route: "workers",
  worker_custom_domain: "workers",
  workers_dev: "workers",
  worker_preview_url: "workers",
  pages_project: "pages",
  pages_domain: "pages",
  pages_preview: "pages",
  r2_bucket: "storage",
  r2_public_domain: "storage",
  access_app: "access",
  access_policy: "access",
  access_group: "access",
  everyone: "access",
  tunnel: "tunnels",
  tunnel_hostname: "tunnels",
};

export const CLASSES = ["zones", "workers", "pages", "storage", "access", "tunnels"] as const;

export type Selector = { kind: string; value: unknown };

export const EVERYONE: Selector = { kind: "everyone", value: null };

/** Collects nodes and edges the way the collectors emit them. */
export class Graph {
  readonly nodes: NodeInput[] = [];
  readonly edges: EdgeInput[] = [];

  node(type: NodeType, nativeId: string, name: string | null, props: JsonObject): string {
    const id = nodeId(type, nativeId);
    const i = this.nodes.findIndex((n) => nodeId(n.type, n.nativeId) === id);
    if (i >= 0) this.nodes.splice(i, 1);
    this.nodes.push({ type, nativeId, name, props });
    return id;
  }

  edge(type: EdgeInput["type"], src: string, dst: string, props: JsonObject = {}): void {
    this.edges.push({ type, src, dst, props });
  }

  zone(id: string, name: string): string {
    return this.node("zone", id, name, {
      status: "active",
      paused: false,
      type: "full",
      plan: null,
    });
  }

  script(name: string, props: JsonObject = {}): string {
    return this.node("worker_script", name, name, {
      worker_id: null,
      workers_dev: true,
      preview_urls: true,
      has_assets: null,
      compatibility_date: null,
      created_on: null,
      modified_on: null,
      ...props,
    });
  }

  version(id: string, script: string): string {
    return this.node("worker_version", id, "1", {
      script_node_id: nodeId("worker_script", script),
      number: 1,
      created_on: null,
      source: "wrangler",
      plain_text_vars: [],
      secret_names: [],
    });
  }

  route(id: string, pattern: string, script: string | null, zoneId = "zone-1"): string {
    const route = this.node("worker_route", id, pattern, { zone_id: zoneId, pattern, script });
    if (script) this.edge("ROUTES_TO", route, nodeId("worker_script", script));
    return route;
  }

  customDomain(hostname: string, script: string, zoneId = "zone-1"): string {
    const id = this.node("worker_custom_domain", hostname, hostname, {
      zone_id: zoneId,
      hostname,
      service: script,
      environment: null,
    });
    this.edge("ROUTES_TO", id, nodeId("worker_script", script));
    return id;
  }

  workersDev(host: string, script: string): string {
    const id = this.node("workers_dev", host, host, { script });
    this.edge("ROUTES_TO", id, nodeId("worker_script", script));
    return id;
  }

  /** A version URL: the host starts with the first 8 characters of the version ID. */
  previewUrl(host: string, script: string, versionId: string): string {
    const id = this.node("worker_preview_url", host, host, {
      script,
      kind: "version",
      version_id: versionId,
      alias: null,
    });
    this.edge("ROUTES_TO", id, this.version(versionId, script));
    return id;
  }

  pages(project: string, customDomains: string[] = []): { domains: string[]; preview: string } {
    const projectId = this.node("pages_project", project, project, {
      production_branch: "main",
      subdomain: `${project}.pages.dev`,
      preview_deployments: "all",
    });
    const domains = [`${project}.pages.dev`, ...customDomains].map((host) => {
      const id = this.node("pages_domain", host, host, { project, status: "active" });
      this.edge("ROUTES_TO", id, projectId, { environment: "production" });
      return id;
    });
    const wildcard = `*.${project}.pages.dev`;
    const preview = this.node("pages_preview", wildcard, wildcard, { project });
    this.edge("ROUTES_TO", preview, projectId, { environment: "preview" });
    return { domains, preview };
  }

  r2Domain(domain: string, bucket: string, kind: "r2_dev" | "custom", enabled: boolean | null) {
    const bucketId = this.node("r2_bucket", bucket, bucket, {
      location: null,
      jurisdiction: null,
      storage_class: null,
      creation_date: null,
    });
    const id = this.node("r2_public_domain", domain, domain, {
      bucket,
      kind,
      enabled,
      zone_id: kind === "custom" ? "zone-1" : null,
    });
    this.edge("ROUTES_TO", id, bucketId);
    return id;
  }

  tunnelHostname(
    hostname: string,
    path = "",
    service = "ssh://localhost:22",
    { tunnelId = "tun-1", accessRequired = false, viaFallthrough = false, truncated = false } = {},
  ): string {
    // Every hostname of one tunnel must pass the same `truncated`: the last one wins.
    const tunnel = this.node("tunnel", tunnelId, "tunnel", {
      tunnel_type: "cfd_tunnel",
      status: "healthy",
      config_src: "cloudflare",
      ingress_truncated: truncated,
    });
    const scheme = service.slice(0, service.indexOf(":"));
    const id = this.node("tunnel_hostname", `${tunnelId}:${hostname}:${path}`, hostname, {
      hostname,
      path,
      service,
      origin_scheme: scheme,
      tunnel_id: tunnelId,
      access_required: accessRequired,
      via_fallthrough: viaFallthrough,
    });
    this.edge("ROUTES_TO", id, tunnel);
    return id;
  }

  policy(
    id: string,
    decision: string,
    include: Selector[] = [EVERYONE],
    require: Selector[] = [],
  ): string {
    return this.node("access_policy", id, id, {
      decision,
      include,
      require,
      exclude: [],
      session_duration: null,
    });
  }

  group(id: string, include: Selector[]): string {
    return this.node("access_group", id, id, { include, require: [], exclude: [] });
  }

  /** An Access app with its policies in order; each policy is given as its node ID. */
  app(id: string, targets: unknown[], policies: string[] = []): string {
    const app = this.node("access_app", id, id, {
      app_type: "self_hosted",
      targets: targets as JsonObject[],
      session_duration: null,
      allowed_idps: [],
    });
    policies.forEach((policy, i) => {
      this.edge("ALLOWS", policy, app, { precedence: i + 1 });
    });
    return app;
  }
}

export type Override = { behavior: string; path_pattern: string };

export const publicPath = (path_pattern: string): Override => ({
  behavior: "public",
  path_pattern,
});

export const host = (h: string, path = "", overrides: Override[] = []) => ({
  kind: "hostname",
  host: h,
  path,
  overrides,
});
export const worker = (
  script: string,
  scope: "all" | "previews" = "all",
  overrides: Override[] = [],
) => ({ kind: "worker", script, scope, overrides });
export const allWorkers = (scope: "all" | "previews" = "all", overrides: Override[] = []) => ({
  kind: "all_workers",
  scope,
  overrides,
});
export const other = (raw: unknown) => ({ kind: "other", raw });

export interface Options {
  /** Coverage per class in the current scan; `null` writes no row. Default `complete`. */
  coverage?: Partial<Record<(typeof CLASSES)[number], CoverageStatus | null>>;
  /** Without a current scan the meta key is absent. */
  noScan?: boolean;
}

/** Loads the graph through the regular write path, one batch per resource class. */
export async function load(graph: Graph, options: Options = {}): Promise<NodeSqlRunner> {
  const db = openNodeDatabase();
  migrate(db);
  if (!options.noScan) beginScan(db, { id: SCAN, kind: "fixture", at: 1 });
  const classOf = new Map(
    graph.nodes.map((n) => [nodeId(n.type, n.nativeId), CLASS_OF[n.type] ?? "fixture"]),
  );
  for (const resourceClass of [...CLASSES, "fixture"]) {
    const nodes = graph.nodes.filter(
      (n) => classOf.get(nodeId(n.type, n.nativeId)) === resourceClass,
    );
    const edges = graph.edges.filter((e) => (classOf.get(e.src) ?? "fixture") === resourceClass);
    if (nodes.length + edges.length === 0) continue;
    applyBatch(db, await prepareBatch({ scanId: SCAN, resourceClass, nodes, edges }, 1));
  }
  if (!options.noScan) {
    for (const resourceClass of CLASSES) {
      const status = options.coverage?.[resourceClass];
      if (status === null) continue;
      recordCoverage(db, { scanId: SCAN, resourceClass, status: status ?? "complete" });
    }
  }
  return db;
}

export type Expected = [
  entry: string,
  path: string,
  decision: string,
  confidence: number,
  reasonId: string | null,
];

const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export const sorted = (rows: readonly Expected[]): Expected[] =>
  [...rows].sort((a, b) => compare(a[0], b[0]) || compare(a[1], b[1]));

/** Rows reduced to the fields a table case states, sorted by entry and path. */
export function summarize(rows: readonly ExposureRow[]): Expected[] {
  return sorted(
    rows.map(
      (r): Expected => [
        r.entryId,
        r.pathPrefix ?? "/",
        r.decision,
        r.confidence,
        r.reasonId ?? null,
      ],
    ),
  );
}

export function rowCount(db: SqlRunner, table: string): number {
  return db.query<{ n: number }>(`SELECT count(*) AS n FROM ${table}`)[0]?.n ?? 0;
}
