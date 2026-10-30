import { nodeId } from "@virga/graph";
import type { Collector, CollectorContext } from "../types.ts";
import { bindingTarget, type StoreLookup, storeLookup } from "./bindings.ts";
import { listZoneIds } from "./lists.ts";
import { inspectValue, type ValueVerdict } from "./secrets.ts";
import {
  bool,
  chunk,
  GraphBuilder,
  hostOf,
  isObject,
  nonEmpty,
  num,
  sortedUnique,
  str,
  unlessGone,
} from "./util.ts";

/** developers.cloudflare.com/api/resources/workers/subresources/beta/subresources/workers/methods/list */
interface CfWorker {
  id?: string;
  name?: string;
  created_on?: string;
  updated_on?: string;
  subdomain?: {
    enabled?: boolean;
    previews_enabled?: boolean;
    url?: string;
    preview_url_suffix?: string;
  };
  references?: { domains?: { hostname?: string; zone_id?: string }[] };
}

/** developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/subdomain/methods/get */
interface CfScriptSubdomain {
  enabled?: boolean;
  previews_enabled?: boolean;
}

/** developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/list */
interface CfDeployments {
  deployments?: { versions?: { version_id?: string; percentage?: number }[] }[];
}

interface CfVersionMetadata {
  created_on?: string;
  source?: string;
  hasPreview?: boolean;
}

/** developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/list */
interface CfVersionList {
  items?: { id?: string; metadata?: CfVersionMetadata }[];
}

/** developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/get */
interface CfVersion {
  number?: number;
  metadata?: CfVersionMetadata;
  resources?: { bindings?: unknown; script_runtime?: { compatibility_date?: string } };
}

/** developers.cloudflare.com/api/resources/workers/subresources/routes/methods/list */
interface CfRoute {
  id?: string;
  pattern?: string;
  script?: string;
}

export type WorkersUnit = { kind: "script"; name: string } | { kind: "zone"; id: string };

const SCRIPTS_PER_CHUNK = 20;
const ZONES_PER_CHUNK = 25;
const WORKERS_PER_PAGE = 100;
/**
 * Besides the deployed versions, version URLs are collected for this many of
 * the most recent versions: phase 1 does not list the full version history.
 */
export const PREVIEW_WINDOW = 5;

/**
 * Worker scripts, their deployed versions with bindings, and the entry points
 * that reach them: routes (per zone), Custom Domains, workers.dev and version
 * URLs. Script chunks and zone chunks are planned separately.
 *
 * Scripts come from the Workers API (beta) listing, which accepts Workers
 * Metadata Read-Only and carries the Worker ID, the workers.dev and preview
 * settings with their hostnames, and the Custom Domains.
 */
export const workersCollector: Collector<WorkersUnit> = {
  resourceClass: "workers",
  after: ["storage"],
  permissions: ["Workers Metadata Read-Only", "Workers Routes Read", "Zone Read", "Queues Read"],

  async plan(ctx) {
    const names = sortedUnique((await listWorkers(ctx)).map((w) => str(w.name)));
    const zones = await listZoneIds(ctx);
    return nonEmpty([
      ...chunk(
        names.map((name): WorkersUnit => ({ kind: "script", name })),
        SCRIPTS_PER_CHUNK,
      ),
      ...chunk(
        zones.map((id): WorkersUnit => ({ kind: "zone", id })),
        ZONES_PER_CHUNK,
      ),
    ]);
  },

  async collect(ctx, units) {
    const g = new GraphBuilder();
    const names = units.flatMap((u) => (u.kind === "script" ? [u.name] : []));
    if (names.length > 0) {
      const workers = new Map<string, CfWorker>();
      for (const w of await listWorkers(ctx)) {
        const name = str(w.name);
        if (name) workers.set(name, w);
      }
      const lookup = storeLookup(ctx);
      for (const name of names) {
        const worker = workers.get(name);
        // Absent when it was deleted after the plan step.
        if (worker) await collectScript(ctx, name, worker, lookup, g);
      }
    }
    for (const unit of units) if (unit.kind === "zone") await collectRoutes(ctx, unit.id, g);
    return g.output();
  },
};

function listWorkers(ctx: CollectorContext): Promise<CfWorker[]> {
  const path = `/accounts/${ctx.accountId}/workers/workers`;
  return ctx.api.all<CfWorker>(path, {}, { perPage: WORKERS_PER_PAGE });
}

async function collectRoutes(ctx: CollectorContext, zoneId: string, g: GraphBuilder) {
  const routes = await unlessGone(ctx.api.get<CfRoute[]>(`/zones/${zoneId}/workers/routes`));
  for (const route of routes ?? []) {
    const id = str(route.id);
    const pattern = str(route.pattern);
    if (!id || !pattern) continue;
    const script = str(route.script);
    const routeId = g.node("worker_route", id, pattern, { zone_id: zoneId, pattern, script });
    if (script) g.edge("ROUTES_TO", routeId, nodeId("worker_script", script));
  }
}

async function collectScript(
  ctx: CollectorContext,
  name: string,
  worker: CfWorker,
  lookup: StoreLookup,
  g: GraphBuilder,
): Promise<void> {
  const base = `/accounts/${ctx.accountId}/workers/scripts/${name}`;
  const scriptId = nodeId("worker_script", name);
  let workersDev = bool(worker.subdomain?.enabled);
  let previews = bool(worker.subdomain?.previews_enabled);
  if (workersDev === null || previews === null) {
    const sub = await unlessGone(ctx.api.get<CfScriptSubdomain>(`${base}/subdomain`));
    workersDev = bool(sub?.enabled);
    previews = bool(sub?.previews_enabled);
  }

  const devHost = hostOf(worker.subdomain?.url);
  if (workersDev && devHost) {
    g.edge("ROUTES_TO", g.node("workers_dev", devHost, devHost, { script: name }), scriptId);
  }

  for (const domain of worker.references?.domains ?? []) {
    const hostname = str(domain.hostname)?.toLowerCase();
    if (!hostname) continue;
    const domainId = g.node("worker_custom_domain", hostname, hostname, {
      zone_id: str(domain.zone_id),
      hostname,
      service: name,
      environment: null,
    });
    g.edge("ROUTES_TO", domainId, scriptId);
  }

  // The first deployment is the one serving traffic.
  const deployments = await unlessGone(ctx.api.get<CfDeployments>(`${base}/deployments`));
  const traffic = new Map<string, number | null>();
  for (const v of deployments?.deployments?.[0]?.versions ?? []) {
    const id = str(v.version_id);
    if (id) traffic.set(id, num(v.percentage));
  }

  const suffix = str(worker.subdomain?.preview_url_suffix);
  const withPreviewUrls = previews === true && suffix !== null;
  const recent: string[] = [];
  if (withPreviewUrls) {
    // The first version in the list is the latest.
    const query = { page: 1, per_page: PREVIEW_WINDOW };
    const list = await unlessGone(ctx.api.get<CfVersionList>(`${base}/versions`, query));
    for (const item of (list?.items ?? []).slice(0, PREVIEW_WINDOW)) {
      const id = str(item.id);
      if (id && item.metadata?.hasPreview === true) recent.push(id);
    }
  }

  // The script's compatibility date is that of the version with most traffic.
  let compatibilityDate: string | null = null;
  let topShare = -1;
  for (const versionId of sortedUnique([...traffic.keys(), ...recent])) {
    const version = await unlessGone(ctx.api.get<CfVersion>(`${base}/versions/${versionId}`));
    if (!version) continue;
    const versionNode = await addVersion(g, name, versionId, version, lookup);
    if (traffic.has(versionId)) {
      const percentage = traffic.get(versionId) ?? null;
      g.edge("DEPLOYS", scriptId, versionNode, { percentage });
      if ((percentage ?? 100) > topShare) {
        topShare = percentage ?? 100;
        compatibilityDate = str(version.resources?.script_runtime?.compatibility_date);
      }
    }
    if (withPreviewUrls && version.metadata?.hasPreview === true) {
      // Version URLs are <version prefix><suffix>; the prefix is the first 8 characters of the ID.
      const host = `${versionId.slice(0, 8)}${suffix}`.toLowerCase();
      const previewId = g.node("worker_preview_url", host, host, {
        script: name,
        kind: "version",
        version_id: versionId,
        alias: null,
      });
      g.edge("ROUTES_TO", previewId, versionNode);
    }
  }

  g.node("worker_script", name, name, {
    worker_id: str(worker.id),
    workers_dev: workersDev,
    preview_urls: previews,
    // Unknown: only the classic script listing reports it, and that path is not allowlisted.
    has_assets: null,
    compatibility_date: compatibilityDate,
    created_on: str(worker.created_on),
    modified_on: str(worker.updated_on),
  });
}

type PlainTextVar = { name: string; kind: string } & ValueVerdict;

/**
 * Binding types that hold their value in plain text, and the field with the
 * value. wrangler uploads a `[vars]` entry with an object value as `json`.
 */
const PLAIN_VALUES = new Map<string, string>([
  ["plain_text", "text"],
  ["json", "json"],
]);

async function addVersion(
  g: GraphBuilder,
  script: string,
  versionId: string,
  version: CfVersion,
  lookup: StoreLookup,
): Promise<string> {
  const versionNode = nodeId("worker_version", versionId);
  const bindings = version.resources?.bindings;
  const plainTextVars: PlainTextVar[] = [];
  const secretNames: string[] = [];
  for (const binding of Array.isArray(bindings) ? bindings : []) {
    if (!isObject(binding)) continue;
    const type = str(binding.type);
    const name = str(binding.name);
    if (!type || !name) continue;
    const field = PLAIN_VALUES.get(type);
    if (field) {
      // The value is inspected here and dropped; only the verdict is kept.
      plainTextVars.push({ name, kind: type, ...inspectValue(binding[field]) });
    } else if (type === "secret_text") {
      secretNames.push(name);
    } else {
      const target = await bindingTarget(binding, script, lookup);
      if (target) g.edge("BINDS", versionNode, target, { binding_type: type }, name);
    }
  }
  plainTextVars.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const number = num(version.number);
  g.node("worker_version", versionId, number === null ? null : String(number), {
    script_node_id: nodeId("worker_script", script),
    number,
    created_on: str(version.metadata?.created_on),
    source: str(version.metadata?.source),
    plain_text_vars: plainTextVars,
    secret_names: sortedUnique(secretNames),
  });
  return versionNode;
}
