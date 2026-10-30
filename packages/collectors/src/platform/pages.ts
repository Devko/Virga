import type { Collector, CollectorContext } from "../types.ts";
import { type Binding, bindingTarget, type StoreLookup, storeLookup } from "./bindings.ts";
import { inspectValue, type ValueVerdict } from "./secrets.ts";
import { chunk, GraphBuilder, isObject, nonEmpty, sortedUnique, str, unlessGone } from "./util.ts";

/** developers.cloudflare.com/api/resources/pages/subresources/projects/methods/get */
interface CfPagesProject {
  name?: string;
  subdomain?: string;
  production_branch?: string;
  source?: { config?: { preview_deployment_setting?: string; production_branch?: string } };
  deployment_configs?: Record<string, unknown>;
}

/** developers.cloudflare.com/api/resources/pages/subresources/projects/subresources/domains/methods/list */
interface CfPagesDomain {
  name?: string;
  status?: string;
}

const PROJECTS_PER_CHUNK = 20;
const ENVIRONMENTS = ["preview", "production"] as const;
const PREVIEW_SETTINGS = new Set(["all", "none", "custom"]);

// Pages keys bindings by name inside one map per kind. Each map is turned into
// the Worker binding shape so both share one target table.
const BINDING_MAPS: Record<string, (value: Record<string, unknown>) => Binding> = {
  d1_databases: (v) => ({ type: "d1", database_id: v.id }),
  kv_namespaces: (v) => ({ type: "kv_namespace", namespace_id: v.namespace_id }),
  r2_buckets: (v) => ({ type: "r2_bucket", bucket_name: v.name }),
  durable_object_namespaces: (v) => ({
    type: "durable_object_namespace",
    namespace_id: v.namespace_id,
  }),
  services: (v) => ({ type: "service", service: v.service }),
  queue_producers: (v) => ({ type: "queue", queue_name: v.name }),
  hyperdrive_bindings: (v) => ({ type: "hyperdrive", id: v.id }),
  vectorize_bindings: (v) => ({ type: "vectorize", index_name: v.index_name }),
};

/**
 * Pages projects, their pages.dev and custom domains, the preview wildcard,
 * and the bindings of the production and preview environments.
 */
export const pagesCollector: Collector<string> = {
  resourceClass: "pages",
  after: ["storage", "workers"],
  permissions: ["Pages Read", "Queues Read"],

  async plan(ctx) {
    const projects = await ctx.api.all<CfPagesProject>(`/accounts/${ctx.accountId}/pages/projects`);
    return nonEmpty(chunk(sortedUnique(projects.map((p) => str(p.name))), PROJECTS_PER_CHUNK));
  },

  async collect(ctx, names) {
    const g = new GraphBuilder();
    const lookup = storeLookup(ctx);
    for (const name of names) await collectProject(ctx, name, lookup, g);
    return g.output();
  },
};

/**
 * Preview deployments are on by default; only Git-connected projects have a
 * setting (developers.cloudflare.com/pages/configuration/preview-deployments/).
 */
function previewSetting(project: CfPagesProject): string {
  const setting = str(project.source?.config?.preview_deployment_setting);
  return setting && PREVIEW_SETTINGS.has(setting) ? setting : "all";
}

type PlainTextVar = { name: string; environment: string; kind: string } & ValueVerdict;

/**
 * Plain-text environment variables of both environments, without their
 * values. Values are inspected here and dropped; secret_text is never read.
 */
function plainTextVars(configs: unknown): PlainTextVar[] {
  const vars: PlainTextVar[] = [];
  for (const environment of ENVIRONMENTS) {
    const config = isObject(configs) ? configs[environment] : undefined;
    const envVars = isObject(config) && isObject(config.env_vars) ? config.env_vars : {};
    for (const name of Object.keys(envVars).sort()) {
      const envVar = envVars[name];
      if (!isObject(envVar) || envVar.type !== "plain_text") continue;
      vars.push({ name, environment, kind: "plain_text", ...inspectValue(envVar.value) });
    }
  }
  return vars;
}

async function collectProject(
  ctx: CollectorContext,
  name: string,
  lookup: StoreLookup,
  g: GraphBuilder,
): Promise<void> {
  const path = `/accounts/${ctx.accountId}/pages/projects/${name}`;
  const project = await unlessGone(ctx.api.get<CfPagesProject>(path));
  if (!project) return;
  const subdomain = (str(project.subdomain) ?? `${name}.pages.dev`).toLowerCase();
  const preview = previewSetting(project);
  const configs = project.deployment_configs;
  const projectId = g.node("pages_project", name, name, {
    production_branch:
      str(project.production_branch) ?? str(project.source?.config?.production_branch),
    subdomain,
    preview_deployments: preview,
    plain_text_vars: plainTextVars(configs),
  });

  const production = { environment: "production" };
  g.edge(
    "ROUTES_TO",
    g.node("pages_domain", subdomain, subdomain, { project: name, status: null }),
    projectId,
    production,
  );
  const domains = await unlessGone(ctx.api.all<CfPagesDomain>(`${path}/domains`));
  for (const domain of domains ?? []) {
    const host = str(domain.name)?.toLowerCase();
    if (!host) continue;
    const domainId = g.node("pages_domain", host, host, {
      project: name,
      status: str(domain.status),
    });
    g.edge("ROUTES_TO", domainId, projectId, production);
  }
  if (preview !== "none") {
    const wildcard = `*.${subdomain}`;
    const previewId = g.node("pages_preview", wildcard, wildcard, { project: name });
    g.edge("ROUTES_TO", previewId, projectId, { environment: "preview" });
  }

  for (const environment of ENVIRONMENTS) {
    const config = isObject(configs) ? configs[environment] : undefined;
    if (!isObject(config)) continue;
    for (const [field, toBinding] of Object.entries(BINDING_MAPS)) {
      const map = config[field];
      if (!isObject(map)) continue;
      for (const [bindingName, value] of Object.entries(map)) {
        if (!isObject(value)) continue;
        const binding = toBinding(value);
        const target = await bindingTarget(binding, name, lookup);
        if (!target) continue;
        g.edge(
          "BINDS",
          projectId,
          target,
          { binding_type: str(binding.type), environment },
          `${environment}:${bindingName}`,
        );
      }
    }
  }
}
