import { NoPermissionError } from "@virga/cf-api";
import type { SignalRow } from "@virga/graph";
import {
  chunk,
  GraphBuilder,
  isObject,
  num,
  sortedUnique,
  str,
  unlessGone,
} from "../platform/util.ts";
import type { Collector, CollectorContext } from "../types.ts";
import { addSelects, rulesOf } from "./selectors.ts";
import { appTargets, needsWorkerScripts } from "./targets.ts";
import { displayName, epochMs, fitsId, listWorkers, sortedSignals } from "./util.ts";

// Sources:
// developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/list
// developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/subresources/policies/methods/list
// developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/policies/methods/list
// developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/groups/methods/list
// developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/service_tokens/methods/list
// developers.cloudflare.com/api/resources/zero_trust/subresources/identity_providers/methods/list
// Every listing allows 1,000 per page and reports total_pages.

export type AccessUnit = { kind: "app"; id: string } | { kind: "directory" };

const APPS_PER_CHUNK = 25;
const PER_PAGE = 1000;

type Item = Record<string, unknown>;

async function list(ctx: CollectorContext, resource: string): Promise<Item[]> {
  const path = `/accounts/${ctx.accountId}/access/${resource}`;
  return (await ctx.api.all<unknown>(path, {}, { perPage: PER_PAGE })).filter(isObject);
}

/**
 * Access apps with their policies (one chunk per 25 apps), and in one more
 * chunk the reusable policies, groups, service tokens and identity providers.
 *
 * Only selected fields are copied: the listings also carry SaaS and SCIM
 * credentials and IdP client secrets, which never enter the graph.
 */
export const accessCollector: Collector<AccessUnit> = {
  resourceClass: "access",
  permissions: [
    "Access: Apps and Policies Read",
    "Access: Organizations, Identity Providers, and Groups Read",
    "Access: Service Tokens Read",
    // Optional: resolves Worker destinations to script names.
    "Workers Metadata Read-Only",
  ],

  async plan(ctx) {
    const ids = sortedUnique((await list(ctx, "apps")).map((app) => str(app.id)));
    return [
      [{ kind: "directory" }],
      ...chunk(
        ids.map((id): AccessUnit => ({ kind: "app", id })),
        APPS_PER_CHUNK,
      ),
    ];
  },

  async collect(ctx, units) {
    const g = new GraphBuilder();
    const ids = units.flatMap((u) => (u.kind === "app" ? [u.id] : []));
    if (ids.length > 0) await collectApps(ctx, ids, g);
    const signals = units.some((u) => u.kind === "directory") ? await collectDirectory(ctx, g) : [];
    return { ...g.output(), signals };
  },
};

/**
 * Worker ID to script name, or null without permission to list Workers:
 * Worker destinations then stay unresolved (`other`).
 */
async function readableScripts(ctx: CollectorContext): Promise<Map<string, string> | null> {
  try {
    const scripts = new Map<string, string>();
    for (const { id, name } of await listWorkers(ctx)) if (id) scripts.set(id, name);
    return scripts;
  } catch (error) {
    if (error instanceof NoPermissionError) return null;
    throw error;
  }
}

async function collectApps(ctx: CollectorContext, ids: string[], g: GraphBuilder): Promise<void> {
  const apps = new Map<string, Item>();
  for (const app of await list(ctx, "apps")) {
    const id = str(app.id);
    if (id) apps.set(id, app);
  }
  let scripts: Map<string, string> | null | undefined;
  for (const id of [...ids].sort()) {
    const app = apps.get(id);
    // Absent when it was deleted after the plan step.
    if (!app || !fitsId(id)) continue;
    if (scripts === undefined && needsWorkerScripts(app)) scripts = await readableScripts(ctx);
    const allowedIdps = Array.isArray(app.allowed_idps) ? app.allowed_idps.map(str) : [];
    const appId = g.node("access_app", id, displayName(app.name), {
      app_type: str(app.type),
      targets: appTargets(app, scripts ?? null),
      session_duration: str(app.session_duration),
      allowed_idps: sortedUnique(allowedIdps),
    });
    // Both the app's own and the reusable policies it uses, with their precedence in this app.
    const path = `/accounts/${ctx.accountId}/access/apps/${id}/policies`;
    const policies = await unlessGone(ctx.api.all<unknown>(path, {}, { perPage: PER_PAGE }));
    for (const policy of (policies ?? []).filter(isObject)) {
      const policyId = addPolicy(g, policy);
      if (policyId) g.edge("ALLOWS", policyId, appId, { precedence: num(policy.precedence) });
    }
  }
}

function addPolicy(g: GraphBuilder, policy: Item): string | null {
  const id = str(policy.id);
  if (!id || !fitsId(id)) return null;
  const rules = rulesOf(policy);
  const policyId = g.node("access_policy", id, displayName(policy.name), {
    decision: str(policy.decision),
    ...rules,
    session_duration: str(policy.session_duration),
  });
  addSelects(g, policyId, rules);
  return policyId;
}

async function collectDirectory(ctx: CollectorContext, g: GraphBuilder): Promise<SignalRow[]> {
  // Reusable policies that no app uses yet; the apps' chunks emit the same nodes.
  for (const policy of await list(ctx, "policies")) addPolicy(g, policy);

  for (const group of await list(ctx, "groups")) {
    const id = str(group.id);
    if (!id || !fitsId(id)) continue;
    const rules = rulesOf(group);
    addSelects(g, g.node("access_group", id, displayName(group.name), { ...rules }), rules);
  }

  const signals: SignalRow[] = [];
  for (const token of await list(ctx, "service_tokens")) {
    const id = str(token.id);
    if (!id || !fitsId(id)) continue;
    // client_id is half of the credential and stays out of the graph.
    const tokenId = g.node("service_token", id, displayName(token.name), {
      expires_at: str(token.expires_at),
      duration: str(token.duration),
    });
    signals.push({ nodeId: tokenId, name: "last_seen_at", value: epochMs(token.last_seen_at) });
  }

  for (const idp of await list(ctx, "identity_providers")) {
    const id = str(idp.id);
    if (!id || !fitsId(id)) continue;
    g.node("identity_provider", id, displayName(idp.name), { idp_type: str(idp.type) });
  }
  return sortedSignals(signals);
}
