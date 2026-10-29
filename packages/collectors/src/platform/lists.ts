import type { CollectorContext } from "../types.ts";
import { sortedUnique, str } from "./util.ts";

// Listings that more than one platform collector needs. Field names follow the
// API reference; every field is optional because responses are untrusted.

/** developers.cloudflare.com/api/resources/zones/methods/list */
export interface CfZone {
  id?: string;
  name?: string;
  status?: string;
  paused?: boolean;
  type?: string;
  plan?: { name?: string } | null;
}

/** developers.cloudflare.com/api/resources/queues/methods/list */
export interface CfQueue {
  queue_id?: string;
  queue_name?: string;
}

/** developers.cloudflare.com/api/resources/durable_objects/subresources/namespaces/methods/list */
export interface CfDoNamespace {
  id?: string;
  class?: string;
  name?: string;
  script?: string;
  use_sqlite?: boolean;
}

// The zone list allows at most 50 per page.
export const listZones = (ctx: CollectorContext): Promise<CfZone[]> =>
  ctx.api.all<CfZone>("/zones", { "account.id": ctx.accountId }, { perPage: 50 });

export async function listZoneIds(ctx: CollectorContext): Promise<string[]> {
  return sortedUnique((await listZones(ctx)).map((z) => str(z.id)));
}

export const listQueues = (ctx: CollectorContext): Promise<CfQueue[]> =>
  ctx.api.all<CfQueue>(`/accounts/${ctx.accountId}/queues`);

export const listDoNamespaces = (ctx: CollectorContext): Promise<CfDoNamespace[]> =>
  ctx.api.all<CfDoNamespace>(
    `/accounts/${ctx.accountId}/workers/durable_objects/namespaces`,
    {},
    { perPage: 1000 },
  );
