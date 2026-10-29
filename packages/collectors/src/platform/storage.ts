import { CfApiError, NoPermissionError } from "@virga/cf-api";
import { nodeId } from "@virga/graph";
import type { Collector, CollectorContext } from "../types.ts";
import { listDoNamespaces, listQueues } from "./lists.ts";
import { bool, chunk, GraphBuilder, listByPage, sortedUnique, str, unlessGone } from "./util.ts";

/** developers.cloudflare.com/api/resources/r2/subresources/buckets/methods/list */
interface CfBucket {
  name?: string;
  location?: string;
  jurisdiction?: string;
  storage_class?: string;
  creation_date?: string;
}

/** developers.cloudflare.com/api/resources/r2/subresources/buckets/subresources/domains/subresources/managed/methods/list */
interface CfManagedDomain {
  domain?: string;
  enabled?: boolean;
}

/** developers.cloudflare.com/api/resources/r2/subresources/buckets/subresources/domains/subresources/custom/methods/list */
interface CfCustomDomains {
  domains?: { domain?: string; enabled?: boolean; zoneId?: string }[];
}

/** developers.cloudflare.com/api/resources/d1/subresources/database/methods/list */
interface CfD1Database {
  uuid?: string;
  name?: string;
  created_at?: string;
}

/** developers.cloudflare.com/api/resources/kv/subresources/namespaces/methods/list */
interface CfKvNamespace {
  id?: string;
  title?: string;
}

/** developers.cloudflare.com/api/resources/hyperdrive/subresources/configs/methods/list */
interface CfHyperdrive {
  id?: string;
  name?: string;
  origin?: { host?: string; scheme?: string };
}

/** developers.cloudflare.com/api/resources/secrets_store/subresources/stores/methods/list */
interface CfSecretsStore {
  id?: string;
}

/** developers.cloudflare.com/api/resources/secrets_store/subresources/stores/subresources/secrets/methods/list */
interface CfStoreSecret {
  name?: string;
  status?: string;
}

type Product = "r2_buckets" | "d1" | "kv" | "queues" | "hyperdrive" | "do_namespaces" | "secrets";
export type StorageUnit = { kind: Product } | { kind: "r2_domains"; bucket: string };

const PRODUCTS: readonly Product[] = [
  "d1",
  "do_namespaces",
  "hyperdrive",
  "kv",
  "queues",
  "r2_buckets",
  "secrets",
];
const BUCKETS_PER_CHUNK = 25;
const BUCKETS_PER_PAGE = 1000;
const MAX_BUCKET_PAGES = 1000;

/**
 * R2 lists with a cursor inside `result_info`, which `CfReader.get` does not
 * return, so this pages with `start_after` (buckets are ordered by name).
 */
async function listBuckets(ctx: CollectorContext): Promise<CfBucket[]> {
  const path = `/accounts/${ctx.accountId}/r2/buckets`;
  const out: CfBucket[] = [];
  let after: string | undefined;
  for (let n = 0; n < MAX_BUCKET_PAGES; n++) {
    const result = await ctx.api.get<{ buckets?: CfBucket[] }>(path, {
      per_page: BUCKETS_PER_PAGE,
      start_after: after,
    });
    const buckets = result?.buckets ?? [];
    out.push(...buckets);
    const last = str(buckets.at(-1)?.name);
    if (buckets.length < BUCKETS_PER_PAGE || !last || last === after) return out;
    after = last;
  }
  throw new CfApiError(0, path, [], `more than ${MAX_BUCKET_PAGES} pages on ${path}`);
}

/**
 * Data stores. One chunk per product, so a product without permission fails
 * only its own chunk, plus chunks of R2 buckets for the per-bucket domain reads.
 */
export const storageCollector: Collector<StorageUnit> = {
  resourceClass: "storage",
  permissions: [
    "Workers R2 Storage Read",
    "D1 Read",
    "Workers KV Storage Read",
    "Queues Read",
    "Hyperdrive Read",
    "Secrets Store Read",
    "Workers Metadata Read-Only",
  ],

  async plan(ctx) {
    let buckets: string[] = [];
    try {
      buckets = sortedUnique((await listBuckets(ctx)).map((b) => str(b.name)));
    } catch (error) {
      // The r2_buckets chunk repeats the call and lets the error propagate, so
      // a token without R2 access still collects the other products.
      if (!(error instanceof NoPermissionError)) throw error;
    }
    return [
      ...PRODUCTS.map((kind): StorageUnit[] => [{ kind }]),
      ...chunk(
        buckets.map((bucket): StorageUnit => ({ kind: "r2_domains", bucket })),
        BUCKETS_PER_CHUNK,
      ),
    ];
  },

  async collect(ctx, units) {
    const g = new GraphBuilder();
    for (const unit of units) {
      if (unit.kind === "r2_domains") await collectBucketDomains(ctx, unit.bucket, g);
      else await COLLECT[unit.kind](ctx, g);
    }
    return g.output();
  },
};

const COLLECT: Record<Product, (ctx: CollectorContext, g: GraphBuilder) => Promise<void>> = {
  async r2_buckets(ctx, g) {
    for (const bucket of await listBuckets(ctx)) {
      const name = str(bucket.name);
      if (!name) continue;
      g.node("r2_bucket", name, name, {
        location: str(bucket.location),
        jurisdiction: str(bucket.jurisdiction),
        storage_class: str(bucket.storage_class),
        creation_date: str(bucket.creation_date),
      });
    }
  },

  async d1(ctx, g) {
    const path = `/accounts/${ctx.accountId}/d1/database`;
    for (const db of await listByPage<CfD1Database>(ctx.api, path, 1000)) {
      const id = str(db.uuid);
      if (id) g.node("d1_database", id, str(db.name), { created_at: str(db.created_at) });
    }
  },

  async kv(ctx, g) {
    const path = `/accounts/${ctx.accountId}/storage/kv/namespaces`;
    for (const ns of await listByPage<CfKvNamespace>(ctx.api, path, 1000)) {
      const id = str(ns.id);
      if (id) g.node("kv_namespace", id, str(ns.title));
    }
  },

  async queues(ctx, g) {
    for (const queue of await listQueues(ctx)) {
      const id = str(queue.queue_id);
      if (id) g.node("queue", id, str(queue.queue_name));
    }
  },

  async hyperdrive(ctx, g) {
    const path = `/accounts/${ctx.accountId}/hyperdrive/configs`;
    for (const config of await listByPage<CfHyperdrive>(ctx.api, path, 100)) {
      const id = str(config.id);
      if (!id) continue;
      g.node("hyperdrive_config", id, str(config.name), {
        origin_host: str(config.origin?.host),
        origin_scheme: str(config.origin?.scheme),
      });
    }
  },

  async do_namespaces(ctx, g) {
    for (const ns of await listDoNamespaces(ctx)) {
      const id = str(ns.id);
      if (!id) continue;
      const script = str(ns.script);
      const className = str(ns.class);
      g.node("do_namespace", id, script && className ? `${script}:${className}` : str(ns.name), {
        script,
        class: className,
        use_sqlite: bool(ns.use_sqlite),
      });
    }
  },

  async secrets(ctx, g) {
    const base = `/accounts/${ctx.accountId}/secrets_store/stores`;
    const stores = await ctx.api.all<CfSecretsStore>(base, {}, { perPage: 100 });
    for (const storeId of sortedUnique(stores.map((s) => str(s.id)))) {
      const path = `${base}/${storeId}/secrets`;
      const secrets = await unlessGone(ctx.api.all<CfStoreSecret>(path, {}, { perPage: 100 }));
      for (const secret of secrets ?? []) {
        const name = str(secret.name);
        if (!name || secret.status === "deleted") continue;
        g.node("secrets_store_secret", `${storeId}/${name}`, name, { store_id: storeId });
      }
    }
  },
};

async function collectBucketDomains(
  ctx: CollectorContext,
  bucket: string,
  g: GraphBuilder,
): Promise<void> {
  const base = `/accounts/${ctx.accountId}/r2/buckets/${bucket}/domains`;
  const bucketId = nodeId("r2_bucket", bucket);
  const managed = await unlessGone(ctx.api.get<CfManagedDomain>(`${base}/managed`));
  const managedHost = str(managed?.domain)?.toLowerCase();
  // The r2.dev domain always exists; it is an entry point only while enabled.
  if (managedHost && managed?.enabled === true) {
    const id = g.node("r2_public_domain", managedHost, managedHost, {
      bucket,
      kind: "r2_dev",
      enabled: true,
      zone_id: null,
    });
    g.edge("ROUTES_TO", id, bucketId);
  }
  const custom = await unlessGone(ctx.api.get<CfCustomDomains>(`${base}/custom`));
  for (const domain of custom?.domains ?? []) {
    const host = str(domain.domain)?.toLowerCase();
    if (!host) continue;
    const id = g.node("r2_public_domain", host, host, {
      bucket,
      kind: "custom",
      enabled: bool(domain.enabled),
      zone_id: str(domain.zoneId),
    });
    g.edge("ROUTES_TO", id, bucketId);
  }
}
