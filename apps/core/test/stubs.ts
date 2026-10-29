import { CfApiError } from "@virga/cf-api";
import type { Collector, CollectorOutput } from "@virga/collectors";
import type { NodeInput } from "@virga/graph";
import type { DnsRecord, R2Bucket } from "./fixtures/api.ts";

/**
 * Small stand-ins for real collectors, reading the fixture API through the
 * same reader the scan gives every collector.
 */

/** `dns`: one chunk per zone, so the fixture account (two zones) takes two chunks. */
export const dnsStub: Collector<string> = {
  resourceClass: "dns",
  after: ["storage"],
  permissions: ["DNS Read"],
  async plan(ctx) {
    const zones = await ctx.api.all<{ id: string }>("/zones");
    return zones.map((z) => [z.id]);
  },
  async collect(ctx, zoneIds) {
    const nodes: NodeInput[] = [];
    for (const zoneId of zoneIds) {
      for (const r of await ctx.api.all<DnsRecord>(`/zones/${zoneId}/dns_records`)) {
        nodes.push({
          type: "dns_record",
          nativeId: r.id,
          name: r.name,
          props: {
            zone_id: zoneId,
            type: r.type,
            content: r.content,
            proxied: r.proxied,
            ttl: r.ttl,
          },
        });
      }
    }
    return { nodes, edges: [] };
  },
};

/** `storage`: a single chunk listing R2 buckets; NoPermissionError when the API answers 403. */
export const storageStub: Collector<never> = {
  resourceClass: "storage",
  permissions: ["Workers R2 Storage Read"],
  async plan() {
    return [[]];
  },
  async collect(ctx) {
    const { buckets } = await ctx.api.get<{ buckets: R2Bucket[] }>(
      `/accounts/${ctx.accountId}/r2/buckets`,
    );
    return {
      nodes: buckets.map((b) => ({
        type: "r2_bucket" as const,
        nativeId: b.name,
        name: b.name,
        props: {
          location: b.location,
          jurisdiction: b.jurisdiction,
          storage_class: b.storage_class,
          creation_date: b.creation_date,
        },
      })),
      edges: [],
    };
  },
};

/** A collector whose chunks are scripted: each entry is an output or an error to throw. */
export function scriptedStub(
  resourceClass: Collector["resourceClass"],
  chunks: (CollectorOutput | Error)[],
): Collector<number> & { calls: number[] } {
  const calls: number[] = [];
  return {
    resourceClass,
    permissions: [],
    calls,
    async plan() {
      return chunks.map((_, i) => [i]);
    },
    async collect(_ctx, [i]) {
      calls.push(i ?? -1);
      const outcome = chunks[i ?? -1];
      if (!outcome) throw new Error(`no chunk ${i}`);
      if (outcome instanceof Error) throw outcome;
      return outcome;
    },
  };
}

export const serverError = (path: string) =>
  new CfApiError(500, path, [{ code: 10001, message: "Internal server error" }]);
