import type { Collector } from "../types.ts";
import { listZoneIds } from "./lists.ts";
import { bool, chunk, GraphBuilder, nonEmpty, num, str, unlessGone } from "./util.ts";

/** developers.cloudflare.com/api/resources/dns/subresources/records/methods/list */
interface CfDnsRecord {
  id?: string;
  name?: string;
  type?: string;
  content?: string;
  proxied?: boolean;
  ttl?: number;
}

const ZONES_PER_CHUNK = 25;
// The API allows far larger pages; 5,000 records keep one response at a few MB.
const RECORDS_PER_PAGE = 5000;

/** `dns_record` nodes, chunked by zone. */
export const dnsCollector: Collector<string> = {
  resourceClass: "dns",
  permissions: ["Zone Read", "DNS Read"],

  async plan(ctx) {
    return nonEmpty(chunk(await listZoneIds(ctx), ZONES_PER_CHUNK));
  },

  async collect(ctx, zoneIds) {
    const g = new GraphBuilder();
    for (const zoneId of zoneIds) {
      const path = `/zones/${zoneId}/dns_records`;
      const records = await unlessGone(
        ctx.api.all<CfDnsRecord>(path, {}, { perPage: RECORDS_PER_PAGE }),
      );
      for (const record of records ?? []) {
        const id = str(record.id);
        if (!id) continue;
        g.node("dns_record", id, str(record.name), {
          zone_id: zoneId,
          type: str(record.type),
          content: str(record.content),
          proxied: bool(record.proxied),
          ttl: num(record.ttl),
        });
      }
    }
    return g.output();
  },
};
