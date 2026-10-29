// API responses for the scan tests, shaped after the documented 200 examples:
// - GET /zones: https://developers.cloudflare.com/api/resources/zones/methods/list/
// - GET /zones/{zone_id}/dns_records:
//   https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/
// - GET /accounts/{account_id}/r2/buckets:
//   https://developers.cloudflare.com/api/resources/r2/subresources/buckets/methods/list/
// The 403 uses the v4 error envelope; the pages above do not document a 403
// body, so code 10000 ("Authentication error") is the one errorFor maps.
import { envelope, type FixtureRoute, failure } from "@virga/cf-api/testing";

export const ZONE_A = "023e105f4ecef8ad9ca31a8372d0c353";
export const ZONE_B = "372e67954025e0ba6aaa6d586b9e0b59";

export interface DnsRecord {
  id: string;
  name: string;
  type: string;
  content: string;
  proxied: boolean;
  ttl: number;
}

export interface R2Bucket {
  name: string;
  creation_date: string;
  jurisdiction: string;
  location: string;
  storage_class: string;
}

const zone = (id: string, name: string, accountId: string) => ({
  id,
  account: { id: accountId, name: "Example Account Name" },
  activated_on: "2014-01-02T00:01:00.12345Z",
  created_on: "2014-01-01T05:20:00.12345Z",
  modified_on: "2014-01-01T05:20:00.12345Z",
  name,
  name_servers: ["bob.ns.cloudflare.com", "lola.ns.cloudflare.com"],
  paused: false,
  plan: { id: "023e105f4ecef8ad9ca31a8372d0c353", name: "Free Website", legacy_id: "free" },
  status: "active",
  type: "full",
});

export const record = (id: string, name: string, content: string) => ({
  id,
  name,
  ttl: 3600,
  type: "A",
  comment: "Domain verification record",
  content,
  proxied: true,
  settings: { ipv4_only: true, ipv6_only: true },
  tags: ["owner:dns-team"],
  created_on: "2014-01-01T05:20:00.12345Z",
  modified_on: "2014-01-01T05:20:00.12345Z",
  proxiable: true,
});

export const bucket = (name: string): R2Bucket => ({
  creation_date: "2024-05-01T10:00:00.000Z",
  jurisdiction: "default",
  location: "weur",
  name,
  storage_class: "Standard",
});

/** What the fixture account looks like. Tests change it between scans. */
export interface ApiState {
  records: Record<string, DnsRecord[]>;
  /** `forbidden` answers 403, as for a token without R2 read. */
  buckets: R2Bucket[] | "forbidden";
}

export const initialState = (): ApiState => ({
  records: {
    [ZONE_A]: [
      record("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", "example.com", "198.51.100.4"),
      record("a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2", "www.example.com", "198.51.100.5"),
    ],
    [ZONE_B]: [record("b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", "example.org", "203.0.113.7")],
  },
  buckets: "forbidden",
});

const page = (count: number) => ({
  count,
  page: 1,
  per_page: 50,
  total_count: count,
  total_pages: 1,
});

export function apiRoutes(accountId: string, state: ApiState): Record<string, FixtureRoute> {
  const zones = [zone(ZONE_A, "example.com", accountId), zone(ZONE_B, "example.org", accountId)];
  const routes: Record<string, FixtureRoute> = {
    "/zones": envelope(zones, page(zones.length)),
    [`/accounts/${accountId}/r2/buckets`]:
      state.buckets === "forbidden"
        ? failure(403, 10000, "Authentication error")
        : envelope({ buckets: state.buckets }, { per_page: 20 }),
  };
  for (const [zoneId, records] of Object.entries(state.records)) {
    routes[`/zones/${zoneId}/dns_records`] = envelope(records, page(records.length));
  }
  return routes;
}
