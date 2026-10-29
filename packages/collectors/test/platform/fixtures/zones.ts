// Source: https://developers.cloudflare.com/api/resources/zones/methods/list/
// The first zone is the documented 200 example; the second varies it.

import type { CfQuery } from "@virga/cf-api";
import { envelope } from "@virga/cf-api/testing";

export const ZONE_A = "023e105f4ecef8ad9ca31a8372d0c353";
export const ZONE_B = "9a7806061c88ada191ed06f989cc3dac";

export const zoneA = {
  id: ZONE_A,
  account: { id: "023e105f4ecef8ad9ca31a8372d0c353", name: "Example Account Name" },
  activated_on: "2014-01-02T00:01:00.12345Z",
  created_on: "2014-01-01T05:20:00.12345Z",
  development_mode: 7200,
  meta: {
    cdn_only: true,
    custom_certificate_quota: 1,
    dns_only: true,
    foundation_dns: true,
    page_rule_quota: 100,
    phishing_detected: false,
    step: 2,
  },
  modified_on: "2014-01-01T05:20:00.12345Z",
  name: "example.com",
  name_servers: ["bob.ns.cloudflare.com", "lola.ns.cloudflare.com"],
  original_dnshost: "NameCheap",
  original_name_servers: ["ns1.originaldnshost.com", "ns2.originaldnshost.com"],
  original_registrar: "GoDaddy",
  owner: { id: "023e105f4ecef8ad9ca31a8372d0c353", name: "Example Org", type: "organization" },
  plan: {
    id: "023e105f4ecef8ad9ca31a8372d0c353",
    can_subscribe: false,
    currency: "USD",
    externally_managed: false,
    frequency: "monthly",
    is_subscribed: false,
    legacy_discount: false,
    legacy_id: "free",
    name: "Example Org",
    price: 10.99,
  },
  cname_suffix: "cdn.cloudflare.com",
  paused: true,
  permissions: ["#worker:read"],
  status: "active",
  tenant: { id: "023e105f4ecef8ad9ca31a8372d0c353", name: "Example Account Name" },
  tenant_unit: { id: "023e105f4ecef8ad9ca31a8372d0c353" },
  type: "full",
  vanity_name_servers: ["ns1.example.com", "ns2.example.com"],
  verification_key: "284344499-1084221259",
};

// No plan, paused and type omitted: optional fields in the schema.
export const zoneB = {
  id: ZONE_B,
  account: { id: "023e105f4ecef8ad9ca31a8372d0c353", name: "Example Account Name" },
  activated_on: "2015-03-02T00:01:00.12345Z",
  created_on: "2015-03-01T05:20:00.12345Z",
  development_mode: 0,
  meta: { phishing_detected: false },
  modified_on: "2015-03-01T05:20:00.12345Z",
  name: "example.org",
  name_servers: ["bob.ns.cloudflare.com", "lola.ns.cloudflare.com"],
  original_dnshost: "NameCheap",
  original_name_servers: [],
  original_registrar: "GoDaddy",
  owner: { id: "023e105f4ecef8ad9ca31a8372d0c353", name: "Example Org", type: "organization" },
  status: "pending",
};

/** GET /zones, two pages of one zone each, as `result_info.total_pages` describes. */
export function zonesRoute(zones: object[] = [zoneA, zoneB]) {
  return (q: CfQuery) => {
    const page = Number(q.page ?? 1);
    return envelope(zones.slice(page - 1, page), {
      count: 1,
      page,
      per_page: Number(q.per_page),
      total_count: zones.length,
      total_pages: zones.length,
    });
  };
}
