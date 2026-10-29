// Route tables for the fixture transport, one per collector, assembled from the
// documented examples in the sibling fixture files (sources are cited there).

import type { CfQuery } from "@virga/cf-api";
import { envelope, type FixtureRoute } from "@virga/cf-api/testing";
import { recordA, recordCname, recordTxt } from "./dns.ts";
import { ZONE_A, ZONE_B, zonesRoute } from "./zones.ts";

export type Routes = Record<string, FixtureRoute>;

export const ACCOUNT = "023e105f4ecef8ad9ca31a8372d0c353";

export const zonesRoutes: Routes = { "/zones": zonesRoute() };

/** Zone A has two pages of records, zone B one. */
export const dnsRoutes: Routes = {
  "/zones": zonesRoute(),
  [`/zones/${ZONE_A}/dns_records`]: (q: CfQuery) =>
    Number(q.page) === 1
      ? envelope([recordA], { count: 1, page: 1, per_page: 5000, total_count: 2, total_pages: 2 })
      : envelope([recordCname], {
          count: 1,
          page: 2,
          per_page: 5000,
          total_count: 2,
          total_pages: 2,
        }),
  [`/zones/${ZONE_B}/dns_records`]: envelope([recordTxt], {
    count: 1,
    page: 1,
    per_page: 5000,
    total_count: 1,
    total_pages: 1,
  }),
};
