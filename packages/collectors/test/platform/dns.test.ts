import { describe, expect, it } from "vitest";
import { dnsCollector } from "../../src/platform/dns.ts";
import { recordA, recordCname, recordTxt } from "./fixtures/dns.ts";
import { dnsRoutes } from "./fixtures/routes.ts";
import { ZONE_A, ZONE_B, zoneA, zonesRoute } from "./fixtures/zones.ts";
import {
  context,
  denied,
  expectDeterministic,
  expectNoPermission,
  expectProps,
  node,
  run,
  without,
} from "./helpers.ts";

const routes = dnsRoutes;

describe("dns collector", () => {
  it("plans zone chunks of 25", async () => {
    const zones = Array.from({ length: 30 }, (_, i) => ({
      ...zoneA,
      id: `${String(i).padStart(2, "0")}${zoneA.id.slice(2)}`,
    }));
    const plan = await dnsCollector.plan(context({ "/zones": zonesRoute(zones) }).ctx);
    expect(plan.map((c) => c.length)).toEqual([25, 5]);
    expect(plan.flat()).toEqual(zones.map((z) => z.id).sort());
  });

  it("emits dns_record nodes with the contract props across pages", async () => {
    const { output, calls } = await run(dnsCollector, routes);
    expect(calls.filter((c) => c.includes("dns_records"))).toEqual([
      `GET /zones/${ZONE_A}/dns_records?page=1&per_page=5000`,
      `GET /zones/${ZONE_A}/dns_records?page=2&per_page=5000`,
      `GET /zones/${ZONE_B}/dns_records?page=1&per_page=5000`,
    ]);
    expect(output.edges).toEqual([]);
    expectProps(output, "dns_record", ["zone_id", "type", "content", "proxied", "ttl"]);
    expect(node(output, `dns_record:${recordA.id}`)).toEqual({
      type: "dns_record",
      nativeId: recordA.id,
      name: "example.com",
      props: { zone_id: ZONE_A, type: "A", content: "198.51.100.4", proxied: true, ttl: 3600 },
    });
    expect(node(output, `dns_record:${recordCname.id}`).props).toEqual({
      zone_id: ZONE_A,
      type: "CNAME",
      content: "example.com",
      proxied: false,
      ttl: 1,
    });
    expect(node(output, `dns_record:${recordTxt.id}`).props).toMatchObject({ zone_id: ZONE_B });
  });

  it("skips zones deleted between listing and reading", async () => {
    const { output } = await run(dnsCollector, without(routes, `/zones/${ZONE_B}/dns_records`));
    expect(output.nodes.map((n) => n.nativeId).sort()).toEqual([recordA.id, recordCname.id].sort());
  });

  it("is deterministic", async () => {
    await expectDeterministic(dnsCollector, routes);
  });

  it("surfaces 403 as NoPermissionError", async () => {
    await expectNoPermission(dnsCollector, {
      ...routes,
      [`/zones/${ZONE_B}/dns_records`]: denied(),
    });
    await expectNoPermission(dnsCollector, { "/zones": denied() });
  });
});
