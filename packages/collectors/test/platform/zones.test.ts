import { describe, expect, it } from "vitest";
import { zonesCollector } from "../../src/platform/zones.ts";
import { zonesRoutes } from "./fixtures/routes.ts";
import { ZONE_A, ZONE_B } from "./fixtures/zones.ts";
import {
  ACCOUNT,
  denied,
  expectDeterministic,
  expectNoPermission,
  expectProps,
  node,
  run,
} from "./helpers.ts";

const routes = zonesRoutes;

describe("zones collector", () => {
  it("emits one zone node per zone across pages", async () => {
    const { output, calls, chunks } = await run(zonesCollector, routes);
    expect(chunks).toEqual([[]]);
    expect(calls).toEqual([
      `GET /zones?account.id=${ACCOUNT}&page=1&per_page=50`,
      `GET /zones?account.id=${ACCOUNT}&page=2&per_page=50`,
    ]);
    expect(output.edges).toEqual([]);
    expectProps(output, "zone", ["status", "paused", "type", "plan"]);
    expect(node(output, `zone:${ZONE_A}`)).toEqual({
      type: "zone",
      nativeId: ZONE_A,
      name: "example.com",
      props: { status: "active", paused: true, type: "full", plan: "Example Org" },
    });
    expect(node(output, `zone:${ZONE_B}`).props).toEqual({
      status: "pending",
      paused: null,
      type: null,
      plan: null,
    });
  });

  it("is deterministic", async () => {
    await expectDeterministic(zonesCollector, routes);
  });

  it("surfaces 403 as NoPermissionError", async () => {
    await expectNoPermission(zonesCollector, { "/zones": denied() });
  });
});
