import { NoPermissionError } from "@virga/cf-api";
import { describe, expect, it } from "vitest";
import { TRAFFIC_QUERY, trafficCollector } from "../../src/identity/traffic.ts";
import { trafficRoutes } from "./fixtures/routes.ts";
import { trafficGraphql } from "./fixtures/traffic.ts";
import {
  ACCOUNT,
  BASE,
  denied,
  expectDeterministic,
  expectNoPermission,
  type GraphqlHandler,
  NOW,
  run,
} from "./helpers.ts";

const routes = trafficRoutes;
const script = (name: string) => `worker_script:${name}`;

describe("traffic collector", () => {
  it("sends one query for the 30 days before the scan started", async () => {
    const { handler, calls: queries } = trafficGraphql();
    const { chunks, calls } = await run(trafficCollector, routes, handler);
    expect(chunks).toEqual([[]]);
    expect(calls.filter((c) => c === "POST /graphql")).toHaveLength(1);
    expect(queries).toEqual([
      {
        query: TRAFFIC_QUERY,
        variables: {
          accountTag: ACCOUNT,
          start: "2026-09-29T12:00:00.000Z",
          end: "2026-10-29T12:00:00.000Z",
        },
      },
    ]);
    expect(new Date(NOW).toISOString()).toBe("2026-10-29T12:00:00.000Z");
    expect(TRAFFIC_QUERY).toContain("workersInvocationsAdaptive");
    expect(TRAFFIC_QUERY).not.toMatch(/\bmutation\b/);
  });

  it("sums requests and errors per script into worker_script signals", async () => {
    const { output } = await run(trafficCollector, routes, trafficGraphql().handler);
    expect(output.nodes).toEqual([]);
    expect(output.edges).toEqual([]);
    expect(output.signals).toEqual([
      { nodeId: script("api-worker"), name: "errors_30d", value: 0 },
      { nodeId: script("api-worker"), name: "invocations_30d", value: 50 },
      // No traffic: 0, so an earlier value never lingers in the signals table.
      { nodeId: script("legacy-worker"), name: "errors_30d", value: 0 },
      { nodeId: script("legacy-worker"), name: "invocations_30d", value: 0 },
      { nodeId: script("my-worker"), name: "errors_30d", value: 4 },
      { nodeId: script("my-worker"), name: "invocations_30d", value: 1234 },
    ]);
  });

  it("is deterministic", async () => {
    await expectDeterministic(trafficCollector, routes, trafficGraphql().handler);
  });

  it("surfaces a GraphQL authorization error as NoPermissionError", async () => {
    const unauthorized: GraphqlHandler = () => ({
      status: 200,
      data: null,
      errors: [{ message: "not authorized for that account" }],
    });
    await expectNoPermission(trafficCollector, routes, unauthorized);
  });

  it("treats an account the analytics API does not show as no permission, not as no traffic", async () => {
    const hidden: GraphqlHandler = () => ({
      status: 200,
      data: { viewer: { accounts: [] } },
      errors: null,
    });
    await expectNoPermission(trafficCollector, routes, hidden);
  });

  it("surfaces 403 on the Worker list as NoPermissionError", async () => {
    await expectNoPermission(
      trafficCollector,
      { [`${BASE}/workers/workers`]: denied() },
      trafficGraphql().handler,
    );
  });

  it("refuses a truncated result instead of reporting zeros", async () => {
    const rows = Array.from({ length: 10_000 }, (_, i) => ({
      dimensions: { scriptName: `w-${i}` },
      sum: { requests: 1, errors: 0 },
    }));
    const error = await run(trafficCollector, routes, trafficGraphql(rows).handler).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(NoPermissionError);
  });
});
