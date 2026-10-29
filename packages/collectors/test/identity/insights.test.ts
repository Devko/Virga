import { envelope } from "@virga/cf-api/testing";
import { describe, expect, it } from "vitest";
import { insightsCollector } from "../../src/identity/insights.ts";
import { exampleIssue, insightsRoute, manyIssues, tunnelIssue } from "./fixtures/insights.ts";
import { insightsRoutes } from "./fixtures/routes.ts";
import { BASE, denied, expectDeterministic, expectNoPermission, run } from "./helpers.ts";

const path = `${BASE}/security-center/insights`;
const routes = insightsRoutes;

describe("insights collector", () => {
  it("returns the whole current set as insights rows, in one chunk", async () => {
    const { chunks, calls, output } = await run(insightsCollector, routes);
    expect(chunks).toEqual([[]]);
    expect(calls).toEqual([`GET ${path}?page=1&per_page=1000`]);
    expect(output.nodes).toEqual([]);
    expect(output.edges).toEqual([]);
    expect(output.insights).toEqual([
      {
        id: "id",
        type: "compliance_violation",
        severity: "Low",
        subjectId: null,
        payload: exampleIssue,
      },
    ]);
  });

  it("keeps only the documented fields in the payload", async () => {
    const { output } = await run(insightsCollector, {
      [path]: insightsRoute([tunnelIssue, exampleIssue]),
    });
    expect(output.insights.map((i) => i.id)).toEqual(["b2f0c6a4-unprotected-tunnel", "id"]);
    const tunnel = output.insights[0];
    expect(tunnel).toMatchObject({ type: "exposed_infrastructure", severity: "Critical" });
    expect(tunnel?.payload).not.toHaveProperty("unknown_field");
    expect(tunnel?.payload.subject).toBe("tunnel.example.com");
  });

  it("follows pages until the count is reached", async () => {
    const { calls, output } = await run(insightsCollector, { [path]: insightsRoute(manyIssues) });
    expect(calls).toEqual([`GET ${path}?page=1&per_page=1000`, `GET ${path}?page=2&per_page=1000`]);
    expect(output.insights).toHaveLength(1001);
  });

  it("returns an empty set when there are no insights", async () => {
    const { output } = await run(insightsCollector, {
      [path]: envelope({ count: 0, issues: [], page: 1, per_page: 1000 }),
    });
    expect(output.insights).toEqual([]);
  });

  it("is deterministic", async () => {
    await expectDeterministic(insightsCollector, routes);
  });

  it("surfaces 403 as NoPermissionError", async () => {
    await expectNoPermission(insightsCollector, { [path]: denied() });
  });
});
