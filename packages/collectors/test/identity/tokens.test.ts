import { describe, expect, it } from "vitest";
import { tokensCollector } from "../../src/identity/tokens.ts";
import { tokensRoutes } from "./fixtures/routes.ts";
import { TOKENS, tokenDeploy, tokenDisabled, tokenExample } from "./fixtures/tokens.ts";
import {
  BASE,
  denied,
  expectDeterministic,
  expectNoPermission,
  expectProps,
  node,
  nodeIds,
  run,
} from "./helpers.ts";

const routes = tokensRoutes;

describe("tokens collector", () => {
  it("lists tokens, including recently expired ones, until a short page", async () => {
    const { chunks, calls, output } = await run(tokensCollector, routes);
    expect(chunks).toEqual([[]]);
    expect(calls).toEqual([
      `GET ${BASE}/tokens?include_expired=true&page=1&per_page=50`,
      `GET ${BASE}/tokens?include_expired=true&page=2&per_page=50`,
    ]);
    expect(nodeIds(output, "account_token")).toHaveLength(TOKENS.length);
    expect(output.edges).toEqual([]);
  });

  it("emits account_token nodes with the contract props", async () => {
    const { output } = await run(tokensCollector, routes);
    expectProps(output, "account_token", [
      "status",
      "issued_on",
      "modified_on",
      "expires_on",
      "not_before",
      "policies",
      "ip_condition",
    ]);
    expect(node(output, `account_token:${tokenExample.id}`)).toEqual({
      type: "account_token",
      nativeId: tokenExample.id,
      name: "readonly token",
      props: {
        status: "active",
        issued_on: "2018-07-01T05:20:00Z",
        modified_on: "2018-07-02T05:20:00Z",
        expires_on: "2020-01-01T00:00:00Z",
        not_before: "2018-07-01T05:20:00Z",
        policies: [
          {
            effect: "allow",
            permission_groups: [
              { id: "82e64a83756745bbbb1c9c2701bf816b", name: "Magic Network Monitoring" },
              { id: "c8fed203ed3043cba015a93ad1616f1f", name: "Zone Read" },
            ],
            resources: { "com.cloudflare.api.account.zone.22b1de5f1c0e4b3ea97bb1e963b06a43": "*" },
          },
        ],
        ip_condition: {
          in: ["123.123.123.0/24", "2606:4700::/32"],
          not_in: ["123.123.123.100/24", "2606:4700:4700::/48"],
        },
      },
    });
  });

  it("uses null for no expiry and no IP condition, and flattens nested resources", async () => {
    const { output } = await run(tokensCollector, routes);
    expect(node(output, `account_token:${tokenDeploy.id}`).props).toEqual({
      status: "active",
      issued_on: "2024-02-01T00:00:00Z",
      modified_on: "2024-02-01T00:00:00Z",
      expires_on: null,
      not_before: null,
      policies: [
        {
          effect: "allow",
          permission_groups: [
            { id: "e086da7e2179491d91ee5f35b3ca210a", name: "Workers Scripts Write" },
          ],
          resources: { "com.cloudflare.api.account.zone.*": "*" },
        },
        {
          effect: "deny",
          permission_groups: [{ id: "4755a26eedb94da69e1066d98aa820be", name: "DNS Write" }],
          resources: { "com.cloudflare.api.account.zone.22b1de5f1c0e4b3ea97bb1e963b06a43": "*" },
        },
      ],
      ip_condition: null,
    });
    expect(node(output, `account_token:${tokenDisabled.id}`).props).toMatchObject({
      status: "disabled",
      policies: [],
    });
  });

  it("emits last_used_on as an epoch ms signal, null when never used", async () => {
    const { output } = await run(tokensCollector, routes);
    const signal = (id: string) => output.signals.find((s) => s.nodeId === `account_token:${id}`);
    expect(signal(tokenExample.id)).toEqual({
      nodeId: `account_token:${tokenExample.id}`,
      name: "last_used_on",
      value: Date.parse("2020-01-02T12:34:00Z"),
    });
    expect(signal(tokenDeploy.id)?.value).toBeNull();
    expect(output.signals).toHaveLength(TOKENS.length);
    // Volatile values stay out of props.
    expect(JSON.stringify(output.nodes)).not.toContain("last_used_on");
  });

  it("is deterministic", async () => {
    await expectDeterministic(tokensCollector, routes);
  });

  it("surfaces 403 as NoPermissionError", async () => {
    await expectNoPermission(tokensCollector, { [`${BASE}/tokens`]: denied() });
  });
});
