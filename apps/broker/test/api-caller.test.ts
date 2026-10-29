import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import {
  type BrokerApi,
  brokerTransport,
  CfApiError,
  createReader,
  NOT_ALLOWED_CODE,
  NoPermissionError,
  NotAllowedError,
  RateLimitedError,
} from "@virga/cf-api";
import { describe, expect, it } from "vitest";
import { loadMasterKey } from "../src/master-key.ts";
import type { RateBudget } from "../src/rate-budget.ts";
import { BUDGET_EXHAUSTED_CODE, MAX_WAIT_MS, NO_TOKEN_CODE } from "../src/upstream.ts";
import { putToken } from "../src/vault.ts";
import { detailsResult, inDays, TOKEN_ID, verifyResult } from "./fixtures/tokens.ts";
import { cfError, json, mockCloudflare, ok, TEST_TOKEN } from "./helpers.ts";

// RPC types turn the `unknown` in CfEnvelope into `never`; callers type the
// binding as BrokerApi, as brokerTransport expects.
const api = exports.ApiCaller as unknown as BrokerApi;

/** A fresh account with a stored token, so budget state does not leak between tests. */
async function account(): Promise<string> {
  const accountId = crypto.randomUUID().replaceAll("-", "");
  await putToken(env.VAULT, await loadMasterKey(env), {
    accountId,
    tokenId: TOKEN_ID,
    profile: "inventory",
    token: TEST_TOKEN,
    expiresOn: inDays(30),
    now: Date.now(),
  });
  return accountId;
}

const detailsPath = (accountId: string) => `/accounts/${accountId}/tokens/${TOKEN_ID}`;
const verifyPath = (accountId: string) => `/accounts/${accountId}/tokens/verify`;

describe("ApiCaller.get", () => {
  it("sends an allowlisted read with the account's token", async () => {
    const id = await account();
    const { calls } = mockCloudflare({
      [`GET ${detailsPath(id)}`]: () =>
        json(200, ok(detailsResult()), { ratelimit: '"default";r=1187;t=12' }),
    });
    const response = await api.get(id, detailsPath(id), {
      page: 2,
      per_page: 50,
      "name.contains": "a b&c",
      flag: true,
      skip: undefined,
    });
    expect(response).toMatchObject({ status: 200, rateRemaining: 1187 });
    expect(response.body).toMatchObject({ success: true, result: { id: TOKEN_ID } });
    expect(calls).toHaveLength(1);
    const [call] = calls;
    expect(call?.method).toBe("GET");
    expect(call?.url.origin).toBe("https://api.cloudflare.com");
    expect(call?.url.pathname).toBe(`/client/v4${detailsPath(id)}`);
    expect([...(call?.url.searchParams ?? [])]).toEqual([
      ["page", "2"],
      ["per_page", "50"],
      ["name.contains", "a b&c"],
      ["flag", "true"],
    ]);
    expect(call?.authorization).toBe(`Bearer ${TEST_TOKEN}`);
    expect(call?.redirect).toBe("manual");
  });

  it("works as a transport for the reader", async () => {
    const id = await account();
    mockCloudflare({ [`GET ${verifyPath(id)}`]: () => json(200, ok(verifyResult())) });
    const reader = createReader(brokerTransport(api, id));
    expect(await reader.get(verifyPath(id))).toMatchObject({ id: TOKEN_ID, status: "active" });
  });

  it("refuses paths off the allowlist without calling Cloudflare", async () => {
    const id = await account();
    const { calls } = mockCloudflare({});
    const paths = [
      `/accounts/${id}/workers/scripts`,
      `/accounts/${id}/tokens`,
      `/accounts/${id}/tokens/verify/extra`,
      `/accounts/${id}/tokens/../tokens/verify`,
      `/accounts/${id}/tokens/%2e%2e`,
      `/accounts/${id}/tokens/verify?x=1`,
      `/accounts/${id}//tokens/verify`,
      `accounts/${id}/tokens/verify`,
      "https://example.com/accounts/x/tokens/verify",
      "/graphql",
      "/user/tokens/verify",
      "",
    ];
    for (const path of paths) {
      const response = await api.get(id, path);
      expect(response.status, path).toBe(400);
      expect(response.body.errors[0]?.code, path).toBe(NOT_ALLOWED_CODE);
    }
    await expect(createReader(brokerTransport(api, id)).get(paths[0] ?? "")).rejects.toThrow(
      NotAllowedError,
    );
    expect(calls).toHaveLength(0);
  });

  it("refuses paths of another account", async () => {
    const id = await account();
    const other = await account();
    const { calls } = mockCloudflare({});
    const response = await api.get(id, verifyPath(other));
    expect(response.status).toBe(400);
    expect(response.body.errors[0]?.code).toBe(NOT_ALLOWED_CODE);
    expect(response.body.errors[0]?.message).toContain("not scoped to account");
    expect(calls).toHaveLength(0);
  });

  it("refuses invalid account IDs and query parameters", async () => {
    const id = await account();
    const { calls } = mockCloudflare({});
    const refused = [
      await api.get("../x", verifyPath(id)),
      await api.get(id.toUpperCase(), verifyPath(id.toUpperCase())),
      await api.get(id, verifyPath(id), { "a&b": "1" }),
      await api.get(id, verifyPath(id), { a: "x".repeat(2000) }),
      await api.get(id, verifyPath(id), { a: Number.NaN }),
    ];
    for (const response of refused) {
      expect(response.body.errors[0]?.code).toBe(NOT_ALLOWED_CODE);
    }
    expect(calls).toHaveLength(0);
  });

  it("answers 401 for an account without a token", async () => {
    const id = crypto.randomUUID().replaceAll("-", "");
    const { calls } = mockCloudflare({});
    const response = await api.get(id, verifyPath(id));
    expect(response.status).toBe(401);
    expect(response.body.errors[0]?.code).toBe(NO_TOKEN_CODE);
    expect(calls).toHaveLength(0);
  });

  it("passes Cloudflare errors through", async () => {
    const id = await account();
    mockCloudflare({
      [`GET ${detailsPath(id)}`]: () =>
        json(403, cfError(9109, "Unauthorized to access requested resource")),
    });
    const response = await api.get(id, detailsPath(id));
    expect(response.status).toBe(403);
    expect(response.body.errors).toEqual([
      { code: 9109, message: "Unauthorized to access requested resource" },
    ]);
    await expect(createReader(brokerTransport(api, id)).get(detailsPath(id))).rejects.toThrow(
      NoPermissionError,
    );
  });

  it("does not follow redirects and wraps non-JSON responses", async () => {
    const id = await account();
    mockCloudflare({
      [`GET ${detailsPath(id)}`]: () =>
        new Response(null, { status: 302, headers: { location: "https://example.com/" } }),
      [`GET ${verifyPath(id)}`]: () => new Response("<html>oops</html>", { status: 200 }),
    });
    const redirect = await api.get(id, detailsPath(id));
    expect(redirect.status).toBe(302);
    expect(redirect.body.success).toBe(false);
    const html = await api.get(id, verifyPath(id));
    expect(html.body).toMatchObject({ success: false, result: null });
    expect(html.body.errors[0]?.message).toContain("non-JSON");
    await expect(createReader(brokerTransport(api, id)).get(verifyPath(id))).rejects.toThrow(
      CfApiError,
    );
  });

  it("answers 502 when Cloudflare is unreachable", async () => {
    const id = await account();
    mockCloudflare({
      [`GET ${verifyPath(id)}`]: () => {
        throw new TypeError("network down");
      },
    });
    const response = await api.get(id, verifyPath(id));
    expect(response.status).toBe(502);
  });
});

describe("ApiCaller and the rate budget", () => {
  const budget = (id: string) => env.RATE_BUDGET.get(env.RATE_BUDGET.idFromName(id));

  it("blocks after a 429 and answers 429 without calling Cloudflare", async () => {
    const id = await account();
    const { calls } = mockCloudflare({
      [`GET ${verifyPath(id)}`]: () =>
        json(429, cfError(10000, "Rate limited"), { "retry-after": "120" }),
    });
    const first = await api.get(id, verifyPath(id));
    expect(first).toMatchObject({ status: 429, retryAfter: 120 });
    const second = await api.get(id, verifyPath(id));
    expect(second.status).toBe(429);
    expect(second.body.errors[0]?.code).toBe(BUDGET_EXHAUSTED_CODE);
    expect(second.retryAfter).toBeGreaterThan(100);
    expect(calls).toHaveLength(1);
    const error = await createReader(brokerTransport(api, id))
      .get(verifyPath(id))
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RateLimitedError);
    expect((error as RateLimitedError).retryAfter).toBeGreaterThan(100);
  });

  it("stops before the quota in the Ratelimit header runs out", async () => {
    const id = await account();
    const { calls } = mockCloudflare({
      [`GET ${verifyPath(id)}`]: () =>
        json(200, ok(verifyResult()), { ratelimit: '"default";r=121;t=200' }),
    });
    expect((await api.get(id, verifyPath(id))).rateRemaining).toBe(121);
    const paused = await api.get(id, verifyPath(id));
    expect(paused.status).toBe(429);
    expect(paused.body.errors[0]?.code).toBe(BUDGET_EXHAUSTED_CODE);
    expect(calls).toHaveLength(1);
  });

  it("waits out a short pause, then sends", async () => {
    const id = await account();
    const { calls } = mockCloudflare({
      [`GET ${verifyPath(id)}`]: () => json(200, ok(verifyResult())),
    });
    await runInDurableObject(budget(id), (instance: RateBudget) =>
      instance.ledger.blockUntil("rest", Date.now() + 200),
    );
    const started = Date.now();
    const response = await api.get(id, verifyPath(id));
    expect(response.status).toBe(200);
    expect(Date.now() - started).toBeGreaterThanOrEqual(150);
    expect(calls).toHaveLength(1);
  });

  it("does not wait longer than the limit", async () => {
    const id = await account();
    const { calls } = mockCloudflare({});
    await runInDurableObject(budget(id), (instance: RateBudget) =>
      instance.ledger.blockUntil("rest", Date.now() + MAX_WAIT_MS + 10_000),
    );
    const started = Date.now();
    const response = await api.get(id, verifyPath(id));
    expect(response.status).toBe(429);
    expect(Date.now() - started).toBeLessThan(1000);
    expect(calls).toHaveLength(0);
  });
});

describe("ApiCaller.graphql", () => {
  const QUERY =
    "query ($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { workersInvocationsAdaptive(limit: 10) { sum { requests } } } } }";

  it("posts a query and returns data and errors", async () => {
    const id = await account();
    const { calls } = mockCloudflare({
      "POST /graphql": () =>
        json(200, {
          data: { viewer: { accounts: [] } },
          errors: [
            {
              message: "cannot request data older than 2678400s",
              path: ["viewer", "accounts", 0, "workersInvocationsAdaptive"],
              extensions: { timestamp: "2026-10-29T12:00:00Z" },
            },
          ],
        }),
    });
    const response = await api.graphql(id, QUERY, { accountTag: id });
    expect(response).toEqual({
      status: 200,
      data: { viewer: { accounts: [] } },
      errors: [
        {
          message: "cannot request data older than 2678400s",
          path: ["viewer", "accounts", 0, "workersInvocationsAdaptive"],
        },
      ],
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.authorization).toBe(`Bearer ${TEST_TOKEN}`);
    expect(JSON.parse(calls[0]?.body ?? "")).toEqual({
      query: QUERY,
      variables: { accountTag: id },
    });
  });

  it("refuses mutations and subscriptions without calling Cloudflare", async () => {
    const id = await account();
    const { calls } = mockCloudflare({});
    for (const query of [
      "mutation { deleteEverything }",
      "subscription { events { id } }",
      "query { a } mutation { b }",
      "",
    ]) {
      const response = await api.graphql(id, query);
      expect(response.status, query).toBe(400);
      expect(response.errors?.[0]?.message, query).toContain("not on the read allowlist");
    }
    const notObject = await api.graphql(id, QUERY, [] as unknown as Record<string, unknown>);
    expect(notObject.status).toBe(400);
    expect(calls).toHaveLength(0);
  });

  it("blocks GraphQL after a GraphQL 429 but keeps REST open", async () => {
    const id = await account();
    const { calls } = mockCloudflare({
      "POST /graphql": () =>
        json(429, {
          data: null,
          errors: [{ message: "rate limiter budget depleted, try again after 5 minutes" }],
        }),
      [`GET ${verifyPath(id)}`]: () => json(200, ok(verifyResult())),
    });
    expect((await api.graphql(id, QUERY, { accountTag: id })).status).toBe(429);
    const blocked = await api.graphql(id, QUERY, { accountTag: id });
    expect(blocked.status).toBe(429);
    expect(blocked.errors?.[0]?.message).toContain("not sent to Cloudflare");
    expect((await api.get(id, verifyPath(id))).status).toBe(200);
    expect(calls.map((c) => c.method)).toEqual(["POST", "GET"]);
    await expect(
      createReader(brokerTransport(api, id)).graphql(QUERY, { accountTag: id }),
    ).rejects.toThrow(RateLimitedError);
  });
});

describe("default export", () => {
  it("answers 404 to every request", async () => {
    const response = await exports.default.fetch("https://virga-broker.example/anything");
    expect(response.status).toBe(404);
  });
});
