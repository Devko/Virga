import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import {
  type BrokerApi,
  brokerTransport,
  CfApiError,
  createReader,
  isAllowedRead,
  NoPermissionError,
  RateLimitedError,
} from "@virga/cf-api";
import { describe, expect, it, vi } from "vitest";
import { loadMasterKey } from "../src/master-key.ts";
import type { RateBudget } from "../src/rate-budget.ts";
import { RECHECK_AFTER_MS, usableToken } from "../src/token-check.ts";
import {
  MAX_WAIT_MS,
  NO_TOKEN_CODE,
  RECHECK_FAILED_CODE,
  RECHECK_UNAVAILABLE_CODE,
} from "../src/upstream.ts";
import { getEntry, putToken } from "../src/vault.ts";
import {
  accountResource,
  detailsResult,
  INVENTORY_GROUPS,
  inDays,
  policy,
  TOKEN_ID,
  verifyResult,
} from "./fixtures/tokens.ts";
import {
  cfError,
  json,
  mockCloudflare,
  ok,
  type RecordedCall,
  type Route,
  TEST_TOKEN,
} from "./helpers.ts";

// RPC types turn the `unknown` in CfEnvelope into `never`; callers type the
// binding as BrokerApi, as brokerTransport expects.
const api = exports.ApiCaller as unknown as BrokerApi;
const reader = (accountId: string) => createReader(brokerTransport(api, accountId));

const HOUR = 60 * 60 * 1000;
const QUERY =
  "query ($accountTag: string!) { viewer { accounts(filter: { accountTag: $accountTag }) { workersInvocationsAdaptive(limit: 10) { sum { requests } } } } }";

/** A fresh account whose token last passed the write check `ago` ms before now. */
async function stored(ago: number): Promise<string> {
  const accountId = crypto.randomUUID().replaceAll("-", "");
  await putToken(env.VAULT, await loadMasterKey(env), {
    accountId,
    tokenId: TOKEN_ID,
    profile: "inventory",
    token: TEST_TOKEN,
    expiresOn: inDays(30),
    now: Date.now() - ago,
  });
  return accountId;
}

const verify = (id: string) => `GET /accounts/${id}/tokens/verify`;
const details = (id: string) => `GET /accounts/${id}/tokens/${TOKEN_ID}`;
const queues = (id: string) => `/accounts/${id}/queues`;

/** Cloudflare for one account: a passing write check, one REST read and GraphQL. */
function cloudflare(
  id: string,
  overrides: Record<string, unknown> = {},
  routes: Record<string, Route> = {},
) {
  return mockCloudflare({
    [verify(id)]: () => json(200, ok(verifyResult())),
    [details(id)]: () =>
      json(
        200,
        ok(
          detailsResult({
            policies: [policy(INVENTORY_GROUPS, accountResource(id))],
            ...overrides,
          }),
        ),
      ),
    [`GET ${queues(id)}`]: () => json(200, ok([])),
    "POST /graphql": () => json(200, { data: { viewer: { accounts: [] } }, errors: null }),
    ...routes,
  });
}

const sent = (calls: RecordedCall[]) =>
  calls.map((c) => `${c.method} ${c.url.pathname.slice("/client/v4".length)}`);

const budget = (id: string) => env.RATE_BUDGET.get(env.RATE_BUDGET.idFromName(id));

describe("TM-04: ApiCaller rechecks a token before use", () => {
  it("TM-04: serves a token checked less than 24 hours ago without a recheck", async () => {
    const id = await stored(RECHECK_AFTER_MS - HOUR);
    const before = await getEntry(env.VAULT, id);
    const { calls } = cloudflare(id);
    expect((await api.get(id, queues(id))).status).toBe(200);
    expect((await api.graphql(id, QUERY, { accountTag: id })).status).toBe(200);
    expect(sent(calls)).toEqual([`GET ${queues(id)}`, "POST /graphql"]);
    expect(await getEntry(env.VAULT, id)).toEqual(before);
  });

  it("TM-04: rechecks a token last checked 24 hours ago once, then serves calls", async () => {
    const id = await stored(RECHECK_AFTER_MS);
    const expiry = inDays(20);
    const { calls } = cloudflare(id, { expires_on: expiry });
    const started = Date.now();
    const response = await api.get(id, queues(id));
    expect(response).toMatchObject({ status: 200, body: { success: true, result: [] } });
    expect(sent(calls)).toEqual([verify(id), details(id), `GET ${queues(id)}`]);
    const entry = await getEntry(env.VAULT, id);
    expect(entry?.checkedAt).toBeGreaterThanOrEqual(started);
    expect(entry?.expiresOn).toBe(expiry);
    expect(entry?.recheckUntil).toBeNull();

    expect((await api.get(id, queues(id))).status).toBe(200);
    expect((await api.graphql(id, QUERY, { accountTag: id })).status).toBe(200);
    expect(sent(calls).slice(3)).toEqual([`GET ${queues(id)}`, "POST /graphql"]);
  });

  it("TM-04: rechecks before a GraphQL query too", async () => {
    const id = await stored(RECHECK_AFTER_MS + HOUR);
    const { calls } = cloudflare(id);
    expect((await api.graphql(id, QUERY, { accountTag: id })).status).toBe(200);
    expect(sent(calls)).toEqual([verify(id), details(id), "POST /graphql"]);
  });

  it("TM-04: rechecks a token whose check time lies in the future", async () => {
    const id = await stored(-HOUR);
    const { calls } = cloudflare(id);
    expect((await api.get(id, queues(id))).status).toBe(200);
    expect(sent(calls)).toEqual([verify(id), details(id), `GET ${queues(id)}`]);
    expect((await getEntry(env.VAULT, id))?.checkedAt).toBeLessThanOrEqual(Date.now());
  });
});

const noExpiry = (id: string): Record<string, Route> => ({
  [verify(id)]: () => json(200, ok(verifyResult({ expires_on: undefined }))),
});

describe("TM-04: a token that fails the recheck", () => {
  it("TM-04: deletes a token that gained a write group and fails the call with NoPermissionError", async () => {
    const id = await stored(RECHECK_AFTER_MS);
    const { calls } = cloudflare(id, {
      policies: [policy([...INVENTORY_GROUPS, "DNS Write"], accountResource(id))],
    });
    const response = await api.get(id, queues(id));
    expect(response.status).toBe(401);
    expect(response.body.success).toBe(false);
    expect(response.body.errors[0]?.code).toBe(RECHECK_FAILED_CODE);
    expect(response.body.errors[0]?.message).toContain("not_read_only");
    expect(response.body.errors[0]?.message).toContain("DNS Write can change the account");
    expect(sent(calls)).toEqual([verify(id), details(id)]);
    expect(await getEntry(env.VAULT, id)).toBeNull();

    // Core maps NoPermissionError to `no_permission` without retries.
    const error = await reader(id)
      .get(queues(id))
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(NoPermissionError);
    expect((await api.get(id, queues(id))).body.errors[0]?.code).toBe(NO_TOKEN_CODE);
    expect(sent(calls)).toHaveLength(2);
  });

  it("TM-04: fails a GraphQL query the same way", async () => {
    const id = await stored(RECHECK_AFTER_MS);
    const { calls } = cloudflare(id, {
      policies: [policy([...INVENTORY_GROUPS, "Workers Scripts Edit"], accountResource(id))],
    });
    const error = await reader(id)
      .graphql(QUERY, { accountTag: id })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(NoPermissionError);
    expect((error as NoPermissionError).status).toBe(401);
    expect(sent(calls)).toEqual([verify(id), details(id)]);
    expect(await getEntry(env.VAULT, id)).toBeNull();
  });

  it.each<[string, string, Record<string, unknown>, (id: string) => Record<string, Route>]>([
    ["has no expiry any more", "no_expiry", { expires_on: undefined }, (id) => noExpiry(id)],
    ["expires more than 90 days ahead", "expiry_too_far", { expires_on: inDays(120) }, () => ({})],
    ["was disabled", "not_active", { status: "disabled" }, () => ({})],
    [
      "was revoked",
      "verify_failed",
      {},
      (id) => ({ [verify(id)]: () => json(401, cfError(1000, "Invalid API Token")) }),
    ],
    [
      "lost Account API Tokens Read",
      "details_unavailable",
      {},
      (id) => ({ [details(id)]: () => json(403, cfError(9109, "Unauthorized")) }),
    ],
    [
      "now covers another account",
      "foreign_resource",
      {
        policies: [
          policy(INVENTORY_GROUPS, {
            ...accountResource("fedcba9876543210fedcba9876543210"),
            "com.cloudflare.api.account.0123456789abcdef0123456789abcdef": "*",
          }),
        ],
      },
      () => ({}),
    ],
  ])("TM-04: deletes a token that %s", async (_, code, overrides, routes) => {
    const id = await stored(RECHECK_AFTER_MS);
    const { calls } = cloudflare(id, overrides, routes(id));
    const response = await api.get(id, queues(id));
    expect(response.status).toBe(401);
    expect(response.body.errors[0]?.code).toBe(RECHECK_FAILED_CODE);
    expect(response.body.errors[0]?.message).toContain(code);
    expect(sent(calls)).not.toContain(`GET ${queues(id)}`);
    expect(await getEntry(env.VAULT, id)).toBeNull();
  });

  it("TM-04: deletes a token that now verifies as another token ID", async () => {
    const id = await stored(RECHECK_AFTER_MS);
    const other = "0123456789abcdef0123456789abcdef";
    const { calls } = cloudflare(
      id,
      {},
      {
        [verify(id)]: () => json(200, ok(verifyResult({ id: other }))),
        [`GET /accounts/${id}/tokens/${other}`]: () =>
          json(
            200,
            ok(
              detailsResult({
                id: other,
                policies: [policy(INVENTORY_GROUPS, accountResource(id))],
              }),
            ),
          ),
      },
    );
    const response = await api.get(id, queues(id));
    expect(response.body.errors[0]?.code).toBe(RECHECK_FAILED_CODE);
    expect(response.body.errors[0]?.message).toContain("token_mismatch");
    expect(sent(calls)).not.toContain(`GET ${queues(id)}`);
    expect(await getEntry(env.VAULT, id)).toBeNull();
  });
});

describe("TM-04: a recheck that cannot run", () => {
  it("TM-04: keeps the token and fails the call closed when Cloudflare is unreachable", async () => {
    const id = await stored(RECHECK_AFTER_MS);
    const before = await getEntry(env.VAULT, id);
    const { calls } = cloudflare(
      id,
      {},
      {
        [verify(id)]: () => {
          throw new TypeError("network down");
        },
      },
    );
    const response = await api.get(id, queues(id));
    expect(response.status).toBe(503);
    expect(response.body.errors[0]?.code).toBe(RECHECK_UNAVAILABLE_CODE);
    expect(response.body.errors[0]?.message).toContain("nothing was sent");
    expect(sent(calls)).toEqual([verify(id)]);
    // The token, its check time and its expiry stay as they were; no claim is left.
    expect(await getEntry(env.VAULT, id)).toEqual(before);

    // A retryable error for core, not a missing permission.
    const error = await reader(id)
      .get(queues(id))
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CfApiError);
    expect(error).not.toBeInstanceOf(NoPermissionError);
    expect((error as CfApiError).status).toBe(503);
    const graphql = await api.graphql(id, QUERY, { accountTag: id });
    expect(graphql.status).toBe(503);
    expect(sent(calls)).not.toContain("POST /graphql");

    // Once Cloudflare answers, the next call rechecks and is served.
    cloudflare(id);
    expect((await api.get(id, queues(id))).status).toBe(200);
    expect((await getEntry(env.VAULT, id))?.checkedAt).toBeGreaterThan(before?.checkedAt ?? 0);
  });

  it.each<[string, (id: string) => Record<string, Route>]>([
    ["a 5xx from the verify call", (id) => ({ [verify(id)]: () => json(503, cfError(1, "x")) })],
    ["a 5xx from the details call", (id) => ({ [details(id)]: () => json(500, cfError(1, "x")) })],
    [
      "a response that is not a v4 envelope",
      (id) => ({ [verify(id)]: () => new Response("<html>maintenance</html>", { status: 200 }) }),
    ],
  ])("TM-04: keeps the token and fails the call closed on %s", async (_, routes) => {
    const id = await stored(RECHECK_AFTER_MS);
    const before = await getEntry(env.VAULT, id);
    const { calls } = cloudflare(id, {}, routes(id));
    const response = await api.get(id, queues(id));
    expect(response.status).toBe(503);
    expect(response.body.errors[0]?.code).toBe(RECHECK_UNAVAILABLE_CODE);
    expect(sent(calls)).not.toContain(`GET ${queues(id)}`);
    expect(await getEntry(env.VAULT, id)).toEqual(before);
  });

  it("TM-04: answers 429 without calling Cloudflare when the rate budget blocks the recheck", async () => {
    const id = await stored(RECHECK_AFTER_MS);
    const before = await getEntry(env.VAULT, id);
    const { calls } = cloudflare(id);
    await runInDurableObject(budget(id), (instance: RateBudget) =>
      instance.ledger.blockUntil("rest", Date.now() + MAX_WAIT_MS + 60_000),
    );
    const response = await api.get(id, queues(id));
    expect(response.status).toBe(429);
    expect(response.body.errors[0]?.code).toBe(RECHECK_UNAVAILABLE_CODE);
    expect(response.retryAfter).toBeGreaterThan(60);
    expect(calls).toHaveLength(0);
    expect(await getEntry(env.VAULT, id)).toEqual(before);
    const error = await reader(id)
      .get(queues(id))
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(RateLimitedError);
    expect((error as RateLimitedError).retryAfter).toBeGreaterThan(60);
  });

  it("TM-04: answers 429 when Cloudflare rate-limits the recheck, and keeps the token", async () => {
    const id = await stored(RECHECK_AFTER_MS);
    const { calls } = cloudflare(
      id,
      {},
      {
        [verify(id)]: () => json(429, cfError(10000, "Rate limited"), { "retry-after": "120" }),
      },
    );
    const response = await api.get(id, queues(id));
    expect(response).toMatchObject({ status: 429, retryAfter: 120 });
    expect(response.body.errors[0]?.code).toBe(RECHECK_UNAVAILABLE_CODE);
    expect(sent(calls)).toEqual([verify(id)]);
    expect(await getEntry(env.VAULT, id)).not.toBeNull();
  });
});

describe("TM-04: one recheck per account at a time", () => {
  it("TM-04: parallel calls start one recheck", async () => {
    const id = await stored(RECHECK_AFTER_MS);
    const { calls } = cloudflare(
      id,
      {},
      {
        [verify(id)]: async () => {
          await scheduler.wait(100);
          return json(200, ok(verifyResult()));
        },
      },
    );
    const responses = await Promise.all([
      ...Array.from({ length: 5 }, () => api.get(id, queues(id))),
      api.graphql(id, QUERY, { accountTag: id }),
    ]);
    expect(responses.map((r) => r.status)).toEqual([200, 200, 200, 200, 200, 200]);
    const names = sent(calls);
    expect(names.filter((c) => c === verify(id))).toHaveLength(1);
    expect(names.filter((c) => c === details(id))).toHaveLength(1);
    expect(names.filter((c) => c === `GET ${queues(id)}`)).toHaveLength(5);
    expect(names.filter((c) => c === "POST /graphql")).toHaveLength(1);
  });

  it("TM-04: a call that waits for another call's recheck fails closed when it does not finish", async () => {
    const id = await stored(RECHECK_AFTER_MS);
    const { calls } = cloudflare(id);
    // Another call holds the claim and has not finished.
    await env.VAULT.prepare("UPDATE vault_tokens SET recheck_until = ? WHERE account_id = ?")
      .bind(Date.now() + 60_000, id)
      .run();
    const started = Date.now();
    const result = await usableToken(env, id, { waitMs: 300 });
    expect(result).toMatchObject({ ok: false, status: 503, code: RECHECK_UNAVAILABLE_CODE });
    expect(Date.now() - started).toBeGreaterThanOrEqual(250);
    expect(calls).toHaveLength(0);
    expect(await getEntry(env.VAULT, id)).not.toBeNull();
  });

  it("TM-04: a claim that lapsed does not block the recheck", async () => {
    const id = await stored(RECHECK_AFTER_MS);
    const { calls } = cloudflare(id);
    await env.VAULT.prepare("UPDATE vault_tokens SET recheck_until = ? WHERE account_id = ?")
      .bind(Date.now() - 1, id)
      .run();
    expect((await api.get(id, queues(id))).status).toBe(200);
    expect(sent(calls)).toEqual([verify(id), details(id), `GET ${queues(id)}`]);
    expect((await getEntry(env.VAULT, id))?.recheckUntil).toBeNull();
  });
});

describe("TM-04: the recheck goes through the allowlist and the rate budget", () => {
  it("TM-04: the recheck's calls are allowlisted reads and count against the rate budget", async () => {
    const id = await stored(RECHECK_AFTER_MS);
    const { calls } = cloudflare(id);
    expect((await api.get(id, queues(id))).status).toBe(200);
    expect(calls).toHaveLength(3);
    for (const call of calls) {
      expect(call.method).toBe("GET");
      expect(call.url.origin).toBe("https://api.cloudflare.com");
      expect(call.url.search).toBe("");
      expect(isAllowedRead("GET", call.url.pathname.slice("/client/v4".length))).toBe(true);
      expect(call.authorization).toBe(`Bearer ${TEST_TOKEN}`);
      expect(call.redirect).toBe("manual");
      expect(call.body).toBeNull();
    }
    const grants = await runInDurableObject(budget(id), (_: RateBudget, state) =>
      state.storage.sql
        .exec<{ n: number }>("SELECT count(*) AS n FROM grants WHERE kind = 'rest'")
        .one(),
    );
    expect(grants.n).toBe(3);
  });
});

describe("TM-04: the recheck never leaks the token", () => {
  it("TM-04: no token value in any error or log", async () => {
    const logs: unknown[][] = [];
    for (const level of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
        logs.push(args);
      });
    }
    const outputs: unknown[] = [];
    const recorded: RecordedCall[][] = [];
    const capture = async (run: () => Promise<unknown>) => {
      try {
        outputs.push(await run());
      } catch (error) {
        outputs.push(error);
      }
    };
    const scenario = async (routes: (id: string) => Record<string, Route>) => {
      const id = await stored(RECHECK_AFTER_MS);
      recorded.push(cloudflare(id, {}, routes(id)).calls);
      await capture(() => api.get(id, queues(id)));
      await capture(() => api.graphql(id, QUERY, { accountTag: id }));
      await capture(() => reader(id).get(queues(id)));
    };

    // A write group named after the Authorization header: reasons quote group names.
    await scenario((id) => ({
      [details(id)]: (call) =>
        json(
          200,
          ok(
            detailsResult({
              policies: [
                policy(
                  [...INVENTORY_GROUPS, `DNS Write ${call.authorization}`],
                  accountResource(id),
                ),
              ],
            }),
          ),
        ),
    }));
    await scenario((id) => ({
      [verify(id)]: () => json(401, cfError(1000, `Invalid API Token ${TEST_TOKEN}`)),
    }));
    await scenario((id) => ({
      [verify(id)]: () => {
        throw new TypeError(`connect failed for Bearer ${TEST_TOKEN}`);
      },
    }));
    await scenario((id) => ({
      [details(id)]: () => new Response(`<html>${TEST_TOKEN}</html>`, { status: 500 }),
    }));
    await scenario((id) => ({
      [verify(id)]: () => json(429, cfError(10000, TEST_TOKEN), { "retry-after": "1" }),
    }));

    const secret = TEST_TOKEN.slice("cfat_".length);
    expect(recorded.flat().some((c) => c.authorization === `Bearer ${TEST_TOKEN}`)).toBe(true);
    expect(outputs).toHaveLength(15);
    const text = (value: unknown) =>
      value instanceof Error
        ? `${value.name}: ${value.message}\n${value.stack ?? ""}`
        : (JSON.stringify(value) ?? String(value));
    const haystack = [...outputs.map(text), ...logs.flat().map(text)].join("\n");
    expect(haystack).toContain("[redacted]");
    expect(haystack).not.toContain(secret);
  });
});
