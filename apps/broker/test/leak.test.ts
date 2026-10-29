import { env, exports } from "cloudflare:workers";
import { type BrokerApi, brokerTransport, createReader } from "@virga/cf-api";
import { describe, expect, it, vi } from "vitest";
import {
  ACCOUNT_ID,
  detailsResult,
  INVENTORY_GROUPS,
  policy,
  TOKEN_ID,
  verifyResult,
} from "./fixtures/tokens.ts";
import { cfError, json, mockCloudflare, ok, type RecordedCall, TEST_TOKEN } from "./helpers.ts";

const SECRET_PART = TEST_TOKEN.slice("cfat_".length);

function text(value: unknown): string {
  if (value instanceof Error) return `${value.name}: ${value.message}\n${value.stack ?? ""}`;
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

describe("the token never leaves the broker", () => {
  it("does not appear in responses, errors or logs", async () => {
    const logs: unknown[][] = [];
    for (const level of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
        logs.push(args);
      });
    }
    const outputs: unknown[] = [];
    const capture = async (run: () => Promise<unknown>) => {
      try {
        outputs.push(await run());
      } catch (error) {
        outputs.push(error);
      }
    };

    const verify = `GET /accounts/${ACCOUNT_ID}/tokens/verify`;
    const details = `GET /accounts/${ACCOUNT_ID}/tokens/${TOKEN_ID}`;
    // Responses that echo the token, as a buggy or hostile upstream might.
    const echo = (call: RecordedCall) =>
      json(200, ok({ ...detailsResult(), name: call.authorization }));
    const recorded: RecordedCall[][] = [];
    const routes = (overrides = {}) => {
      const { calls } = mockCloudflare({
        [verify]: () => json(200, ok(verifyResult())),
        [details]: echo,
        "POST /graphql": (call) =>
          json(200, {
            data: { echo: call.authorization },
            errors: [{ message: `bad token ${call.authorization}` }],
          }),
        ...overrides,
      });
      recorded.push(calls);
    };

    const intake = exports.TokenIntake;
    const api = exports.ApiCaller as unknown as BrokerApi;
    const reader = createReader(brokerTransport(api, ACCOUNT_ID));

    routes({
      [details]: () =>
        json(200, ok(detailsResult({ policies: [policy([...INVENTORY_GROUPS, "DNS Write"])] }))),
    });
    await capture(() => intake.store(ACCOUNT_ID, TEST_TOKEN, "inventory"));
    routes({ [verify]: () => json(401, cfError(1000, `Invalid API Token ${TEST_TOKEN}`)) });
    await capture(() => intake.store(ACCOUNT_ID, TEST_TOKEN, "inventory"));
    await capture(() => intake.store(ACCOUNT_ID, `${TEST_TOKEN}\n`, "inventory"));
    routes();
    await capture(() => intake.store(ACCOUNT_ID, TEST_TOKEN, "inventory"));
    expect(outputs.at(-1)).toMatchObject({ stored: true });
    await capture(() => intake.recheck(ACCOUNT_ID));

    routes();
    await capture(() => api.get(ACCOUNT_ID, `/accounts/${ACCOUNT_ID}/tokens/${TOKEN_ID}`));
    await capture(() => reader.get(`/accounts/${ACCOUNT_ID}/tokens/${TOKEN_ID}`));
    await capture(() => api.get(ACCOUNT_ID, `/accounts/${ACCOUNT_ID}/workers/scripts`));
    await capture(() => reader.get(`/accounts/${ACCOUNT_ID}/workers/scripts`));
    await capture(() => api.graphql(ACCOUNT_ID, "{ viewer { echo } }"));
    await capture(() => reader.graphql("{ viewer { echo } }"));
    await capture(() => api.graphql(ACCOUNT_ID, "mutation { x }"));
    routes({
      [verify]: () => {
        throw new TypeError(`connect failed for Bearer ${TEST_TOKEN}`);
      },
      [details]: () => new Response(`<html>${TEST_TOKEN}</html>`, { status: 500 }),
    });
    await capture(() => api.get(ACCOUNT_ID, `/accounts/${ACCOUNT_ID}/tokens/verify`));
    await capture(() => reader.get(`/accounts/${ACCOUNT_ID}/tokens/${TOKEN_ID}`));
    await capture(() => intake.recheck(ACCOUNT_ID));
    routes({ [details]: () => json(429, cfError(10000, TEST_TOKEN), { "retry-after": "1" }) });
    await capture(() => reader.get(`/accounts/${ACCOUNT_ID}/tokens/${TOKEN_ID}`));
    await capture(() => api.get(ACCOUNT_ID, `/accounts/${ACCOUNT_ID}/tokens/${TOKEN_ID}`));

    // A tampered vault row fails closed without describing the token.
    await env.VAULT.exec("UPDATE vault_tokens SET token_iv = zeroblob(12)");
    await capture(() => api.get(ACCOUNT_ID, `/accounts/${ACCOUNT_ID}/tokens/verify`));
    await capture(() => intake.recheck(ACCOUNT_ID));
    await capture(() => intake.remove(ACCOUNT_ID));

    // The token did go to Cloudflare and came back in bodies and errors, so
    // the search below is not vacuous.
    const sent = recorded.flat();
    expect(sent.some((c) => c.authorization === `Bearer ${TEST_TOKEN}`)).toBe(true);
    expect(outputs).toHaveLength(20);
    const haystack = [...outputs.map(text), ...logs.flat().map(text)].join("\n");
    expect(haystack).toContain("[redacted]");
    expect(haystack).not.toContain(SECRET_PART);
    const { results } = await env.VAULT.prepare("SELECT * FROM vault_tokens").all();
    expect(text(results)).not.toContain(SECRET_PART);
  });
});
