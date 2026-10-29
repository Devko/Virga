import { env, exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { getEntry } from "../src/vault.ts";
import {
  ACCOUNT_ID,
  detailsResult,
  INVENTORY_GROUPS,
  inDays,
  policy,
  TOKEN_ID,
  verifyResult,
} from "./fixtures/tokens.ts";
import { cfError, json, mockCloudflare, ok, type Route, TEST_TOKEN } from "./helpers.ts";

const RATELIMIT = { ratelimit: '"default";r=1199;t=1' };
const VERIFY = `GET /accounts/${ACCOUNT_ID}/tokens/verify`;
const DETAILS = `GET /accounts/${ACCOUNT_ID}/tokens/${TOKEN_ID}`;

function cloudflare(details: Record<string, unknown> = {}, overrides: Record<string, Route> = {}) {
  return mockCloudflare({
    [VERIFY]: () => json(200, ok(verifyResult()), RATELIMIT),
    [DETAILS]: () => json(200, ok(detailsResult(details)), RATELIMIT),
    ...overrides,
  });
}

const intake = exports.TokenIntake;

describe("TokenIntake.store", () => {
  beforeEach(async () => {
    await env.VAULT.exec("DELETE FROM vault_tokens");
  });

  it("verifies and stores a read-only token", async () => {
    const { calls } = cloudflare();
    const result = await intake.store(ACCOUNT_ID, TEST_TOKEN, "inventory");
    expect(result).toMatchObject({ ok: true, stored: true, tokenId: TOKEN_ID, reasons: [] });
    expect(result.permissionGroups).toEqual(INVENTORY_GROUPS);
    expect(calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual([
      `GET /client/v4/accounts/${ACCOUNT_ID}/tokens/verify`,
      `GET /client/v4/accounts/${ACCOUNT_ID}/tokens/${TOKEN_ID}`,
    ]);
    expect(calls.every((c) => c.authorization === `Bearer ${TEST_TOKEN}`)).toBe(true);
    expect(await getEntry(env.VAULT, ACCOUNT_ID)).toMatchObject({
      tokenId: TOKEN_ID,
      profile: "inventory",
    });
  });

  it("rejects a write-capable token and stores nothing", async () => {
    cloudflare({ policies: [policy([...INVENTORY_GROUPS, "Workers Scripts Write"])] });
    const result = await intake.store(ACCOUNT_ID, TEST_TOKEN, "inventory");
    expect(result).toMatchObject({ ok: false, stored: false });
    expect(result.reasons.map((r) => r.code)).toEqual(["not_read_only"]);
    expect(await getEntry(env.VAULT, ACCOUNT_ID)).toBeNull();
  });

  it("rejects a long-lived token and one without expiry", async () => {
    cloudflare({ expires_on: inDays(120) });
    const long = await intake.store(ACCOUNT_ID, TEST_TOKEN, "inventory");
    expect(long.reasons.map((r) => r.code)).toEqual(["expiry_too_far"]);

    cloudflare(
      { expires_on: undefined },
      { [VERIFY]: () => json(200, ok(verifyResult({ expires_on: undefined }))) },
    );
    const forever = await intake.store(ACCOUNT_ID, TEST_TOKEN, "inventory");
    expect(forever.reasons.map((r) => r.code)).toEqual(["no_expiry"]);
    expect(await getEntry(env.VAULT, ACCOUNT_ID)).toBeNull();
  });

  it("rejects a token that does not verify", async () => {
    const { calls } = cloudflare(
      {},
      { [VERIFY]: () => json(401, cfError(1000, "Invalid API Token")) },
    );
    const result = await intake.store(ACCOUNT_ID, TEST_TOKEN, "inventory");
    expect(result).toMatchObject({ ok: false, stored: false, retryable: false });
    expect(result.reasons[0]).toMatchObject({ code: "verify_failed" });
    expect(result.reasons[0]?.message).toContain("HTTP 401");
    expect(calls).toHaveLength(1);
  });

  it("rejects a token that cannot read its own policies", async () => {
    cloudflare(
      {},
      { [DETAILS]: () => json(403, cfError(9109, "Unauthorized to access requested resource")) },
    );
    const result = await intake.store(ACCOUNT_ID, TEST_TOKEN, "inventory");
    expect(result.reasons.map((r) => r.code)).toEqual(["details_unavailable"]);
    expect(result.reasons[0]?.message).toContain("Account API Tokens Read");
  });

  it("reports a Cloudflare outage as retryable", async () => {
    cloudflare({}, { [VERIFY]: () => json(503, cfError(1000, "unavailable")) });
    const result = await intake.store(ACCOUNT_ID, TEST_TOKEN, "inventory");
    expect(result).toMatchObject({ ok: false, stored: false, retryable: true });
  });

  it.each([
    ["a Global API Key", "cfk_0123456789abcdef0123456789abcdef01234567abcd"],
    ["a user token", "cfut_0123456789abcdef0123456789abcdef01234567abcd"],
    ["a Wrangler OAuth token", "cfoat_0123456789abcdef0123456789abcdef01234567abc"],
  ])("refuses %s without calling Cloudflare", async (_, token) => {
    const { calls } = cloudflare();
    const result = await intake.store(ACCOUNT_ID, token, "inventory");
    expect(result.reasons.map((r) => r.code)).toEqual(["not_account_token"]);
    expect(calls).toHaveLength(0);
  });

  it("validates its input without calling Cloudflare", async () => {
    const { calls } = cloudflare();
    const bad = [
      await intake.store("not-an-account", TEST_TOKEN, "inventory"),
      await intake.store(ACCOUNT_ID, "short", "inventory"),
      await intake.store(ACCOUNT_ID, `${TEST_TOKEN}\r\nX-Injected: 1`, "inventory"),
      await intake.store(ACCOUNT_ID, TEST_TOKEN, "admin" as "inventory"),
    ];
    expect(bad.map((r) => r.reasons[0]?.code)).toEqual([
      "invalid_input",
      "invalid_input",
      "invalid_input",
      "invalid_input",
    ]);
    expect(calls).toHaveLength(0);
  });
});

describe("TokenIntake.recheck and remove", () => {
  beforeEach(async () => {
    await env.VAULT.exec("DELETE FROM vault_tokens");
    cloudflare();
    expect((await intake.store(ACCOUNT_ID, TEST_TOKEN, "workload")).stored).toBe(true);
  });

  it("keeps a token that still passes and records the check", async () => {
    const before = await getEntry(env.VAULT, ACCOUNT_ID);
    const expiry = inDays(20);
    cloudflare({ expires_on: expiry });
    const result = await intake.recheck(ACCOUNT_ID);
    expect(result).toMatchObject({ ok: true, stored: true, removed: false });
    const after = await getEntry(env.VAULT, ACCOUNT_ID);
    expect(after?.expiresOn).toBe(expiry);
    expect(after?.checkedAt).toBeGreaterThanOrEqual(before?.checkedAt ?? 0);
    expect(after?.profile).toBe("workload");
  });

  it("deletes a token that gained a write permission", async () => {
    cloudflare({ policies: [policy([...INVENTORY_GROUPS, "DNS Write"])] });
    const result = await intake.recheck(ACCOUNT_ID);
    expect(result).toMatchObject({ ok: false, stored: false, removed: true });
    expect(await getEntry(env.VAULT, ACCOUNT_ID)).toBeNull();
  });

  it("deletes a token that was revoked", async () => {
    cloudflare({}, { [VERIFY]: () => json(401, cfError(1000, "Invalid API Token")) });
    expect(await intake.recheck(ACCOUNT_ID)).toMatchObject({ stored: false, removed: true });
  });

  it("keeps the token when the check cannot finish", async () => {
    cloudflare({}, { [DETAILS]: () => json(500, cfError(1000, "internal")) });
    const result = await intake.recheck(ACCOUNT_ID);
    expect(result).toMatchObject({ ok: false, stored: true, removed: false, retryable: true });
    expect(await getEntry(env.VAULT, ACCOUNT_ID)).not.toBeNull();
  });

  it("deletes a token whose ID changed", async () => {
    const other = "0123456789abcdef0123456789abcdef";
    cloudflare(
      { id: other },
      {
        [VERIFY]: () => json(200, ok(verifyResult({ id: other }))),
        [`GET /accounts/${ACCOUNT_ID}/tokens/${other}`]: () =>
          json(200, ok(detailsResult({ id: other }))),
      },
    );
    const result = await intake.recheck(ACCOUNT_ID);
    expect(result.reasons.map((r) => r.code)).toEqual(["token_mismatch"]);
    expect(result.removed).toBe(true);
  });

  it("removes a token", async () => {
    expect(await intake.remove(ACCOUNT_ID)).toEqual({ removed: true });
    expect(await intake.remove(ACCOUNT_ID)).toEqual({ removed: false });
    expect((await intake.recheck(ACCOUNT_ID)).reasons.map((r) => r.code)).toEqual(["not_found"]);
  });
});
