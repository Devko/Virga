import { describe, expect, it } from "vitest";
import { checkToken, classifyPermissionGroup, type IssueCode } from "../src/write-check.ts";
import {
  ACCOUNT_ID,
  accountResource,
  DAY,
  detailsResult,
  INVENTORY_GROUPS,
  inDays,
  OTHER_ACCOUNT_ID,
  policy,
  TOKEN_ID,
  verifyResult,
  ZONE_ID,
} from "./fixtures/tokens.ts";

const NOW = Date.parse("2026-10-29T12:00:00Z");

function check(details: Record<string, unknown> = {}, verify: Record<string, unknown> = {}) {
  return checkToken({
    accountId: ACCOUNT_ID,
    profile: "inventory",
    verify: verifyResult({ expires_on: inDays(30, NOW), ...verify }),
    details: detailsResult({ expires_on: inDays(30, NOW), ...details }),
    now: NOW,
  });
}

const codes = (result: { reasons: { code: IssueCode }[] }) => result.reasons.map((r) => r.code);

describe("permission group names", () => {
  it.each([
    ["Zone Read", "read"],
    ["Account API Tokens Read", "read"],
    ["Workers Metadata Read-Only", "read"],
    ["Pages Metadata Read", "read"],
    ["Account Security Center Insights", "read"],
    ["Zone Security Center Insights", "read"],
    ["Workers Scripts Write", "write"],
    ["Workers Scripts Edit", "write"],
    ["Workers Editor", "write"],
    ["Workers Platform Admin", "write"],
    ["Access: Apps and Policies Revoke", "write"],
    ["Cache Purge", "write"],
    ["Account Settings Write Read", "write"],
    ["Magic Network Monitoring", "unknown"],
    ["AI Gateway Run", "unknown"],
    ["Zero Trust Report", "unknown"],
    ["Zone Reader", "unknown"],
    ["", "unknown"],
  ])("%s is %s", (name, kind) => {
    expect(classifyPermissionGroup(name)).toBe(kind);
  });
});

describe("write check", () => {
  it("accepts a short-lived read-only token for this account", () => {
    const result = check();
    expect(result).toMatchObject({ ok: true, accountId: ACCOUNT_ID, tokenId: TOKEN_ID });
    expect(result.reasons).toEqual([]);
    expect(result.permissionGroups).toEqual(INVENTORY_GROUPS);
  });

  it.each([
    ["Workers Scripts Write"],
    ["Workers Scripts Edit"],
    ["Account Settings Write"],
    ["DNS Write"],
    ["Access: Organizations Revoke"],
    ["Cache Purge"],
    ["Magic Network Monitoring"],
  ])("rejects a token with %s", (name) => {
    const result = check({ policies: [policy([...INVENTORY_GROUPS, name])] });
    expect(result.ok).toBe(false);
    expect(codes(result)).toEqual(["not_read_only"]);
    expect(result.reasons[0]?.message).toContain(name);
  });

  it("rejects a write group in a second allow policy", () => {
    const result = check({
      policies: [
        policy(INVENTORY_GROUPS),
        policy(["Zone Settings Edit"], { [`com.cloudflare.api.account.zone.${ZONE_ID}`]: "*" }),
      ],
    });
    expect(codes(result)).toEqual(["not_read_only"]);
  });

  it("ignores write groups in deny policies", () => {
    const result = check({
      policies: [
        policy(INVENTORY_GROUPS),
        policy(["Workers Scripts Write"], accountResource(), "deny"),
      ],
    });
    expect(result.ok).toBe(true);
  });

  it("rejects a group without a name", () => {
    const groups = [{ id: "c8fed203ed3043cba015a93ad1616f1f" }];
    const result = check({
      policies: [{ ...policy(INVENTORY_GROUPS), permission_groups: groups }],
    });
    expect(codes(result)).toEqual(["not_read_only"]);
  });

  it("rejects a token without expiry", () => {
    expect(codes(check({ expires_on: undefined }, { expires_on: undefined }))).toEqual([
      "no_expiry",
    ]);
    expect(codes(check({ expires_on: "next week" }))).toEqual(["no_expiry"]);
  });

  it("rejects a token that lives longer than 90 days", () => {
    expect(codes(check({ expires_on: inDays(91, NOW) }))).toEqual(["expiry_too_far"]);
    expect(check({ expires_on: new Date(NOW + 90 * DAY).toISOString() }).ok).toBe(true);
  });

  it("rejects expired, disabled and not yet valid tokens", () => {
    expect(codes(check({ expires_on: inDays(-1, NOW) }))).toEqual(["expired"]);
    expect(codes(check({ status: "disabled" }, { status: "disabled" }))).toEqual(["not_active"]);
    expect(codes(check({}, { status: "expired" }))).toEqual(["not_active"]);
    expect(codes(check({ not_before: inDays(2, NOW) }))).toEqual(["not_yet_valid"]);
  });

  it("rejects a token whose policies do not include this account", () => {
    const zoneOnly = { [`com.cloudflare.api.account.zone.${ZONE_ID}`]: "*" };
    expect(codes(check({ policies: [policy(INVENTORY_GROUPS, zoneOnly)] }))).toEqual([
      "account_not_covered",
    ]);
    const other = accountResource(OTHER_ACCOUNT_ID);
    expect(codes(check({ policies: [policy(INVENTORY_GROUPS, other)] }))).toEqual([
      "foreign_resource",
      "account_not_covered",
    ]);
  });

  it.each([
    ["com.cloudflare.api.account.*"],
    ["com.cloudflare.api.account.zone.*"],
    [`com.cloudflare.api.account.${OTHER_ACCOUNT_ID}`],
    ["com.cloudflare.api.user.7c5dae5552338874e5053f2534d2767a"],
  ])("rejects the resource %s", (key) => {
    const resources = { ...accountResource(), [key]: "*" };
    expect(codes(check({ policies: [policy(INVENTORY_GROUPS, resources)] }))).toEqual([
      "foreign_resource",
    ]);
  });

  it("accepts all zones of this account and single zones", () => {
    const resources = {
      [`com.cloudflare.api.account.${ACCOUNT_ID}`]: { "com.cloudflare.api.account.zone.*": "*" },
      [`com.cloudflare.api.account.zone.${ZONE_ID}`]: "*",
    };
    expect(check({ policies: [policy(INVENTORY_GROUPS, resources)] }).ok).toBe(true);
  });

  it("rejects a token without allow policies", () => {
    expect(codes(check({ policies: [] }))).toEqual(["no_policies"]);
    expect(codes(check({ policies: undefined }))).toEqual(["no_policies"]);
  });

  it("rejects details of another token and a missing token ID", () => {
    expect(codes(check({ id: "0".repeat(32) }))).toEqual(["token_mismatch"]);
    expect(codes(check({}, { id: undefined }))).toEqual(["verify_failed"]);
    expect(codes(check({}, { id: "../../x" }))).toEqual(["verify_failed"]);
  });

  it("collects every reason", () => {
    const result = check({
      expires_on: inDays(365, NOW),
      policies: [policy(["Workers Scripts Write", "DNS Read"], accountResource(OTHER_ACCOUNT_ID))],
    });
    expect(codes(result)).toEqual([
      "expiry_too_far",
      "not_read_only",
      "foreign_resource",
      "account_not_covered",
    ]);
  });

  it("warns when the inventory profile reaches code or data", () => {
    const groups = [...INVENTORY_GROUPS, "Workers Scripts Read", "D1 Read"];
    const inventory = check({ policies: [policy(groups)] });
    expect(inventory.ok).toBe(true);
    expect(inventory.warnings.map((w) => w.code)).toEqual(["reaches_content", "reaches_content"]);
    const workload = checkToken({
      accountId: ACCOUNT_ID,
      profile: "workload",
      verify: verifyResult({ expires_on: inDays(30, NOW) }),
      details: detailsResult({ expires_on: inDays(30, NOW), policies: [policy(groups)] }),
      now: NOW,
    });
    expect(workload.warnings).toEqual([]);
  });
});
