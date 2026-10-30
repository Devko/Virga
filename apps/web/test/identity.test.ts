import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// Core's own check, which every audit row passes (read only: core is not part of this Worker).
import { checkToolCall } from "../../core/src/audit.ts";
import { authenticate, isIdentity, MAX_IDENTITY } from "../src/auth.ts";
import { TEST_ACCESS, VIEWER } from "./config.ts";
import { call, captureLogs, claims, serveCerts, sign, signer, tokenFor } from "./helpers.ts";
import { audit, calls } from "./worker.ts";

beforeEach(async () => {
  serveCerts(await signer());
  calls.length = 0;
  audit.entries.length = 0;
});
afterEach(() => {
  vi.restoreAllMocks();
});

const codePoints = (from: number, to: number) =>
  Array.from({ length: to - from + 1 }, (_, i) => from + i);

// The characters core refuses in an identity, as R9-04 lists them: spaces, C0 and C1
// controls, U+00A0, U+200B to U+200F, U+2028 to U+202E, U+2066 to U+2069, U+FEFF.
const REFUSED = [
  ...codePoints(0x00, 0x20),
  ...codePoints(0x7f, 0xa0),
  ...codePoints(0x200b, 0x200f),
  ...codePoints(0x2028, 0x202e),
  ...codePoints(0x2066, 0x2069),
  0xfeff,
];
// Next to each range, and ordinary characters of an email or a client ID.
const ALLOWED = [
  0x21, 0x2e, 0x40, 0x7e, 0xa1, 0xe9, 0x200a, 0x2010, 0x2027, 0x202f, 0x2065, 0x206a, 0xfefe,
  0xff00, 0x1f600,
];

const around = (c: number) => `a${String.fromCodePoint(c)}b@example.com`;
const hex = (c: number) => `U+${c.toString(16).toUpperCase().padStart(4, "0")}`;

// Strings that are not well-formed Unicode (R10 hardening): a lone high or low
// surrogate at the start, in the middle, at the end and alone, and pairs in the
// wrong order. D1 stored one as U+FFFD in miniflare.
const LONE = [
  ...[0xd800, 0xdbff, 0xdc00, 0xdfff].flatMap((c) => {
    const s = String.fromCharCode(c);
    return [`${s}ab@example.com`, `a${s}b@example.com`, `ab@example.com${s}`, s];
  }),
  "a\udc00\ud800b@example.com",
  "a\ud800\ud800b@example.com",
  "a\ude00\ud83d@example.com",
];
// Surrogate pairs in the same places are characters (U+1F600, U+10000, U+10FFFF).
const PAIRED = ["\u{1f600}ab@example.com", "a\u{10000}b@example.com", "ab@example.com\u{10ffff}"];
// String.prototype.isWellFormed (ES2024): the runtime has it, the es2023 lib does not declare it.
const wellFormed = (s: string) => (s as unknown as { isWellFormed(): boolean }).isWellFormed();

/** Whether core's audit trail stores `identity`. */
function coreStores(identity: string): boolean {
  try {
    checkToolCall({
      identity,
      identityType: "email",
      channel: "api",
      action: "GET /api/me",
      accountId: null,
      outcome: "200",
    });
    return true;
  } catch (error) {
    expect((error as Error).message).toBe("invalid identity");
    return false;
  }
}

/** `/api/me` for a token whose `email`, or with `serviceToken` whose `common_name`, is `value`. */
async function me(value: string, serviceToken = false) {
  const extra = serviceToken ? { common_name: value } : {};
  const token = await sign(await signer(), claims(serviceToken ? null : value, extra));
  return call("/api/me", { token });
}

describe("identity rule (R9-04)", () => {
  it("is core's rule: the same answer for every case", () => {
    const cases = [
      ...REFUSED.map(around),
      ...ALLOWED.map(around),
      ...REFUSED.map((c) => String.fromCodePoint(c)),
      "",
      VIEWER,
      "e367826f93b8d71185e03fe518aff3b4.access",
      `${"a".repeat(MAX_IDENTITY - 12)}@example.com`,
      `${"a".repeat(MAX_IDENTITY - 11)}@example.com`,
      ...LONE,
      ...PAIRED,
    ];
    for (const value of cases) {
      expect(isIdentity(value), JSON.stringify(value)).toBe(coreStores(value));
    }
    expect(MAX_IDENTITY).toBe(320);
    for (const c of REFUSED) expect(isIdentity(around(c)), hex(c)).toBe(false);
    for (const c of ALLOWED) expect(isIdentity(around(c)), hex(c)).toBe(true);
  });

  it("R10 hardening: identity well-formed: refuses lone surrogates in each position, as core does", () => {
    for (const value of LONE) {
      expect(wellFormed(value), JSON.stringify(value)).toBe(false);
      expect(isIdentity(value), JSON.stringify(value)).toBe(false);
      expect(coreStores(value), JSON.stringify(value)).toBe(false);
    }
    for (const value of PAIRED) {
      expect(wellFormed(value), JSON.stringify(value)).toBe(true);
      expect(isIdentity(value), JSON.stringify(value)).toBe(true);
      expect(coreStores(value), JSON.stringify(value)).toBe(true);
    }
  });

  it("refuses an email core cannot store with 403, records nothing and logs only a reason", async () => {
    const logs = captureLogs();
    for (const email of [
      "a\u200bb@example.com",
      "a b@example.com",
      "x y@example.com",
      "a\u0000b@example.com",
      "a\u0009b@example.com",
      "a\u0085b@example.com",
      "a\u00a0b@example.com",
      "a\u2028b@example.com",
      "a\u202eb@example.com",
      "a\u2066b@example.com",
      "a\ufeffb@example.com",
      // Lone surrogates (R10 hardening), escaped in the token's JSON.
      "a\ud800b@example.com",
      "a\udfffb@example.com",
      // 321 characters, and 332 once lowercased (U+0130 becomes two code units).
      `${"a".repeat(309)}@example.com`,
      `${"\u0130".repeat(160)}@example.com`,
    ]) {
      const response = await me(email);
      expect(response.status, JSON.stringify(email)).toBe(403);
      expect(await response.json()).toEqual({ error: "forbidden" });
    }
    logs.restore();
    expect(audit.entries).toEqual([]);
    expect(calls).toEqual([]);
    expect(logs.text()).toContain("access: refused invalid_identity");
    expect(logs.text()).not.toContain("example.com");

    const request = new Request("https://virga.example.com/", {
      headers: { "Cf-Access-Jwt-Assertion": await tokenFor("a b@example.com") },
    });
    expect(await authenticate(request, TEST_ACCESS, {})).toEqual({
      ok: false,
      reason: "invalid_identity",
    });
  });

  it("refuses a service token client ID core cannot store, and an invalid email never falls back to it", async () => {
    expect((await me("e367826f93b8d71185e03fe518aff3b4 .access", true)).status).toBe(403);
    expect((await me("e".repeat(321), true)).status).toBe(403);
    const both = await sign(
      await signer(),
      claims("a b@example.com", { common_name: "e367826f93b8d71185e03fe518aff3b4.access" }),
    );
    expect((await call("/api/me", { token: both })).status).toBe(403);
    expect(audit.entries).toEqual([]);
  });

  it("still serves and records valid identities", async () => {
    const valid = await me("J\u00f6rg.M\u00fcller+virga@Example.com");
    expect(valid.status).toBe(200);
    expect(await valid.json()).toMatchObject({ email: "j\u00f6rg.m\u00fcller+virga@example.com" });
    const longest = `${"a".repeat(MAX_IDENTITY - 12)}@example.com`;
    expect((await me(longest)).status).toBe(200);
    const service = await me("e367826f93b8d71185e03fe518aff3b4.access", true);
    expect(await service.json()).toEqual({
      email: null,
      serviceToken: "e367826f93b8d71185e03fe518aff3b4.access",
      admin: false,
    });
    expect(audit.entries.map((e) => [e.identity, e.identityType])).toEqual([
      ["j\u00f6rg.m\u00fcller+virga@example.com", "email"],
      [longest, "email"],
      ["e367826f93b8d71185e03fe518aff3b4.access", "service_token"],
    ]);
    for (const entry of audit.entries) expect(coreStores(entry.identity)).toBe(true);
  });
});
