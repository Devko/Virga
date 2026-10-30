import { migrate } from "@virga/graph";
import { openNodeDatabase } from "@virga/graph/node";
import { describe, expect, it } from "vitest";
import { loadFixture, RULES, runRule } from "../src/index.ts";

const NOW = 1793232000000; // 2026-10-29

/** Fingerprints CF-003 returns for an active, never-expiring Workers Scripts Write token. */
async function run(ipCondition: unknown, params: Record<string, number> = {}) {
  return (await rows(ipCondition, params)).map((row) => row.fingerprint);
}

/** The rows CF-003 returns for that token. */
async function rows(ipCondition: unknown, params: Record<string, number> = {}) {
  const rule = RULES.find((r) => r.id === "CF-003");
  if (!rule) throw new Error("missing rule CF-003");
  const db = openNodeDatabase();
  try {
    migrate(db);
    await loadFixture(db, {
      rule: "CF-003",
      name: "r2-08",
      nodes: [
        {
          type: "account_token",
          id: "t1",
          name: "deploy",
          props: {
            status: "active",
            issued_on: "2026-01-01T00:00:00Z",
            modified_on: null,
            expires_on: null,
            not_before: null,
            ip_condition: ipCondition,
            policies: [
              {
                effect: "allow",
                permission_groups: [{ id: "pg-1", name: "Workers Scripts Write" }],
                resources: { "com.cloudflare.api.account.023e105f4ecef8ad9ca31a8372d0c353": "*" },
              },
            ],
          },
        },
      ],
      edges: [],
      expect: [],
    });
    return runRule(db, rule, { now_ms: NOW, ...params });
  } finally {
    db.close();
  }
}

const HIT = ["CF-003:account_token:t1"];

describe("R2-08: CF-003 counts an IP allow list only when it limits where a token works", () => {
  it("reports the review scenario: an allow list of 0.0.0.0/0 and ::/0", async () => {
    expect(await run(null)).toEqual(HIT);
    expect(await run({ in: ["0.0.0.0/0", "::/0"], not_in: [] })).toEqual(HIT);
  });

  it.each<[string, string[]]>([
    ["0.0.0.0/0 alone", ["0.0.0.0/0"]],
    ["::/0 next to a narrow IPv4 range", ["198.51.100.0/24", "::/0"]],
    ["a /0 written with another address", ["203.0.113.9/0"]],
    ["a /0 with spaces around it", [" 0.0.0.0/0 "]],
    ["IPv4 split into two halves", ["0.0.0.0/1", "128.0.0.0/1"]],
    ["an IPv4 range wider than /8", ["64.0.0.0/2"]],
    ["an IPv6 range wider than /32", ["2000::/3"]],
    ["IPv4-mapped IPv6 that covers all of IPv4", ["::ffff:0.0.0.0/96"]],
    ["an entry that is not an address", ["any"]],
    ["a prefix that is not a number", ["198.51.100.0/x"]],
    ["a prefix longer than the address", ["198.51.100.0/33"]],
  ])("R2-08: reports a token whose allow list holds %s", async (_, list) => {
    expect(await run({ in: list, not_in: [] })).toEqual(HIT);
  });

  it.each<[string, string[]]>([
    ["a /24 and a /32 IPv6 range", ["198.51.100.0/24", "2001:db8::/32"]],
    ["single addresses", ["198.51.100.7", "2001:db8::7"]],
    ["a /8", ["17.0.0.0/8"]],
    ["IPv4-mapped IPv6 of a /24", ["::ffff:198.51.100.0/120"]],
  ])("R2-08: does not report a token restricted to %s", async (_, list) => {
    expect(await run({ in: list, not_in: [] })).toEqual([]);
  });

  it("R2-08: takes the shortest prefixes that restrict from the rule parameters", async () => {
    const list = { in: ["17.0.0.0/8", "2001:db8::/32"], not_in: [] };
    expect(await run(list, { min_ipv4_prefix: 16 })).toEqual(HIT);
    expect(await run(list, { min_ipv6_prefix: 48 })).toEqual(HIT);
    expect(await run(list, { min_ipv4_prefix: 8, min_ipv6_prefix: 32 })).toEqual([]);
  });
});

describe("R4-06: CF-003 reads every spelling of an IPv4-mapped range", () => {
  it.each([
    // the spellings from the review
    "0:0:0:0:0:ffff:0:0/96",
    "::0:ffff:0:0/96",
    "0::ffff:0.0.0.0/96",
    "0000:0000:0000:0000:0000:ffff:0000:0000/96",
    // and a few more
    "0:0:0:0:0:ffff::/96",
    "::FFFF:0.0.0.0/96",
    "::ffff:0:0/080",
  ])("R4-06: reports a token whose allow list is the IPv4-mapped any-range %s", async (entry) => {
    expect(await run({ in: [entry], not_in: [] })).toEqual(HIT);
  });

  it.each([
    ["an IPv6 range that holds the IPv4-mapped block", "::/64"],
    ["a /88 around the IPv4-mapped block", "0:0:0:0:0:ff00::/88"],
    ["an IPv4-mapped range wider than /8", "0:0:0:0:0:ffff:4000:0/98"],
  ])("R4-06: reports a token whose allow list holds %s", async (_, entry) => {
    expect(await run({ in: [entry, "198.51.100.0/24"], not_in: [] })).toEqual(HIT);
  });

  it.each([
    ["an IPv4-mapped /24 written in hex", "0:0:0:0:0:ffff:c633:6400/120"],
    ["an IPv4-mapped /8 written in full", "0000:0000:0000:0000:0000:ffff:1100:0000/104"],
    ["an IPv6 /96 outside the IPv4-mapped block", "2001:db8::/96"],
    ["the NAT64 prefix", "64:ff9b::/96"],
    ["IPv4-compatible IPv6 at /96", "::0.0.0.0/96"],
    ["an IPv6 range next to the IPv4-mapped block", "::fffe:0:0/96"],
    ["an expanded IPv6 /48", "2001:0db8:0000:0000:0000:0000:0000:0000/48"],
    ["a single IPv6 address", "2001:db8::7"],
  ])("R4-06: does not report a token restricted to %s", async (_, entry) => {
    expect(await run({ in: [entry, "198.51.100.0/24"], not_in: [] })).toEqual([]);
  });

  it.each([
    ["two ::", "2001:db8::1::1/128"],
    ["nine groups", "1:2:3:4:5:6:7:8:9/128"],
    ["seven groups without ::", "1:2:3:4:5:6:7/128"],
    ["a group of five digits", "12345::/64"],
    ["three colons", "2001:db8:::1/128"],
    ["an IPv4 part of three octets", "::ffff:1.2.3/120"],
    ["an IPv4 part that is not last", "::ffff:1.2.3.4:5/120"],
    ["a hex digit glued to the IPv4 part", "::ffff:a1.2.3.4/120"],
    ["a zone", "fe80::1%eth0/128"],
    ["a quote", '2001:db8::"/48'],
    ["an octet above 255", "256.0.0.0/8"],
    ["five octets", "1.2.3.4.5/24"],
    ["an octet with a leading zero", "010.0.0.0/8"],
    ["an IPv4 address with a quote", '1.2.3.4"/24'],
  ])("R4-06: an entry with %s does not parse and limits nothing", async (_, entry) => {
    expect(await run({ in: [entry, "198.51.100.0/24"], not_in: [] })).toEqual(HIT);
  });

  it("R4-06: lists the entries that limit nothing as stored", async () => {
    const [row] = await rows({ in: ["0::ffff:0.0.0.0/96", "198.51.100.0/24"], not_in: [] });
    expect(JSON.parse(String(row?.wide_allowed_ips))).toEqual(["0::ffff:0.0.0.0/96"]);
  });
});
