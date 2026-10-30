import { describe, expect, it } from "vitest";
import { canonicalCidr, tokensCollector } from "../../src/identity/tokens.ts";
import { tokenDeploy, tokensRoute } from "./fixtures/tokens.ts";
import { BASE, node, run } from "./helpers.ts";

const MAPPED_ANY = "::ffff:0.0.0.0/96";

describe("R4-06: canonical CIDRs in ip_condition", () => {
  it.each([
    "::ffff:0.0.0.0/96",
    "::ffff:0:0/96",
    "0:0:0:0:0:ffff:0:0/96",
    "::0:ffff:0:0/96",
    "0::ffff:0.0.0.0/96",
    "0000:0000:0000:0000:0000:ffff:0000:0000/96",
    "::FFFF:0:0/96",
    " ::ffff:0:0/096 ",
  ])("R4-06: writes the IPv4-mapped any-range %s as ::ffff:0.0.0.0/96", (spelling) => {
    expect(canonicalCidr(spelling)).toBe(MAPPED_ANY);
  });

  it.each([
    // RFC 5952: lower case, no leading zeros, the longest run of zero groups as ::
    ["2001:DB8::/32", "2001:db8::/32"],
    ["2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"],
    ["2001:db8::0:1", "2001:db8::1"],
    ["2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"],
    ["2001:0:0:1:0:0:0:1", "2001:0:0:1::1"],
    ["2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"],
    ["2001:db8:1:1:1:1:1::", "2001:db8:1:1:1:1:1:0"],
    ["0:0:0:0:0:0:0:0/0", "::/0"],
    ["::", "::"],
    ["1::", "1::"],
    ["0:0:0:0:0:0:0:1/128", "::1/128"],
    ["FE80:0:0:0:0:0:0:1/64", "fe80::1/64"],
    // IPv4-mapped addresses keep the IPv4 part as a dotted quad
    ["::ffff:c000:0201", "::ffff:192.0.2.1"],
    ["::ffff:198.51.100.0/120", "::ffff:198.51.100.0/120"],
    ["0:0:0:0:0:ffff:0:0/80", "::ffff:0.0.0.0/80"],
    // only IPv4-mapped addresses: an IPv4-compatible one is plain IPv6
    ["::1.2.3.4", "::102:304"],
    ["64:ff9b::198.51.100.7/128", "64:ff9b::c633:6407/128"],
  ])("R4-06: writes IPv6 %s as %s", (spelling, canonical) => {
    expect(canonicalCidr(spelling)).toBe(canonical);
  });

  it.each([
    [" 0.0.0.0/0 ", "0.0.0.0/0"],
    ["198.51.100.7", "198.51.100.7"],
    ["203.0.113.9/0", "203.0.113.9/0"],
    ["123.123.123.100/24", "123.123.123.100/24"],
    ["10.0.0.0/08", "10.0.0.0/8"],
  ])("R4-06: writes IPv4 %s as %s", (spelling, canonical) => {
    expect(canonicalCidr(spelling)).toBe(canonical);
  });

  it.each([
    "any",
    "198.51.100.0/33",
    "198.51.100.0/x",
    "198.51.100.0/",
    "198.51.100/24",
    "010.0.0.0/8",
    "256.0.0.0/8",
    "2001:db8::/129",
    "1:2:3:4:5:6:7:8:9",
    "1:2:3:4:5:6:7",
    "2001:db8::1::1",
    "2001:db8:::1",
    ":1:2:3:4:5:6:7",
    "1:2:3:4:5:6:7:",
    "12345::",
    "::ffff:1.2.3",
    "::ffff:1.2.3.4:5",
    "fe80::1%eth0",
    "0.0.0.0/0/0",
  ])("R4-06: keeps %s as given, because it does not parse", (spelling) => {
    expect(canonicalCidr(spelling)).toBe(spelling);
  });

  it("R4-06: cuts an entry that does not parse, so it cannot parse afterwards either", () => {
    expect(canonicalCidr(` ${"x".repeat(100)} `)).toBe(`${"x".repeat(64)}…`);
    expect(canonicalCidr(`0.0.0.0/0${" ".repeat(10)}#${"x".repeat(80)}`)).toMatch(/…$/);
  });

  it("R4-06: emits each list canonical, deduplicated and sorted", async () => {
    const token = {
      ...tokenDeploy,
      condition: {
        request_ip: {
          in: [
            "0:0:0:0:0:ffff:0:0/96",
            "::0:ffff:0:0/96",
            "0::ffff:0.0.0.0/96",
            "0000:0000:0000:0000:0000:ffff:0000:0000/96",
            "198.51.100.0/24",
            "2001:DB8:0:0:0:0:0:0/32",
          ],
          not_in: ["2001:db8:0:0:0:0:0:1", 7, "not a cidr"],
        },
      },
    };
    const { output } = await run(tokensCollector, { [`${BASE}/tokens`]: tokensRoute([token]) });
    expect(node(output, `account_token:${token.id}`).props?.ip_condition).toEqual({
      in: ["198.51.100.0/24", "2001:db8::/32", MAPPED_ANY],
      // An entry that is not a string stays visible as "", which never parses.
      not_in: ["", "2001:db8::1", "not a cidr"],
    });
  });
});
