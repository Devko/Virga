// Host semantics from
// https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/#wildcards
// https://developers.cloudflare.com/workers/configuration/routing/routes/#matching-behavior
import { describe, expect, it } from "vitest";
import { hostSpecificity, parseHost, relateHost } from "../src/hosts.ts";

const pattern = (text: string, multiLevel = false) => {
  const host = parseHost(text, multiLevel);
  if (!host) throw new Error(text);
  return host;
};

describe("parseHost", () => {
  it.each([
    ["App.Example.com", "app.example.com"],
    ["example.com.", "example.com"],
    ["example.com:8443", "example.com"],
    ["*.example.com", "*.example.com"],
    ["*test.example.com", "*test.example.com"],
  ])("%s -> %s", (input, expected) => {
    expect(parseHost(input)?.labels.join(".")).toBe(expected);
  });

  it.each([[""], ["not a host"], ["a..b"], ["foo*bar*baz.example.com"], [42]])(
    "rejects %j",
    (input) => {
      expect(parseHost(input)).toBeNull();
    },
  );

  it("needs a leading * label for any-depth patterns", () => {
    expect(parseHost("*.example.com", true)?.multiLevel).toBe(true);
    expect(parseHost("example.com", true)).toBeNull();
  });
});

describe("relateHost", () => {
  it.each([
    ["app.example.com", "app.example.com", false, "covers"],
    ["*.example.com", "app.example.com", false, "covers"],
    ["*.example.com", "example.com", false, "disjoint"],
    ["*.example.com", "a.b.example.com", false, "disjoint"],
    ["*test.example.com", "test.example.com", false, "covers"],
    ["*test.example.com", "alphatest.example.com", false, "covers"],
    ["*test.example.com", "beta.test.example.com", false, "disjoint"],
    ["*.test.example.com", "alpha.test.example.com", false, "covers"],
    ["*.example.com", "*.example.com", true, "inside"],
    ["*.example.com", "*.example.com", false, "covers"],
    ["admin.example.com", "*.example.com", true, "inside"],
    ["a.b.example.com", "*.example.com", true, "inside"],
    ["*.b.example.com", "*.example.com", true, "inside"],
    ["*.example.com", "*.example.org", true, "disjoint"],
    ["example.com", "*.example.com", true, "disjoint"],
    ["abc.site.pages.dev", "*.site.pages.dev", false, "inside"],
    ["a.b.site.pages.dev", "*.site.pages.dev", false, "disjoint"],
  ])("%s vs %s (any depth %s): %s", (app, key, multiLevel, expected) => {
    expect(relateHost(pattern(app), pattern(key, multiLevel))).toBe(expected);
  });

  it("R2-03: a one-label Access wildcard never covers a pattern that matches any depth", () => {
    const key = pattern("*.example.com", true);
    for (const app of ["*.example.com", "*.*.example.com", "*", "*.com"]) {
      expect(relateHost(pattern(app), key)).not.toBe("covers");
    }
  });
});

describe("hostSpecificity", () => {
  it("ranks exact hosts above every wildcard", () => {
    const exact = hostSpecificity(pattern("app.example.com"));
    expect(exact).toBeGreaterThan(hostSpecificity(pattern("*app.example.com")));
    expect(hostSpecificity(pattern("*app.example.com"))).toBeGreaterThan(
      hostSpecificity(pattern("*.example.com")),
    );
  });
});
