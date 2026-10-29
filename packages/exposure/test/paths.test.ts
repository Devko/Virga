// Path semantics from
// https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/
// https://developers.cloudflare.com/workers/configuration/routing/routes/#matching-behavior
// https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/
import { describe, expect, it } from "vitest";
import {
  containsPath,
  type PathPattern,
  type PathSet,
  parseAccessPath,
  parseRoutePath,
  parseTunnelPath,
  pathLabel,
  specificity,
} from "../src/paths.ts";

const describePattern = (p: PathPattern) =>
  p.kind === "opaque" ? `opaque ${pathLabel(p.hull)}` : pathLabel(p);

describe("parseAccessPath", () => {
  it.each([
    [null, "/"],
    ["", "/"],
    ["/", "/"],
    ["/*", "/"],
    ["*", "/"],
    ["/admin", "/admin"],
    ["admin/", "/admin"],
    ["/alpha/*", "/alpha/*"],
    ["/alpha*", "/alpha*"],
    ["/foo*/bar", "opaque /foo*"],
    ["*/bar", "opaque /"],
    [42, "opaque /"],
  ])("%j -> %s", (input, expected) => {
    expect(describePattern(parseAccessPath(input))).toBe(expected);
  });
});

describe("parseRoutePath", () => {
  it.each([
    ["", "/"],
    ["/", "/"],
    ["/*", "/"],
    ["/api/*", "/api/*"],
    ["/v1*", "/v1*"],
    ["/status", "/status"],
    ["/*.jpg", "opaque /"],
  ])("%j -> %s", (input, expected) => {
    expect(describePattern(parseRoutePath(input))).toBe(expected);
  });
});

describe("parseTunnelPath", () => {
  it.each([
    ["", "/", false],
    ["^/admin/", "/admin/*", true],
    ["^/api$", "/api", true],
    ["^/api/v[0-9]+", "/api/v*", true],
    ["^/files\\.d/x", "/files.d/x*", true],
    ["^/a?", "/", true],
    ["^/api|/other", "/", true],
    ["\\.(jpg|png)$", "/", true],
    ["/api", "/", true],
  ])("%j -> %s (approximate %s)", (input, label, approximate) => {
    const parsed = parseTunnelPath(input);
    expect([pathLabel(parsed.set), parsed.approximate]).toEqual([label, approximate]);
  });
});

const set = (label: string): PathSet => {
  const p = label.endsWith("*") ? parseRoutePath(label) : parseAccessPath(label);
  if (p.kind === "opaque") throw new Error(label);
  return p;
};

describe("containsPath", () => {
  it.each([
    ["/", "/admin", true],
    ["/admin", "/", false],
    ["/admin", "/admin", true],
    ["/admin", "/admin/users", true],
    ["/admin", "/administrator", false],
    ["/admin", "/admin*", false],
    ["/admin*", "/admin", true],
    ["/admin*", "/administrator", true],
    ["/admin", "/admin/*", true],
    ["/admin/*", "/admin", false],
    ["/admin/*", "/admin/users", true],
    ["/api", "/apiv2*", false],
  ])("%s contains %s: %s", (a, b, expected) => {
    expect(containsPath(set(a), set(b))).toBe(expected);
  });

  it("orders nested sets by specificity", () => {
    const chain = ["/", "/a*", "/a", "/a/*", "/a/b"].map(set);
    for (let i = 1; i < chain.length; i++) {
      const [outer, inner] = [chain[i - 1] as PathSet, chain[i] as PathSet];
      expect(containsPath(outer, inner)).toBe(true);
      expect(specificity(outer)).toBeLessThan(specificity(inner));
    }
  });
});
