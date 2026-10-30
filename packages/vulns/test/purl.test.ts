import { describe, expect, it } from "vitest";
import { parseNpmPurl } from "../src/purl.ts";

describe("parseNpmPurl", () => {
  it.each([
    ["pkg:npm/lodash@4.17.20", "lodash", "4.17.20"],
    ["pkg:npm/%40scope/name@1.0.0", "@scope/name", "1.0.0"],
    ["pkg:npm/@scope/name@1.0.0", "@scope/name", "1.0.0"],
    ["pkg:npm/%40Scope/Name@1.0.0", "@Scope/Name", "1.0.0"],
    ["pkg:npm/JSONStream@1.3.5", "JSONStream", "1.3.5"],
    ["pkg:npm/lodash.merge@4.6.2", "lodash.merge", "4.6.2"],
    ["pkg:npm/%40a-b%2Ec/d_e~f@0.0.1", "@a-b.c/d_e~f", "0.0.1"],
    ["pkg:npm/next@15.0.0-canary.12", "next", "15.0.0-canary.12"],
    ["pkg:npm/pkg@1.0.0%2Bbuild.5", "pkg", "1.0.0+build.5"],
    ["pkg:npm/pkg@1.0.0+build.5", "pkg", "1.0.0+build.5"],
  ])("parses %s", (purl, name, version) => {
    const result = parseNpmPurl(purl);
    expect(result).toMatchObject({ ok: true, name, versionText: version });
    if (result.ok) expect(result.version.text).toBe(version);
  });

  it.each([
    ["another purl type", "pkg:pypi/django@1.11.1", "unsupported purl type"],
    ["an uppercase type", "pkg:NPM/lodash@4.17.20", "unsupported purl type"],
    ["no pkg scheme", "npm/lodash@4.17.20", "not a purl"],
    ["slashes after the scheme", "pkg://npm/lodash@4.17.20", "not a purl"],
    ["no version", "pkg:npm/lodash", "no version"],
    ["a scope without version", "pkg:npm/%40scope/name", "no version"],
    ["a raw scope without version", "pkg:npm/@scope/name", "no version"],
    ["an empty version", "pkg:npm/lodash@", "version is not SemVer 2.0"],
    ["an npm range as version", "pkg:npm/lodash@%5E4.17.20", "version is not SemVer 2.0"],
    ["a v prefix", "pkg:npm/lodash@v4.17.20", "version is not SemVer 2.0"],
    [
      "qualifiers",
      "pkg:npm/lodash@4.17.20?repository_url=https://example.test",
      "qualifiers or subpath",
    ],
    ["a subpath", "pkg:npm/lodash@4.17.20#lib", "qualifiers or subpath"],
    ["an empty name", "pkg:npm/@1.0.0", "invalid package name"],
    ["a scope without @", "pkg:npm/scope/name@1.0.0", "invalid package name"],
    ["three path segments", "pkg:npm/%40a/b/c@1.0.0", "invalid package name"],
    ["an @ inside the name", "pkg:npm/na@me@1.0.0", "invalid package name"],
    ["a space in the name", "pkg:npm/na%20me@1.0.0", "invalid package name"],
    ["a slash encoded in the name", "pkg:npm/a%2Fb@1.0.0", "invalid package name"],
    ["a control character", "pkg:npm/a%00b@1.0.0", "invalid package name"],
    ["broken percent-encoding", "pkg:npm/a%zzb@1.0.0", "invalid percent-encoding"],
    [
      "a name longer than 214 characters",
      `pkg:npm/${"a".repeat(215)}@1.0.0`,
      "invalid package name",
    ],
    [
      "more than 512 characters",
      `pkg:npm/a@1.0.0-${"b".repeat(500)}`,
      "longer than 512 characters",
    ],
  ])("rejects %s", (_, purl, reason) => {
    expect(parseNpmPurl(purl)).toEqual({ ok: false, reason });
  });

  it("accepts a name of 214 characters", () => {
    expect(parseNpmPurl(`pkg:npm/${"a".repeat(214)}@1.0.0`).ok).toBe(true);
    expect(parseNpmPurl(`pkg:npm/%40s/${"a".repeat(211)}@1.0.0`).ok).toBe(true);
    expect(parseNpmPurl(`pkg:npm/%40s/${"a".repeat(212)}@1.0.0`).ok).toBe(false);
  });
});
