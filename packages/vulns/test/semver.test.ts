import { describe, expect, it } from "vitest";
import { compareSemver, parseSemver, type SemVer } from "../src/semver.ts";

const parse = (text: string): SemVer => {
  const version = parseSemver(text);
  if (!version) throw new Error(`does not parse: ${text}`);
  return version;
};

describe("parseSemver", () => {
  it.each([
    ["0.0.0", { major: "0", minor: "0", patch: "0", prerelease: [], build: [] }],
    ["1.2.3", { major: "1", minor: "2", patch: "3", prerelease: [], build: [] }],
    [
      "1.0.0-alpha.1",
      { major: "1", minor: "0", patch: "0", prerelease: ["alpha", "1"], build: [] },
    ],
    ["1.0.0-0.3.7", { major: "1", minor: "0", patch: "0", prerelease: ["0", "3", "7"], build: [] }],
    [
      "1.0.0-x-y-z.--",
      { major: "1", minor: "0", patch: "0", prerelease: ["x-y-z", "--"], build: [] },
    ],
    [
      "1.0.0+20130313144700",
      { major: "1", minor: "0", patch: "0", prerelease: [], build: ["20130313144700"] },
    ],
    [
      "1.0.0-beta+exp.sha.5114f85",
      {
        major: "1",
        minor: "0",
        patch: "0",
        prerelease: ["beta"],
        build: ["exp", "sha", "5114f85"],
      },
    ],
    [
      "99999999999999999999.0.0",
      { major: "99999999999999999999", minor: "0", patch: "0", prerelease: [], build: [] },
    ],
  ])("parses %s", (text, expected) => {
    expect(parseSemver(text)).toEqual({ ...expected, text });
  });

  it.each([
    ["empty", ""],
    ["leading v", "v1.2.3"],
    ["leading =", "=1.2.3"],
    ["two parts", "1.2"],
    ["four parts", "1.2.3.4"],
    ["leading zero in major", "01.2.3"],
    ["leading zero in patch", "1.2.03"],
    ["leading zero in a numeric prerelease identifier", "1.2.3-01"],
    ["empty prerelease identifier", "1.2.3-alpha..1"],
    ["empty prerelease", "1.2.3-"],
    ["empty build", "1.2.3+"],
    ["invalid character", "1.2.3-alpha_1"],
    ["whitespace", " 1.2.3"],
    ["trailing newline", "1.2.3\n"],
    ["npm range", "^1.2.3"],
    ["wildcard", "1.x"],
    ["star", "*"],
    ["zero sentinel", "0"],
    ["longer than 256 characters", `1.2.3-${"a".repeat(251)}`],
  ])("rejects %s", (_, text) => {
    expect(parseSemver(text)).toBeNull();
  });

  it("accepts exactly 256 characters", () => {
    expect(parseSemver(`1.2.3-${"a".repeat(250)}`)).not.toBeNull();
  });
});

describe("compareSemver", () => {
  // SemVer 2.0.0, section 11: each version is lower than the next.
  const ascending = [
    "0.0.1",
    "0.1.0",
    "0.9.9",
    "1.0.0-0",
    "1.0.0-1",
    "1.0.0-2",
    "1.0.0-10",
    "1.0.0-alpha",
    "1.0.0-alpha.1",
    "1.0.0-alpha.beta",
    "1.0.0-beta",
    "1.0.0-beta.2",
    "1.0.0-beta.11",
    "1.0.0-rc.1",
    "1.0.0",
    "1.0.1",
    "1.2.0",
    "1.10.0",
    "2.0.0",
    "10.0.0",
    "99999999999999999998.0.0",
    "99999999999999999999.0.0",
    "100000000000000000000.0.0",
  ];

  it("orders by SemVer precedence", () => {
    for (let i = 0; i < ascending.length; i++) {
      for (let j = 0; j < ascending.length; j++) {
        const expected = Math.sign(i - j);
        const a = ascending[i] as string;
        const b = ascending[j] as string;
        expect(compareSemver(parse(a), parse(b)), `${a} vs ${b}`).toBe(expected);
      }
    }
  });

  it("ignores build metadata", () => {
    expect(compareSemver(parse("1.0.0+a"), parse("1.0.0+b"))).toBe(0);
    expect(compareSemver(parse("1.0.0+a"), parse("1.0.0"))).toBe(0);
    expect(compareSemver(parse("1.0.0-rc.1+a"), parse("1.0.0-rc.1"))).toBe(0);
    expect(compareSemver(parse("1.0.0-rc.1+z"), parse("1.0.0"))).toBe(-1);
  });

  it("compares alphanumeric identifiers in ASCII order", () => {
    expect(compareSemver(parse("1.0.0-Beta"), parse("1.0.0-alpha"))).toBe(-1);
    expect(compareSemver(parse("1.0.0-a1"), parse("1.0.0-a10"))).toBe(-1);
    expect(compareSemver(parse("1.0.0-a9"), parse("1.0.0-a10"))).toBe(1);
  });
});
