import { describe, expect, it } from "vitest";
import { type Decision, evaluateRange, matchAdvisory } from "../src/match.ts";
import type { NpmAffected, OsvAdvisory, OsvEvent, OsvRange } from "../src/osv.ts";
import { parseSemver, type SemVer } from "../src/semver.ts";

const v = (text: string): SemVer => {
  const version = parseSemver(text);
  if (!version) throw new Error(`does not parse: ${text}`);
  return version;
};

/** A range from events written as `kind:version`. */
const range = (type: OsvRange["type"], ...events: string[]): OsvRange => ({
  type,
  events: events.map((e): OsvEvent => {
    const at = e.indexOf(":");
    return { kind: e.slice(0, at) as OsvEvent["kind"], version: e.slice(at + 1) };
  }),
});

const affected = (name: string, ranges: OsvRange[], versions: string[] = []): NpmAffected => ({
  name,
  ranges,
  versions,
  severity: null,
});

const advisory = (...entries: NpmAffected[]): OsvAdvisory => ({
  id: "GHSA-vrga-match-0000",
  modified: "2026-10-01T00:00:00Z",
  aliases: [],
  severity: [],
  databaseSeverity: "HIGH",
  affected: entries,
});

const A: Decision = "affected";
const N: Decision = "not_affected";
const U: Decision = "unknown";

describe("evaluateRange", () => {
  const cases: [string, string[], [string, Decision][]][] = [
    [
      "introduced 0, fixed",
      ["introduced:0", "fixed:1.2.0"],
      [
        ["0.0.0", A],
        ["0.0.0-0", A],
        ["1.1.9", A],
        ["1.2.0-rc.1", A],
        ["1.2.0", N],
        ["1.2.0+build.1", N],
        ["1.2.1", N],
        ["2.0.0", N],
      ],
    ],
    [
      "introduced, fixed",
      ["introduced:1.0.0", "fixed:1.2.0"],
      [
        ["0.9.9", N],
        ["1.0.0-rc.1", N],
        ["1.0.0", A],
        ["1.0.0+build", A],
        ["1.1.0", A],
        ["1.2.0", N],
      ],
    ],
    [
      "introduced at a prerelease",
      ["introduced:2.0.0-beta.1", "fixed:2.0.0"],
      [
        ["2.0.0-alpha.9", N],
        ["2.0.0-beta.0", N],
        ["2.0.0-beta.1", A],
        ["2.0.0-beta.11", A],
        ["2.0.0-rc.1", A],
        ["2.0.0", N],
      ],
    ],
    [
      "introduced 0, last_affected",
      ["introduced:0", "last_affected:2.3.4"],
      [
        ["0.1.0", A],
        ["2.3.4-beta", A],
        ["2.3.4", A],
        ["2.3.4+build", A],
        ["2.3.5-0", N],
        ["2.3.5", N],
      ],
    ],
    [
      "introduced only",
      ["introduced:0"],
      [
        ["0.0.0", A],
        ["99.0.0", A],
      ],
    ],
    [
      "two release lines in one range",
      ["introduced:1.0.0", "fixed:1.4.2", "introduced:2.0.0-beta.1", "fixed:2.1.0"],
      [
        ["0.9.0", N],
        ["1.4.1", A],
        ["1.4.2", N],
        ["1.5.0", N],
        ["2.0.0-alpha", N],
        ["2.0.0-beta.1", A],
        ["2.0.0", A],
        ["2.1.0", N],
        ["3.0.0", N],
      ],
    ],
    [
      "events out of order",
      ["fixed:2.1.0", "introduced:2.0.0", "fixed:1.4.2", "introduced:1.0.0"],
      [
        ["1.2.0", A],
        ["1.9.0", N],
        ["2.0.5", A],
        ["2.1.0", N],
      ],
    ],
    [
      "introduced with a limit",
      ["introduced:3.0.0", "limit:4.0.0"],
      [
        ["2.9.9", N],
        ["3.0.0", A],
        ["3.9.9", A],
        ["4.0.0-rc.1", A],
        ["4.0.0", N],
        ["4.1.0", N],
      ],
    ],
    ["limit *", ["introduced:0", "limit:*"], [["5.0.0", A]]],
    [
      "several limits",
      ["introduced:0", "limit:1.0.0", "limit:2.0.0"],
      [
        ["0.5.0", A],
        ["1.5.0", A],
        ["2.0.0", N],
      ],
    ],
    ["a limit and *", ["introduced:0", "limit:1.0.0", "limit:*"], [["5.0.0", A]]],
    [
      "introduced and fixed at the same version",
      ["introduced:1.0.0", "fixed:1.0.0"],
      [
        ["0.9.0", N],
        ["1.0.0", N],
        ["1.0.1", N],
      ],
    ],
    [
      "introduced and last_affected at the same version",
      ["last_affected:1.0.0", "introduced:1.0.0"],
      [
        ["0.9.0", N],
        ["1.0.0", A],
        ["1.0.1", N],
      ],
    ],
    [
      "numbers above 2^53",
      ["introduced:0", "fixed:99999999999999999999.0.0"],
      [
        ["99999999999999999998.0.0", A],
        ["99999999999999999999.0.0", N],
      ],
    ],
  ];

  for (const type of ["SEMVER", "ECOSYSTEM"] as const) {
    describe(type, () => {
      for (const [title, events, table] of cases) {
        it.each(table)(`${title}: %s is %s`, (version, expected) => {
          expect(evaluateRange(range(type, ...events), v(version))).toBe(expected);
        });
      }
    });
  }

  it.each([
    ["a fixed version that is not SemVer", ["introduced:0", "fixed:1.2"]],
    ["a v prefix", ["introduced:v1.0.0", "fixed:1.2.0"]],
    ["an npm range", ["introduced:>=1.0.0", "fixed:1.2.0"]],
    ["0 outside introduced", ["introduced:1.0.0", "fixed:0"]],
    ["* outside limit", ["introduced:*"]],
    ["an unparseable limit", ["introduced:0", "limit:2"]],
    [
      "an unparseable event after the deciding one",
      ["introduced:0", "fixed:1.0.0", "introduced:x"],
    ],
  ])("gives unknown for %s", (_, events) => {
    for (const version of ["0.0.1", "1.1.0", "5.0.0"]) {
      expect(evaluateRange(range("SEMVER", ...events), v(version))).toBe(U);
      expect(evaluateRange(range("ECOSYSTEM", ...events), v(version))).toBe(U);
    }
  });

  it("gives unknown for a GIT range", () => {
    const git = range("GIT", "introduced:0", "fixed:4f3a1b2c3d4e5f60718293a4b5c6d7e8f9012345");
    expect(evaluateRange(git, v("1.0.0"))).toBe(U);
  });
});

describe("matchAdvisory", () => {
  const twoLines = range(
    "SEMVER",
    "introduced:1.0.0",
    "fixed:1.4.2",
    "introduced:2.0.0",
    "fixed:2.1.0",
  );

  it("does not match another package name", () => {
    expect(matchAdvisory(advisory(affected("a", [twoLines])), "b", v("1.1.0"))).toEqual({
      decision: N,
      fixedIn: null,
      entries: [],
    });
  });

  it("matches the name exactly, case included", () => {
    const adv = advisory(affected("JSONStream", [range("SEMVER", "introduced:0")]));
    expect(matchAdvisory(adv, "jsonstream", v("1.0.0")).decision).toBe(N);
    expect(matchAdvisory(adv, "JSONStream", v("1.0.0")).decision).toBe(A);
  });

  it("returns the lowest fixed version above the installed one", () => {
    const adv = advisory(affected("a", [twoLines]));
    expect(matchAdvisory(adv, "a", v("1.1.0"))).toMatchObject({ decision: A, fixedIn: "1.4.2" });
    expect(matchAdvisory(adv, "a", v("2.0.5"))).toMatchObject({ decision: A, fixedIn: "2.1.0" });
    expect(matchAdvisory(adv, "a", v("1.5.0"))).toMatchObject({ decision: N, fixedIn: null });
  });

  it("has no fixed version when the range has none", () => {
    const adv = advisory(affected("a", [range("SEMVER", "introduced:0", "last_affected:2.0.0")]));
    expect(matchAdvisory(adv, "a", v("1.0.0"))).toMatchObject({ decision: A, fixedIn: null });
  });

  it("matches the versions list, with or without ranges", () => {
    const listed = advisory(affected("a", [], ["1.0.0", "1.0.1"]));
    expect(matchAdvisory(listed, "a", v("1.0.1")).decision).toBe(A);
    expect(matchAdvisory(listed, "a", v("1.0.1+build.7")).decision).toBe(A);
    expect(matchAdvisory(listed, "a", v("1.0.2")).decision).toBe(N);
    expect(matchAdvisory(listed, "a", v("1.0.1-rc.1")).decision).toBe(N);

    const both = advisory(
      affected("a", [range("SEMVER", "introduced:2.0.0", "fixed:2.0.1")], ["1.0.0"]),
    );
    expect(matchAdvisory(both, "a", v("1.0.0")).decision).toBe(A);
    expect(matchAdvisory(both, "a", v("2.0.0")).decision).toBe(A);
    expect(matchAdvisory(both, "a", v("1.5.0")).decision).toBe(N);
  });

  it("gives unknown when a listed version does not parse and nothing else matches", () => {
    const adv = advisory(affected("a", [], ["1.0.0", "1.0"]));
    expect(matchAdvisory(adv, "a", v("1.0.0")).decision).toBe(A);
    expect(matchAdvisory(adv, "a", v("2.0.0")).decision).toBe(U);
  });

  it("gives unknown for an entry with neither ranges nor versions", () => {
    expect(matchAdvisory(advisory(affected("a", [])), "a", v("1.0.0")).decision).toBe(U);
  });

  it("combines ranges and entries: affected wins over unknown, unknown over not affected", () => {
    const bad = range("SEMVER", "introduced:0", "fixed:1.x");
    const good = range("SEMVER", "introduced:0", "fixed:2.0.0");
    const adv = advisory(affected("a", [bad, good]));
    expect(matchAdvisory(adv, "a", v("1.0.0")).decision).toBe(A);
    expect(matchAdvisory(adv, "a", v("3.0.0")).decision).toBe(U);

    const split = advisory(affected("a", [bad]), affected("a", [good]));
    expect(matchAdvisory(split, "a", v("1.0.0"))).toMatchObject({ decision: A, fixedIn: "2.0.0" });
    expect(matchAdvisory(split, "a", v("3.0.0")).decision).toBe(U);
  });

  it("reports the entries that decided affected", () => {
    const first = affected("a", [range("SEMVER", "introduced:0", "fixed:1.0.0")]);
    const second = affected("a", [range("SEMVER", "introduced:0", "fixed:2.0.0")]);
    const result = matchAdvisory(advisory(first, second), "a", v("1.5.0"));
    expect(result).toEqual({ decision: A, fixedIn: "2.0.0", entries: [second] });
  });

  it("applies the wildcard name to every package", () => {
    const adv = advisory(affected("*", [range("SEMVER", "introduced:0", "fixed:1.0.0")]));
    expect(matchAdvisory(adv, "anything", v("0.5.0")).decision).toBe(A);
    expect(matchAdvisory(adv, "@scope/x", v("1.0.0")).decision).toBe(N);
  });
});
