import { describe, expect, it } from "vitest";
import { ScannerOutputRejected } from "../src/errors.ts";
import { readOsvScanner } from "../src/osv.ts";
import { RIGHT_TO_LEFT_OVERRIDE } from "./chars.ts";
import { json, osvSample } from "./samples.ts";

const clone = <T>(value: T): T => structuredClone(value);

const rejection = (value: unknown) => {
  try {
    readOsvScanner(typeof value === "string" ? value : json(value));
  } catch (error) {
    expect(error).toBeInstanceOf(ScannerOutputRejected);
    return error as ScannerOutputRejected;
  }
  throw new Error("expected a rejection");
};

describe("readOsvScanner", () => {
  it("normalizes packages and vulnerability matches", () => {
    const report = readOsvScanner(json(osvSample));
    expect(report.tool).toBe("osv-scanner");
    expect(report.secrets).toEqual([]);
    expect(report.packages).toEqual([
      {
        purl: "pkg:npm/%40babel/traverse@7.22.0",
        ecosystem: "npm",
        name: "@babel/traverse",
        version: "7.22.0",
      },
      { purl: "pkg:npm/lodash@4.17.20", ecosystem: "npm", name: "lodash", version: "4.17.20" },
      { purl: null, ecosystem: "PyPI", name: "requests", version: "2.25.0" },
    ]);
    expect(report.vulnerabilities.map((v) => [v.package.name, v.id, v.severity])).toEqual([
      ["@babel/traverse", "GHSA-67hx-6x53-jw92", 4],
      ["lodash", "GHSA-29mw-wpgm-hmr9", 2],
      ["lodash", "GHSA-35jh-r3h4-6jhm", 3],
      ["requests", "PYSEC-2023-74", null],
    ]);
    const traverse = report.vulnerabilities[0];
    expect(traverse?.aliases).toEqual(["CVE-2023-45133"]);
    expect(traverse?.fixedVersions).toEqual(["7.23.2", "8.0.0-alpha.4"]);
    // GIT ranges carry commits, not versions.
    expect(report.vulnerabilities[3]?.fixedVersions).toEqual(["2.31.0"]);
  });

  it("is deterministic whatever the input order", () => {
    const reversed = clone(osvSample);
    const packages = reversed.results[0]?.packages;
    packages?.reverse();
    for (const p of packages ?? []) p.vulnerabilities.reverse();
    expect(readOsvScanner(json(reversed))).toEqual(readOsvScanner(json(osvSample)));
  });

  it("merges a package listed by two sources into one entry", () => {
    const doubled = clone(osvSample);
    const first = doubled.results[0];
    if (first) doubled.results.push(clone(first));
    const report = readOsvScanner(json(doubled));
    expect(report.packages).toHaveLength(3);
    expect(report.vulnerabilities).toHaveLength(4);
  });

  it("falls back to the database severity and keeps unknown severity unknown", () => {
    const sample = clone(osvSample);
    const lodash = sample.results[0]?.packages[0];
    if (lodash) lodash.groups = [];
    const report = readOsvScanner(json(sample));
    const severities = report.vulnerabilities
      .filter((v) => v.package.name === "lodash")
      .map((v) => v.severity);
    // MODERATE and HIGH from database_specific.
    expect(severities).toEqual([2, 3]);
    expect(report.vulnerabilities.find((v) => v.id === "PYSEC-2023-74")?.severity).toBeNull();
  });

  it.each([
    ["0.0", 0],
    ["3.9", 1],
    ["4.0", 2],
    ["6.9", 2],
    ["7.0", 3],
    ["8.9", 3],
    ["9.0", 4],
    ["10.0", 4],
    ["", null],
    ["unexpected", null],
  ])("maps max_severity %s to rank %s", (score, rank) => {
    const sample = clone(osvSample);
    const babel = sample.results[0]?.packages[1];
    const group = babel?.groups[0];
    if (group) group.max_severity = score;
    const vuln = babel?.vulnerabilities[0] as Record<string, unknown> | undefined;
    if (vuln) vuln.database_specific = {};
    const report = readOsvScanner(json(sample));
    expect(report.vulnerabilities[0]?.severity).toBe(rank);
  });

  it("derives a purl for npm names only when they are valid npm names", () => {
    const sample = clone(osvSample);
    const lodash = sample.results[0]?.packages[0];
    if (lodash) lodash.package = { name: "Not A Name", version: "1.0.0", ecosystem: "npm" };
    const report = readOsvScanner(json(sample));
    expect(report.packages.find((p) => p.name === "Not A Name")?.purl).toBeNull();
  });

  it("lowercases npm names and percent-encodes the version", () => {
    const sample = clone(osvSample);
    const lodash = sample.results[0]?.packages[0];
    if (lodash) lodash.package = { name: "JSONStream", version: "1.0.0+build.1", ecosystem: "npm" };
    const report = readOsvScanner(json(sample));
    expect(report.packages.map((p) => p.purl)).toContain("pkg:npm/jsonstream@1.0.0%2Bbuild.1");
  });

  it("treats an empty version as no version and derives no purl", () => {
    const sample = clone(osvSample);
    const lodash = sample.results[0]?.packages[0];
    if (lodash) lodash.package = { name: "lodash", version: "", ecosystem: "npm" };
    const pkg = readOsvScanner(json(sample)).packages.find((p) => p.name === "lodash");
    expect(pkg).toEqual({ purl: null, ecosystem: "npm", name: "lodash", version: null });
  });

  it("accepts an empty report and null lists", () => {
    expect(readOsvScanner('{"results":[]}').packages).toEqual([]);
    expect(readOsvScanner('{"results":null}').vulnerabilities).toEqual([]);
    expect(readOsvScanner('{"results":[{"packages":null}]}').packages).toEqual([]);
  });

  it("requires the results member, so an empty object is not a clean scan", () => {
    expect(rejection("{}")).toMatchObject({ reason: "missing_field", at: "/results" });
    expect(rejection("[]")).toMatchObject({ reason: "wrong_type", at: "/" });
  });

  it.each([
    ["a numeric id", (s: typeof osvSample) => setVuln(s, { id: 42 }), "wrong_type"],
    ["an id with spaces", (s: typeof osvSample) => setVuln(s, { id: "GHSA x" }), "invalid_format"],
    [
      "a long id",
      (s: typeof osvSample) => setVuln(s, { id: `CVE-${"1".repeat(200)}` }),
      "string_too_long",
    ],
    [
      "an alias that is not an ID",
      (s: typeof osvSample) => setVuln(s, { aliases: ["<b>"] }),
      "invalid_format",
    ],
    [
      "aliases that are not a list",
      (s: typeof osvSample) => setVuln(s, { aliases: "CVE-1" }),
      "wrong_type",
    ],
    [
      "a missing package",
      (s: typeof osvSample) => setEntry(s, { package: undefined }),
      "missing_field",
    ],
    [
      "a name with a control character",
      (s: typeof osvSample) => setPackage(s, { name: "a\u0007b" }),
      "invalid_text",
    ],
    [
      "a name with a bidi override",
      (s: typeof osvSample) => setPackage(s, { name: `a${RIGHT_TO_LEFT_OVERRIDE}b` }),
      "invalid_text",
    ],
    ["an empty name", (s: typeof osvSample) => setPackage(s, { name: "" }), "invalid_format"],
    ["a numeric version", (s: typeof osvSample) => setPackage(s, { version: 1 }), "wrong_type"],
    [
      "an ecosystem with markup",
      (s: typeof osvSample) => setPackage(s, { ecosystem: "<npm>" }),
      "invalid_format",
    ],
    [
      "a numeric max_severity",
      (s: typeof osvSample) => setGroup(s, { max_severity: 9.8 }),
      "wrong_type",
    ],
    [
      "group ids that are not IDs",
      (s: typeof osvSample) => setGroup(s, { ids: [1] }),
      "wrong_type",
    ],
    ["a fixed version that is not text", (s: typeof osvSample) => setFixed(s, 4), "wrong_type"],
    ["a fixed version with a NUL", (s: typeof osvSample) => setFixed(s, "1\u0000"), "invalid_text"],
  ])("rejects %s", (_, mutate, reason) => {
    const sample = clone(osvSample);
    mutate(sample);
    const error = rejection(sample);
    expect(error.reason).toBe(reason);
    expect(error.tool).toBe("osv-scanner");
    expect(error.at).toMatch(/^\/results\/0\/packages\/0/);
  });

  it("rejects too many packages instead of truncating", () => {
    const sample = clone(osvSample);
    expect(() => readOsvScanner(json(sample), { limits: { maxPackages: 2 } })).toThrow(
      expect.objectContaining({ reason: "too_many_items" }),
    );
  });

  it("rejects too many vulnerability matches instead of truncating", () => {
    const sample = clone(osvSample);
    expect(() => readOsvScanner(json(sample), { limits: { maxVulnerabilities: 3 } })).toThrow(
      expect.objectContaining({ reason: "too_many_items" }),
    );
  });
});

type Sample = typeof osvSample;

function entry(sample: Sample) {
  const value = sample.results[0]?.packages[0];
  if (!value) throw new Error("sample changed");
  return value as unknown as Record<string, unknown> & Sample["results"][0]["packages"][0];
}

function setEntry(sample: Sample, fields: Record<string, unknown>) {
  Object.assign(entry(sample), fields);
}

function setPackage(sample: Sample, fields: Record<string, unknown>) {
  Object.assign(entry(sample).package, fields);
}

function setVuln(sample: Sample, fields: Record<string, unknown>) {
  Object.assign(entry(sample).vulnerabilities[0] ?? {}, fields);
}

function setGroup(sample: Sample, fields: Record<string, unknown>) {
  Object.assign(entry(sample).groups[0] ?? {}, fields);
}

function setFixed(sample: Sample, fixed: unknown) {
  const range = (entry(sample).vulnerabilities[0]?.affected?.[0]?.ranges[0] ?? {}) as {
    events: unknown[];
  };
  range.events = [{ introduced: "0" }, { fixed }];
}
