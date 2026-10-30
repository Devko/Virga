import { describe, expect, it } from "vitest";
import { ScannerOutputRejected } from "../src/errors.ts";
import { MASK } from "../src/secrets.ts";
import { readTrivy } from "../src/trivy.ts";
import { json, trivySample } from "./samples.ts";

type Sample = typeof trivySample;
const clone = (): Sample => structuredClone(trivySample);

const rejection = (value: unknown) => {
  try {
    readTrivy(typeof value === "string" ? value : json(value));
  } catch (error) {
    expect(error).toBeInstanceOf(ScannerOutputRejected);
    return error as ScannerOutputRejected;
  }
  throw new Error("expected a rejection");
};

const results = (sample: Sample) => sample.Results as unknown as Record<string, unknown>[];
const at = (sample: Sample, result: number, list: string, index: number) => {
  const items = results(sample)[result]?.[list] as Record<string, unknown>[] | undefined;
  const item = items?.[index];
  if (!item) throw new Error("sample changed");
  return item;
};

describe("readTrivy", () => {
  it("normalizes packages, vulnerability matches and secrets", () => {
    const report = readTrivy(json(trivySample));
    expect(report.tool).toBe("trivy");
    expect(report.packages).toEqual([
      {
        purl: "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=3.19.1",
        ecosystem: "alpine",
        name: "musl",
        version: "1.2.4-r2",
      },
      {
        purl: "pkg:apk/alpine/zlib@1.3-r2?arch=x86_64&distro=3.19.1",
        ecosystem: "alpine",
        name: "zlib",
        version: "1.3-r2",
      },
      { purl: "pkg:npm/lodash@4.17.20", ecosystem: "npm", name: "lodash", version: "4.17.20" },
      { purl: null, ecosystem: "npm", name: "ws", version: "8.0.0" },
    ]);
    expect(report.vulnerabilities).toEqual([
      {
        package: report.packages[0],
        id: "CVE-2025-26519",
        aliases: [],
        severity: 3,
        fixedVersions: ["1.2.4-r3"],
      },
      {
        package: report.packages[2],
        id: "CVE-2021-23337",
        aliases: ["GHSA-35jh-r3h4-6jhm"],
        severity: 3,
        fixedVersions: ["4.17.21"],
      },
      {
        package: report.packages[3],
        id: "CVE-2024-37890",
        aliases: [],
        severity: null,
        fixedVersions: ["7.5.10", "8.17.1"],
      },
    ]);
    expect(report.secrets).toEqual([
      {
        ruleId: "cloudflare-api-token",
        file: "usr/src/app/.env",
        line: 3,
        endLine: 3,
        prefix: null,
        masked: MASK,
      },
    ]);
  });

  it("formats the version with epoch and release like Trivy's installed version", () => {
    const sample = clone();
    Object.assign(at(sample, 0, "Packages", 1), { Epoch: 1 });
    const zlib = readTrivy(json(sample)).packages.find((p) => p.name === "zlib");
    expect(zlib?.version).toBe("1:1.3-r2");
  });

  it("finds the purl of a match through its package ID", () => {
    const sample = clone();
    delete at(sample, 0, "Vulnerabilities", 0).PkgIdentifier;
    const report = readTrivy(json(sample));
    expect(report.vulnerabilities[0]?.package.purl).toBe(
      "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=3.19.1",
    );
  });

  it("accepts a report without results", () => {
    expect(readTrivy('{"SchemaVersion":2,"ArtifactName":"x"}').packages).toEqual([]);
  });

  it.each([
    ["no schema version", "{}", "missing_field"],
    ["schema version 1", '{"SchemaVersion":1}', "unsupported_version"],
    ["schema version as text", '{"SchemaVersion":"2"}', "wrong_type"],
    ["a top-level list", "[]", "wrong_type"],
  ])("rejects %s", (_, text, reason) => {
    expect(rejection(text).reason).toBe(reason);
  });

  it.each([
    [
      "an invalid purl",
      0,
      "Vulnerabilities",
      { PkgIdentifier: { PURL: "pkg:npm/a b@1" } },
      "invalid_format",
    ],
    [
      "a purl without version",
      0,
      "Vulnerabilities",
      { PkgIdentifier: { PURL: "pkg:npm/a" } },
      "invalid_format",
    ],
    [
      "a purl with a fragment",
      0,
      "Packages",
      { Identifier: { PURL: "pkg:npm/a@1#x" } },
      "invalid_format",
    ],
    [
      "a purl with a bad escape",
      0,
      "Packages",
      { Identifier: { PURL: "pkg:npm/%zz@1" } },
      "invalid_format",
    ],
    ["an unknown severity", 0, "Vulnerabilities", { Severity: "SEVERE" }, "invalid_format"],
    ["a severity that is a number", 0, "Vulnerabilities", { Severity: 4 }, "wrong_type"],
    ["a missing package name", 0, "Vulnerabilities", { PkgName: undefined }, "missing_field"],
    ["a negative epoch", 0, "Packages", { Epoch: -1 }, "out_of_range"],
    ["a fractional line", 2, "Secrets", { StartLine: 1.5 }, "wrong_type"],
    [
      "a line range that runs backwards",
      2,
      "Secrets",
      { StartLine: 4, EndLine: 3 },
      "out_of_range",
    ],
    ["a rule ID with a slash", 2, "Secrets", { RuleID: "a/b" }, "invalid_format"],
  ])("rejects %s", (_, result, list, fields, reason) => {
    const sample = clone();
    Object.assign(at(sample, result, list, 0), fields);
    const error = rejection(sample);
    expect(error.reason).toBe(reason);
    expect(error.at.startsWith(`/Results/${result}/${list}/0`)).toBe(true);
  });

  it("requires a type for results that list packages", () => {
    const sample = clone();
    delete results(sample)[1]?.Type;
    expect(rejection(sample)).toMatchObject({ reason: "missing_field", at: "/Results/1/Type" });
  });

  it("rejects a target with a control character", () => {
    const sample = clone();
    const result = results(sample)[2];
    if (result) result.Target = "a\u001bb";
    expect(rejection(sample)).toMatchObject({ reason: "invalid_text", at: "/Results/2/Target" });
  });

  it("rejects too many secrets instead of truncating", () => {
    const sample = clone();
    const result = results(sample)[2];
    const secret = at(sample, 2, "Secrets", 0);
    if (result) result.Secrets = [secret, { ...secret, StartLine: 4, EndLine: 4 }];
    expect(() => readTrivy(json(sample), { limits: { maxSecrets: 1 } })).toThrow(
      expect.objectContaining({ reason: "too_many_items" }),
    );
  });
});
