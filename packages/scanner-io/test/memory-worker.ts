// Runs a reader, or the parser, on a generated report in a worker thread whose heap
// the test caps, so the test sees the peak of a read and not only what stays
// afterwards (R9-06). Node runs this file directly, without vitest.

import { parentPort, workerData } from "node:worker_threads";
import { parseJson } from "../src/json.ts";
import { DEFAULT_LIMITS } from "../src/limits.ts";
import { readOsvScanner } from "../src/osv.ts";
import type { ScanReport } from "../src/report.ts";
import { readTrivy } from "../src/trivy.ts";
import { CJK, worstReport } from "./hostile.ts";

const LONG_NAME = CJK.repeat(512);
const LONG_VERSION = `${"v".repeat(255)}${CJK}`;
const n = DEFAULT_LIMITS.maxVulnerabilities;

/** One package with the longest name and version, and as many advisories as allowed. */
function osvReport(): string {
  const vulnerabilities = Array.from({ length: n }, (_, i) => ({ id: `GHSA-${i}` }));
  const pkg = { name: LONG_NAME, version: LONG_VERSION, ecosystem: "npm" };
  return JSON.stringify({ results: [{ packages: [{ package: pkg, vulnerabilities }] }] });
}

/** One listed package with the longest name, linked by `PkgID` from every match. */
function trivyReport(): string {
  const vulns = Array.from({ length: n }, (_, i) => ({
    VulnerabilityID: `CVE-2024-${i}`,
    PkgID: "p",
    PkgName: "p",
    InstalledVersion: "1",
  }));
  const result = {
    Target: CJK.repeat(1024),
    Type: "T".repeat(128),
    Packages: [{ ID: "p", Name: LONG_NAME, Version: LONG_VERSION }],
    Vulnerabilities: vulns,
  };
  return JSON.stringify({ SchemaVersion: 2, Results: [result] });
}

const runs: Record<string, () => ScanReport> = {
  osv: () => readOsvScanner(osvReport()),
  trivy: () => readTrivy(trivyReport()),
  parse: () => {
    parseJson(worstReport(), DEFAULT_LIMITS, "trivy");
    return { tool: "trivy", packages: [], vulnerabilities: [], secrets: [] };
  },
};

const run = runs[String(workerData)];
if (!run) throw new Error("unknown run");
const report = run();
parentPort?.postMessage({ vulnerabilities: report.vulnerabilities.length });
