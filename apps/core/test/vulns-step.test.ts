import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { createReader } from "@virga/cf-api";
import { fixtureTransport } from "@virga/cf-api/testing";
import { evaluateRules, RULES } from "@virga/rules";
import { type KevCatalog, readOsvFeed } from "@virga/vulns";
import { describe, expect, it } from "vitest";
import type { AccountGraph } from "../src/account-graph.ts";
import { type AdvisoryRead, type AdvisorySource, NO_ADVISORY_FEED } from "../src/graph/vulns.ts";
import { d1ScanIndex } from "../src/index-db.ts";
import { runScan } from "../src/scan/run.ts";
import { fakeStep } from "./fake-step.ts";
import { apiRoutes, initialState } from "./fixtures/api.ts";
import { fakeEvaluators, newAccountId, setupAccount, sql } from "./helpers.ts";
import { scriptedStub } from "./stubs.ts";

/**
 * The scan's `vulns` step: the live package nodes against an advisory feed,
 * written with applyVulnRematch, before the rules. No advisory mirror
 * exists yet (decision 0009), so the default source reports that no feed is
 * configured; these tests give the step a fake one.
 */

const NOW = Date.UTC(2026, 9, 30, 12, 17);
const AFFECTED = "package:pkg:npm/virga-fixture-a@4.17.20";
// From the scanned account, so it must not reach a step result.
const UNPARSED = "package:pkg:npm/evil-<script>@1";

/** A hand-written OSV record: virga-fixture-a below 4.17.21, CVSS 9.8, alias CVE-2099-0001. */
const RECORD = JSON.stringify({
  schema_version: "1.6.0",
  id: "GHSA-vrga-0001-test1",
  modified: "2026-10-01T12:00:00Z",
  aliases: ["CVE-2099-0001"],
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
  affected: [
    {
      package: { ecosystem: "npm", name: "virga-fixture-a" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    },
  ],
});
const KEV: KevCatalog = {
  version: "2099.01.01",
  released: "2099-01-01T12:00:00.000Z",
  cves: new Set(["CVE-2099-0001"]),
};

/** A source with the feed and catalog above, complete or not; it records what it was asked. */
function feed(complete: boolean): AdvisorySource & { asked: string[][] } {
  const asked: string[][] = [];
  return {
    asked,
    read(packages): AdvisoryRead {
      asked.push([...packages]);
      return { configured: true, feed: readOsvFeed([RECORD]), complete, kev: KEV };
    },
  };
}

const CF_001 = RULES.filter((r) => r.id === "CF-001");

/**
 * Scans an account whose `workers` chunk holds `packages`. Before the vulns
 * step the inputs of CF-001 but `vulns` are recorded complete (`packages`
 * only when `packagesComplete`), so its run shows what the step recorded.
 */
async function scan(
  advisories: AdvisorySource,
  options: { packages?: string[]; packagesComplete?: boolean; existing?: string } = {},
) {
  const accountId = newAccountId();
  const evaluators = { ...fakeEvaluators(), rules: evaluateRules, ruleSet: CF_001, advisories };
  const { stub } = await setupAccount(accountId, evaluators);
  const scanId = `vulns-${accountId}`;
  if (options.existing) {
    // An open row from an earlier rematch, for the affected package.
    await runInDurableObject(stub, (_: AccountGraph, state) => {
      state.storage.sql.exec(
        `INSERT INTO vulns (package_id, vuln_id, aliases, severity_rank, kev, fixed_in, status, source, first_seen)
         VALUES (?, ?, '[]', 4, 0, NULL, 'open', 'osv', 1)`,
        AFFECTED,
        options.existing,
      );
    });
  }
  const nodes = (options.packages ?? [AFFECTED, UNPARSED]).map((id) => ({
    type: "package" as const,
    nativeId: id.slice("package:".length),
    name: id,
  }));
  const steps = fakeStep();
  const summary = await runScan(
    {
      step: {
        async do(name, config, callback) {
          if (name === "vulns") {
            const inputs = ["storage", "access", ...(options.packagesComplete ? ["packages"] : [])];
            for (const input of inputs) await stub.recordCoverage(scanId, input, "complete");
          }
          return steps.step.do(name, config, callback);
        },
      },
      graph: () => stub,
      index: d1ScanIndex(env.INDEX),
      reader: (id) => createReader(fixtureTransport(apiRoutes(id, initialState()))),
      collectors: [scriptedStub("workers", [{ nodes, edges: [] }])],
      clock: () => NOW + 60_000,
    },
    { accountId, scanId, now: NOW },
  );
  const coverage = await sql<{ status: string; detail: string | null }>(
    stub,
    "SELECT status, detail FROM coverage WHERE scan_id = ? AND resource_class = 'vulns'",
    scanId,
  );
  const vulns = await sql(
    stub,
    `SELECT package_id, vuln_id, severity_rank, kev, fixed_in, status, source FROM vulns
     ORDER BY package_id, vuln_id`,
  );
  const cf001 = await sql<{ status: string; missing: string | null }>(
    stub,
    "SELECT status, missing FROM rule_runs WHERE scan_id = ? AND rule_id = 'CF-001'",
    scanId,
  );
  return { summary, steps, coverage, vulns, cf001 };
}

describe("the vulns step", () => {
  it("vulns rematch: runs after the collectors and the exposure step, before the rules", async () => {
    const { steps } = await scan(feed(true), { packagesComplete: true });
    expect(steps.names()).toEqual([
      "begin",
      "plan:workers",
      "collect:workers:1",
      "coverage:workers",
      "sweep:workers",
      "exposure",
      "vulns",
      "rules",
      "finish",
    ]);
  });

  it("vulns rematch: with a complete feed and package set, records vulns complete and CF-001 runs", async () => {
    const source = feed(true);
    const { summary, steps, coverage, vulns, cf001 } = await scan(source, {
      packages: [AFFECTED],
      packagesComplete: true,
    });
    expect(source.asked).toEqual([[AFFECTED]]);
    expect(coverage).toEqual([{ status: "complete", detail: null }]);
    expect(vulns).toEqual([
      {
        package_id: AFFECTED,
        vuln_id: "GHSA-vrga-0001-test1",
        severity_rank: 4,
        kev: 1,
        fixed_in: "4.17.21",
        status: "open",
        source: "osv",
      },
    ]);
    expect(summary.vulns).toEqual({
      status: "complete",
      packages: 1,
      matched: 1,
      opened: 1,
      reopened: 0,
      updated: 0,
      fixed: 0,
      unchanged: 0,
      unknown: 0,
      unparsed: 0,
      written: 1,
    });
    expect(steps.record("vulns")?.result).toEqual(summary.vulns);
    expect(cf001).toEqual([{ status: "evaluated", missing: null }]);
    expect(summary.status).toBe("complete");
  });

  it("vulns rematch: with a feed that is not complete, writes decided rows, records vulns partial and leaves CF-001 not evaluated", async () => {
    const { summary, steps, coverage, vulns, cf001 } = await scan(feed(false), {
      packagesComplete: true,
    });
    expect(coverage).toEqual([
      { status: "partial", detail: "unparsed packages: 1; advisory feed not complete" },
    ]);
    expect(vulns).toEqual([expect.objectContaining({ package_id: AFFECTED, status: "open" })]);
    expect(summary.vulns).toMatchObject({
      status: "partial",
      packages: 2,
      opened: 1,
      unparsed: 1,
      detail: "unparsed packages: 1; advisory feed not complete",
    });
    expect(cf001).toEqual([{ status: "not_evaluated", missing: JSON.stringify(["vulns"]) }]);
    // Counts only: the step result holds no ID from the scanned account.
    const result = JSON.stringify(steps.record("vulns")?.result);
    expect(result).not.toContain("evil");
    expect(result).not.toContain("virga-fixture-a");
    // A partial vulns input does not make the scan partial: CF-001's run shows it.
    expect(summary.status).toBe("complete");
  });

  it("vulns rematch: without a feed, records vulns partial with the reason, keeps open rows and leaves CF-001 not evaluated", async () => {
    const { summary, coverage, vulns, cf001 } = await scan(NO_ADVISORY_FEED, {
      packages: [AFFECTED],
      packagesComplete: true,
      existing: "GHSA-vrga-0009-old",
    });
    const detail = "no advisory feed configured; no KEV catalog; advisory feed not complete";
    expect(coverage).toEqual([{ status: "partial", detail }]);
    // Without a feed nothing is known to be fixed.
    expect(vulns).toEqual([
      expect.objectContaining({ vuln_id: "GHSA-vrga-0009-old", status: "open" }),
    ]);
    expect(summary.vulns).toMatchObject({
      status: "partial",
      packages: 1,
      matched: 0,
      fixed: 0,
      unchanged: 1,
      written: 0,
      detail,
    });
    expect(cf001).toEqual([{ status: "not_evaluated", missing: JSON.stringify(["vulns"]) }]);
  });

  it("vulns rematch: without a feed and without packages coverage, says both", async () => {
    const { coverage, cf001 } = await scan(NO_ADVISORY_FEED, { packages: [] });
    expect(coverage).toEqual([
      {
        status: "partial",
        detail:
          "no advisory feed configured; no KEV catalog; package set not complete; advisory feed not complete",
      },
    ]);
    expect(cf001).toEqual([
      { status: "not_evaluated", missing: JSON.stringify(["packages", "vulns"]) },
    ]);
  });

  it("vulns rematch: a source that fails records vulns error, and the scan is partial", async () => {
    const failing: AdvisorySource = {
      read() {
        throw new Error("mirror unavailable");
      },
    };
    const { summary, steps, coverage, cf001 } = await scan(failing, { packagesComplete: true });
    expect(steps.record("vulns")?.attempts).toBe(1);
    expect(coverage).toEqual([{ status: "error", detail: "Error: mirror unavailable" }]);
    expect(summary.vulns).toMatchObject({
      status: "error",
      packages: 2,
      written: 0,
      detail: "Error: mirror unavailable",
    });
    expect(cf001).toEqual([{ status: "not_evaluated", missing: JSON.stringify(["vulns"]) }]);
    expect(summary.rules?.status).toBe("complete");
    expect(summary.status).toBe("partial");
  });

  it("vulns rematch: the default source reports that no feed is configured", async () => {
    expect(await NO_ADVISORY_FEED.read([AFFECTED])).toEqual({
      configured: false,
      reason: "no advisory feed configured",
    });
  });
});
