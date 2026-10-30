import type { VulnRecord } from "@virga/graph";
import { describe, expect, it } from "vitest";
import { type KevCatalog, readKevCatalog } from "../src/kev.ts";
import { type AdvisoryFeed, readOsvFeed } from "../src/osv.ts";
import { rematch } from "../src/rematch.ts";
import { fixture, osvFixtures } from "./helpers.ts";

const AT = 1_000_000;
const EARLIER = 500;

const kevResult = readKevCatalog(fixture("kev/catalog.json"));
if (kevResult.status !== "accepted") throw new Error("KEV fixture rejected");
const kev: KevCatalog = kevResult.catalog;
const feed: AdvisoryFeed = readOsvFeed(osvFixtures());

const A = "package:pkg:npm/virga-fixture-a@4.17.20";
const A_FIXED = "package:pkg:npm/virga-fixture-a@4.17.21";
const LIB = "package:pkg:npm/%40virga-test/lib@2.0.5";
const B = "package:pkg:npm/virga-fixture-b@2.3.4";
const C = "package:pkg:npm/virga-fixture-c@3.1.0";
const PYPI = "package:pkg:pypi/virga-fixture-a@1.0";

const row = (packageId: string, vulnId: string, fields: Partial<VulnRecord> = {}): VulnRecord => ({
  packageId,
  vulnId,
  aliases: [],
  severityRank: 4,
  kev: false,
  fixedIn: null,
  status: "open",
  source: "osv",
  firstSeen: EARLIER,
  ...fields,
});

const ROW_A = row(A, "GHSA-vrga-0001-test1", {
  aliases: ["CVE-2099-0001"],
  severityRank: 4,
  fixedIn: "4.17.21",
  firstSeen: AT,
});
const ROW_LIB = row(LIB, "GHSA-vrga-0002-test2", {
  aliases: ["CVE-2099-0002"],
  severityRank: 3,
  kev: true,
  fixedIn: "2.1.0",
  firstSeen: AT,
});
const ROW_C = row(C, "GHSA-vrga-0006-test6", {
  aliases: ["CVE-2099-0006"],
  severityRank: 3,
  firstSeen: AT,
});

const run = (
  packages: string[],
  existing: VulnRecord[] = [],
  options: {
    feed?: AdvisoryFeed;
    kev?: KevCatalog | null;
    packagesComplete?: boolean;
    feedComplete?: boolean;
  } = {},
) =>
  rematch({
    packages,
    packagesComplete: options.packagesComplete ?? true,
    feed: options.feed ?? feed,
    feedComplete: options.feedComplete ?? true,
    kev: options.kev === undefined ? kev : options.kev,
    existing,
    at: AT,
  });

describe("rematch", () => {
  it("opens new matches with first_seen now, with severity, KEV and the fixed version", () => {
    const result = run([A, A_FIXED, LIB, C]);
    expect(result.rows).toEqual([ROW_LIB, ROW_A, ROW_C]);
    expect(result.complete).toBe(true);
    expect(result.detail).toBeNull();
    expect(result.unknown).toEqual([]);
    expect(result.unparsed).toEqual([]);
    expect(result.counts).toEqual({
      matched: 3,
      opened: 3,
      reopened: 0,
      updated: 0,
      fixed: 0,
      unchanged: 0,
    });
  });

  it("writes nothing when nothing changed", () => {
    const result = run([A, A_FIXED, LIB, C], [ROW_A, ROW_LIB, ROW_C]);
    expect(result.rows).toEqual([]);
    expect(result.complete).toBe(true);
    expect(result.counts).toMatchObject({ matched: 3, opened: 0, unchanged: 3 });
  });

  it("keeps first_seen of an existing row and updates its fields", () => {
    const old = {
      ...ROW_A,
      severityRank: 2 as const,
      aliases: [],
      fixedIn: null,
      firstSeen: EARLIER,
    };
    const result = run([A], [old]);
    expect(result.rows).toEqual([{ ...ROW_A, firstSeen: EARLIER }]);
    expect(result.counts).toMatchObject({ updated: 1, opened: 0 });
  });

  it("reopens a fixed row that matches again and keeps first_seen", () => {
    const result = run([A], [{ ...ROW_A, status: "fixed", firstSeen: EARLIER }]);
    expect(result.rows).toEqual([{ ...ROW_A, firstSeen: EARLIER }]);
    expect(result.counts).toMatchObject({ reopened: 1 });
  });

  it("fixes rows that no longer match and keeps their other fields", () => {
    const existing = [
      // the installed version is not affected
      row(A_FIXED, "GHSA-vrga-0001-test1", { severityRank: 4 }),
      // the advisory is withdrawn
      row(A, "GHSA-vrga-0004-test4", { severityRank: 4 }),
      // the advisory is gone from the feed
      row(A, "GHSA-vrga-gone-0000", { severityRank: 3, kev: true }),
      // the package is gone from the graph
      row("package:pkg:npm/virga-fixture-a@4.17.19", "GHSA-vrga-0001-test1"),
      // already fixed: stays as it is
      row(A_FIXED, "GHSA-vrga-old-0000", { status: "fixed" }),
    ];
    const result = run([A, A_FIXED], existing);
    expect(result.rows).toEqual([
      row("package:pkg:npm/virga-fixture-a@4.17.19", "GHSA-vrga-0001-test1", { status: "fixed" }),
      ROW_A,
      row(A, "GHSA-vrga-0004-test4", { severityRank: 4, status: "fixed" }),
      row(A, "GHSA-vrga-gone-0000", { severityRank: 3, kev: true, status: "fixed" }),
      row(A_FIXED, "GHSA-vrga-0001-test1", { severityRank: 4, status: "fixed" }),
    ]);
    expect(result.counts).toMatchObject({ fixed: 4, opened: 1, unchanged: 1 });
  });

  it("keeps ignored rows ignored, matched or not", () => {
    const ignoredMatch = {
      ...ROW_A,
      status: "ignored" as const,
      severityRank: 1 as const,
      firstSeen: 7,
    };
    const ignoredGone = row(A_FIXED, "GHSA-vrga-0001-test1", { status: "ignored" });
    const result = run([A, A_FIXED], [ignoredMatch, ignoredGone]);
    expect(result.rows).toEqual([{ ...ROW_A, status: "ignored", firstSeen: 7 }]);
    expect(result.counts).toMatchObject({ matched: 1, updated: 1, fixed: 0, unchanged: 1 });
  });

  it("reports a match without a known severity as unknown and keeps its row", () => {
    const existing = row(B, "GHSA-vrga-0003-test3", { severityRank: 4 });
    const result = run([A, B], [existing]);
    expect(result.rows).toEqual([ROW_A]);
    expect(result.unknown).toEqual([
      { packageId: B, vulnId: "GHSA-vrga-0003-test3", reason: "severity unknown" },
    ]);
    expect(result.complete).toBe(false);
    expect(result.detail).toBe("unknown matches: 1");
  });

  it("reports a range it cannot decide as unknown and keeps its row", () => {
    const record = {
      id: "GHSA-vrga-xrng-0000",
      modified: "2026-10-01T00:00:00Z",
      database_specific: { severity: "CRITICAL" },
      affected: [
        {
          package: { ecosystem: "npm", name: "virga-fixture-a" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.x" }] }],
        },
      ],
    };
    const odd = readOsvFeed([JSON.stringify(record)]);
    const existing = row(A, "GHSA-vrga-xrng-0000");
    const result = run([A], [existing], { feed: odd });
    expect(result.rows).toEqual([]);
    expect(result.unknown).toEqual([
      { packageId: A, vulnId: "GHSA-vrga-xrng-0000", reason: "version not decidable" },
    ]);
    expect(result.complete).toBe(false);
  });

  it("reports packages it cannot parse and keeps their rows", () => {
    const latest = "package:pkg:npm/virga-fixture-a@latest";
    const existing = [row(PYPI, "PYSEC-2099-5"), row(latest, "GHSA-vrga-0001-test1")];
    const result = run([A, PYPI, latest, "worker_script:x"], existing);
    expect(result.rows).toEqual([ROW_A]);
    expect(result.unparsed).toEqual([
      { packageId: latest, reason: "version is not SemVer 2.0" },
      { packageId: PYPI, reason: "unsupported purl type" },
      { packageId: "worker_script:x", reason: "not a package node ID" },
    ]);
    expect(result.complete).toBe(false);
    expect(result.detail).toBe("unparsed packages: 3");
  });

  it("keeps rows of a rejected advisory and is not complete", () => {
    const broken = { id: "GHSA-vrga-0001-test1", modified: "x", aliases: 3 };
    const withRejected = readOsvFeed([...osvFixtures(), JSON.stringify(broken)]);
    expect(withRejected.rejected).toEqual([
      { id: "GHSA-vrga-0001-test1", reason: "aliases: not an array" },
    ]);
    const existing = row(A, "GHSA-vrga-0001-test1", { severityRank: 2 });
    const result = run([A], [existing], { feed: withRejected });
    expect(result.rows).toEqual([]);
    expect(result.complete).toBe(false);
    expect(result.detail).toBe("rejected advisories: 1");
  });

  it("after a rejection without ID, fixes only rows whose advisory it read", () => {
    const withUnknown = readOsvFeed([...osvFixtures(), "not json"]);
    const existing = [
      row(A, "GHSA-vrga-gone-0000"),
      row(A, "GHSA-vrga-0004-test4"),
      row(A_FIXED, "GHSA-vrga-0001-test1"),
    ];
    const result = run([A, A_FIXED], existing, { feed: withUnknown });
    expect(result.rows).toEqual([
      ROW_A,
      row(A, "GHSA-vrga-0004-test4", { status: "fixed" }),
      row(A_FIXED, "GHSA-vrga-0001-test1", { status: "fixed" }),
    ]);
    expect(result.complete).toBe(false);
  });

  it("leaves rows of other sources alone, except a key it matches", () => {
    const other = row(A, "TRIVY-only-0000", { source: "trivy" });
    const sameKey = { ...ROW_A, source: "trivy", status: "ignored" as const, firstSeen: 3 };
    const result = run([A], [other, sameKey]);
    expect(result.rows).toEqual([{ ...ROW_A, status: "ignored", firstSeen: 3 }]);
  });

  it("without a KEV catalog, keeps the KEV flag of existing rows and is not complete", () => {
    const result = run([LIB, A], [{ ...ROW_LIB, severityRank: 2 }], { kev: null });
    expect(result.rows).toEqual([ROW_LIB, ROW_A]);
    expect(result.complete).toBe(false);
    expect(result.detail).toBe("no KEV catalog");

    const fresh = run([LIB], [], { kev: null });
    expect(fresh.rows).toEqual([{ ...ROW_LIB, kev: false }]);
  });

  it("joins several reasons in the detail", () => {
    const result = run([B, PYPI], [], { kev: null });
    expect(result.detail).toBe("unknown matches: 1; unparsed packages: 1; no KEV catalog");
  });

  it("reads package names as data, not as object keys", () => {
    const result = run([
      "package:pkg:npm/constructor@1.0.0",
      "package:pkg:npm/__proto__@1.0.0",
      "package:pkg:npm/hasOwnProperty@1.0.0",
    ]);
    expect(result.rows).toEqual([]);
    expect(result.complete).toBe(true);
  });

  it("counts a package listed twice once", () => {
    const result = run([A, A]);
    expect(result.rows).toEqual([ROW_A]);
    expect(result.counts.matched).toBe(1);
  });

  it("uses the given source", () => {
    const result = rematch({
      packages: [A],
      packagesComplete: true,
      feed,
      feedComplete: true,
      kev,
      existing: [],
      at: AT,
      source: "osv-mirror",
    });
    expect(result.rows).toEqual([{ ...ROW_A, source: "osv-mirror" }]);
    expect(result.source).toBe("osv-mirror");
  });

  it("with a package set that is not complete, keeps rows of unlisted packages", () => {
    const gone = row("package:pkg:npm/virga-fixture-a@4.17.19", "GHSA-vrga-0001-test1");
    const notAffected = row(A_FIXED, "GHSA-vrga-0001-test1");
    const result = run([A, A_FIXED], [gone, notAffected], { packagesComplete: false });
    expect(result.rows).toEqual([ROW_A, { ...notAffected, status: "fixed" }]);
    expect(result.complete).toBe(false);
    expect(result.detail).toBe("package set not complete");
  });

  it("with a feed that is not complete, keeps rows whose advisory is missing", () => {
    const missing = row(A, "GHSA-vrga-gone-0000");
    const withdrawn = row(A, "GHSA-vrga-0004-test4");
    const result = run([A], [missing, withdrawn], { feedComplete: false });
    expect(result.rows).toEqual([ROW_A, { ...withdrawn, status: "fixed" }]);
    expect(result.complete).toBe(false);
    expect(result.detail).toBe("advisory feed not complete");
  });

  describe("R9-05: npm names in either case", () => {
    const record = {
      id: "GHSA-vrga-case-0000",
      modified: "2026-10-01T00:00:00Z",
      database_specific: { severity: "CRITICAL" },
      affected: [
        {
          package: { ecosystem: "npm", name: "JSONStream" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.3.6" }] }],
        },
      ],
    };
    const cased = readOsvFeed([JSON.stringify(record)]);
    // As scanner-io's npmPurl writes it, and as npm spells the name.
    const LOWER = "package:pkg:npm/jsonstream@1.3.1";
    const KEPT = "package:pkg:npm/JSONStream@1.3.1";
    const open = (packageId: string) =>
      row(packageId, "GHSA-vrga-case-0000", { fixedIn: "1.3.6", firstSeen: AT });

    it.each([LOWER, KEPT])("matches %s and keeps its node ID", (packageId) => {
      const result = run([packageId], [], { feed: cased });
      expect(result.rows).toEqual([open(packageId)]);
      expect(result.complete).toBe(true);
    });

    it("opens the lower-case node when it replaces the one with capitals", () => {
      const old = row(KEPT, "GHSA-vrga-case-0000", { fixedIn: "1.3.6" });
      const result = run([LOWER], [old], { feed: cased });
      expect(result.rows).toEqual([{ ...old, status: "fixed" }, open(LOWER)]);
      expect(result.counts).toMatchObject({ opened: 1, fixed: 1 });
      expect(result.complete).toBe(true);
    });

    it("matches both spellings in one run, one row each", () => {
      const result = run([LOWER, KEPT], [], { feed: cased });
      expect(result.rows).toEqual([open(KEPT), open(LOWER)]);
    });
  });

  it("does not take an empty feed for the end of every advisory unless it is complete", () => {
    const empty = readOsvFeed([]);
    const open = row(A, "GHSA-vrga-0001-test1");
    expect(run([A], [open], { feed: empty, feedComplete: false }).rows).toEqual([]);
    expect(run([A], [open], { feed: empty }).rows).toEqual([{ ...open, status: "fixed" }]);
  });
});
