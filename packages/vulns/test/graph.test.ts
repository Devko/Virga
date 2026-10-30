import { applyVulnRematch, beginScan, listVulns, migrate } from "@virga/graph";
import { openNodeDatabase } from "@virga/graph/node";
import { describe, expect, it } from "vitest";
import { readKevCatalog } from "../src/kev.ts";
import { readOsvFeed } from "../src/osv.ts";
import { rematch } from "../src/rematch.ts";
import { fixture, osvFixtures } from "./helpers.ts";

const kevResult = readKevCatalog(fixture("kev/catalog.json"));
if (kevResult.status !== "accepted") throw new Error("KEV fixture rejected");
const kev = kevResult.catalog;

const A = "package:pkg:npm/virga-fixture-a@4.17.20";
const LIB = "package:pkg:npm/%40virga-test/lib@2.0.5";
const B = "package:pkg:npm/virga-fixture-b@2.3.4";

describe("rematch with the graph", () => {
  it("writes matches, keeps them across runs and records whether vulns is complete", () => {
    const db = openNodeDatabase();
    migrate(db);
    const feed = readOsvFeed(osvFixtures());
    const complete = { packagesComplete: true, feedComplete: true };
    const coverage = (scanId: string) =>
      db.query(
        "SELECT status, detail FROM coverage WHERE scan_id = ? AND resource_class = 'vulns'",
        scanId,
      )[0];

    beginScan(db, { id: "s1", kind: "full", at: 1 });
    const first = rematch({
      ...complete,
      packages: [A, LIB],
      feed,
      kev,
      existing: listVulns(db),
      at: 100,
    });
    expect(applyVulnRematch(db, "s1", first)).toEqual({ written: 2, complete: true });
    expect(coverage("s1")).toEqual({ status: "complete", detail: null });

    // A day later: nothing changed, nothing is written.
    beginScan(db, { id: "s2", kind: "full", at: 2 });
    const second = rematch({
      ...complete,
      packages: [A, LIB],
      feed,
      kev,
      existing: listVulns(db),
      at: 200,
    });
    expect(second.rows).toEqual([]);
    expect(applyVulnRematch(db, "s2", second)).toEqual({ written: 0, complete: true });

    // The Worker upgraded lib and added a package whose advisory has no usable severity.
    beginScan(db, { id: "s3", kind: "full", at: 3 });
    const upgraded = "package:pkg:npm/%40virga-test/lib@2.1.0";
    const third = rematch({
      ...complete,
      packages: [A, upgraded, B],
      feed,
      kev,
      existing: listVulns(db),
      at: 300,
    });
    expect(applyVulnRematch(db, "s3", third)).toEqual({ written: 1, complete: false });
    expect(coverage("s3")).toEqual({ status: "partial", detail: "unknown matches: 1" });
    expect(
      listVulns(db).map((r) => [
        r.packageId,
        r.vulnId,
        r.status,
        r.severityRank,
        r.kev,
        r.firstSeen,
      ]),
    ).toEqual([
      [LIB, "GHSA-vrga-0002-test2", "fixed", 3, true, 100],
      [A, "GHSA-vrga-0001-test1", "open", 4, false, 100],
    ]);
    db.close();
  });
});
