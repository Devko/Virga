import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  applyVulnRematch,
  beginScan,
  listVulns,
  migrate,
  upsertVulns,
  type VulnRecord,
  type VulnRematch,
} from "../src/index.ts";
import { type NodeSqlRunner, openNodeDatabase } from "../src/node.ts";

let db: NodeSqlRunner;

beforeEach(() => {
  db = openNodeDatabase();
  migrate(db);
  beginScan(db, { id: "s1", kind: "full", at: 1 });
});
afterEach(() => db.close());

const record = (vulnId: string, fields: Partial<VulnRecord> = {}): VulnRecord => ({
  packageId: "package:pkg:npm/lodash@4.17.20",
  vulnId,
  aliases: ["CVE-2099-0001"],
  severityRank: 4,
  kev: false,
  fixedIn: "4.17.21",
  status: "open",
  source: "osv",
  firstSeen: 1000,
  ...fields,
});

const rematch = (rows: VulnRecord[], fields: Partial<VulnRematch> = {}): VulnRematch => ({
  source: "osv",
  rows,
  complete: true,
  detail: null,
  ...fields,
});

const coverage = (scanId = "s1") =>
  db.query(
    "SELECT status, detail FROM coverage WHERE scan_id = ? AND resource_class = 'vulns'",
    scanId,
  )[0];

const rows = () => db.query("SELECT * FROM vulns ORDER BY package_id, vuln_id");

describe("applyVulnRematch", () => {
  it("writes the rows and records vulns coverage as complete", () => {
    const result = applyVulnRematch(
      db,
      "s1",
      rematch([record("GHSA-a"), record("GHSA-b", { kev: true })]),
    );
    expect(result).toEqual({ written: 2, complete: true });
    expect(rows()).toEqual([
      {
        package_id: "package:pkg:npm/lodash@4.17.20",
        vuln_id: "GHSA-a",
        aliases: '["CVE-2099-0001"]',
        severity_rank: 4,
        kev: 0,
        fixed_in: "4.17.21",
        status: "open",
        source: "osv",
        first_seen: 1000,
      },
      {
        package_id: "package:pkg:npm/lodash@4.17.20",
        vuln_id: "GHSA-b",
        aliases: '["CVE-2099-0001"]',
        severity_rank: 4,
        kev: 1,
        fixed_in: "4.17.21",
        status: "open",
        source: "osv",
        first_seen: 1000,
      },
    ]);
    expect(coverage()).toEqual({ status: "complete", detail: null });
  });

  it("records an incomplete result as partial with its detail", () => {
    const result = applyVulnRematch(
      db,
      "s1",
      rematch([record("GHSA-a")], { complete: false, detail: "unknown matches: 2" }),
    );
    expect(result).toEqual({ written: 1, complete: false });
    expect(coverage()).toEqual({ status: "partial", detail: "unknown matches: 2" });
  });

  it("gives an incomplete result without detail a generic one, and caps a long detail", () => {
    applyVulnRematch(db, "s1", rematch([], { complete: false, detail: null }));
    expect(coverage()).toEqual({ status: "partial", detail: "not complete" });
    applyVulnRematch(db, "s1", rematch([], { complete: false, detail: "x".repeat(2000) }));
    expect(String(coverage()?.detail)).toHaveLength(1000);
  });

  it("records coverage for an empty, complete result", () => {
    expect(applyVulnRematch(db, "s1", rematch([]))).toEqual({ written: 0, complete: true });
    expect(coverage()).toEqual({ status: "complete", detail: null });
    expect(rows()).toEqual([]);
  });

  it("updates existing rows but keeps first_seen and an ignored status", () => {
    applyVulnRematch(
      db,
      "s1",
      rematch([record("GHSA-a"), record("GHSA-b", { status: "ignored" })]),
    );
    applyVulnRematch(
      db,
      "s1",
      rematch([
        record("GHSA-a", { severityRank: 2, status: "fixed", firstSeen: 5000, aliases: [] }),
        record("GHSA-b", { status: "open", kev: true, firstSeen: 5000 }),
      ]),
    );
    expect(listVulns(db)).toEqual([
      record("GHSA-a", { severityRank: 2, status: "fixed", aliases: [] }),
      record("GHSA-b", { status: "ignored", kev: true }),
    ]);
  });

  it("splits large results over several statements in one transaction", () => {
    const many = Array.from({ length: 20_000 }, (_, i) =>
      record(`GHSA-${i}`, {
        aliases: Array.from({ length: 10 }, (_, a) => `CVE-2099-${1000 + a}`),
      }),
    );
    expect(applyVulnRematch(db, "s1", rematch(many)).written).toBe(20_000);
    expect(db.query("SELECT count(*) AS n FROM vulns")[0]).toEqual({ n: 20_000 });
  });

  it.each<[string, Partial<VulnRecord>, RegExp]>([
    ["a severity rank above 4", { severityRank: 5 as never }, /severityRank/],
    ["a fractional severity rank", { severityRank: 3.5 as never }, /severityRank/],
    ["an unknown status", { status: "closed" as never }, /status/],
    ["another source", { source: "trivy" }, /source/],
    ["a vuln ID with a space", { vulnId: "GHSA a" }, /vulnId/],
    ["a vuln ID longer than 128 characters", { vulnId: "G".repeat(129) }, /vulnId/],
    ["an invalid alias", { aliases: ["CVE 1"] }, /alias/],
    ["too many aliases", { aliases: Array.from({ length: 101 }, (_, i) => `A-${i}`) }, /aliases/],
    ["a package ID of another node type", { packageId: "worker_script:a" }, /packageId/],
    ["a package ID too long", { packageId: `package:${"a".repeat(513)}` }, /packageId/],
    ["a fixed version too long", { fixedIn: "1".repeat(257) }, /fixedIn/],
    ["a negative first_seen", { firstSeen: -1 }, /firstSeen/],
    ["a fractional first_seen", { firstSeen: 1.5 }, /firstSeen/],
    ["a KEV flag that is not a boolean", { kev: 1 as never }, /kev/],
  ])("rejects %s and writes nothing", (_, fields, error) => {
    const bad = rematch([record("GHSA-ok"), record("GHSA-bad", fields)]);
    expect(() => applyVulnRematch(db, "s1", bad)).toThrow(error);
    expect(rows()).toEqual([]);
    expect(coverage()).toBeUndefined();
  });

  it("rejects a key that occurs twice and writes nothing", () => {
    expect(() => applyVulnRematch(db, "s1", rematch([record("GHSA-a"), record("GHSA-a")]))).toThrow(
      /twice/,
    );
    expect(rows()).toEqual([]);
  });

  it("rejects an invalid source", () => {
    expect(() => applyVulnRematch(db, "s1", rematch([], { source: "OSV mirror" }))).toThrow(
      /source/,
    );
  });

  it("rolls back the rows when the coverage write fails", () => {
    db.script(`CREATE TRIGGER fail_coverage BEFORE INSERT ON coverage
      BEGIN SELECT RAISE(ABORT, 'coverage refused'); END;`);
    expect(() => applyVulnRematch(db, "s1", rematch([record("GHSA-a")]))).toThrow(
      /coverage refused/,
    );
    expect(rows()).toEqual([]);
  });
});

describe("listVulns", () => {
  it("reads every row, or the rows of one source", () => {
    upsertVulns(db, [
      { packageId: "package:pkg:npm/a@1.0.0", vulnId: "X-1", severityRank: 3, source: "fixture" },
    ]);
    applyVulnRematch(db, "s1", rematch([record("GHSA-a", { fixedIn: null, kev: true })]));
    expect(listVulns(db)).toEqual([
      {
        packageId: "package:pkg:npm/a@1.0.0",
        vulnId: "X-1",
        aliases: [],
        severityRank: 3,
        kev: false,
        fixedIn: null,
        status: "open",
        source: "fixture",
        firstSeen: expect.any(Number),
      },
      record("GHSA-a", { fixedIn: null, kev: true }),
    ]);
    expect(listVulns(db, "osv")).toEqual([record("GHSA-a", { fixedIn: null, kev: true })]);
  });

  it("reads aliases that are not a list of strings as none", () => {
    db.run(
      `INSERT INTO vulns (package_id, vuln_id, aliases, severity_rank, source, first_seen)
       VALUES ('package:pkg:npm/a@1.0.0', 'X-1', '{"a": 1}', 1, 'osv', 1),
              ('package:pkg:npm/a@1.0.0', 'X-2', '[1, "CVE-2099-0001"]', 1, 'osv', 1)`,
    );
    expect(listVulns(db).map((r) => r.aliases)).toEqual([[], []]);
  });
});
