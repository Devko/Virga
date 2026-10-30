import { describe, expect, it } from "vitest";
import { OSV_LIMITS, readOsvFeed, readOsvRecord } from "../src/osv.ts";
import { fixture, osvFixtures } from "./helpers.ts";

type Json = Record<string, unknown>;

const base = (): Json => ({
  schema_version: "1.9.2",
  id: "GHSA-vrga-base-0000",
  modified: "2026-10-01T00:00:00Z",
  aliases: ["CVE-2099-1000"],
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
  affected: [
    {
      package: { ecosystem: "npm", name: "virga-fixture-a" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.0" }] }],
      versions: ["0.9.0"],
    },
  ],
});

/** The record after `mutate`, read back. */
const read = (mutate: (record: Json & { affected: Json[] }) => void) => {
  const record = base() as Json & { affected: Json[] };
  mutate(record);
  return readOsvRecord(JSON.stringify(record));
};

const entry = (record: { affected: Json[] }, i = 0) => record.affected[i] as Json;
const range = (record: { affected: Json[] }, r = 0) =>
  (entry(record).ranges as Json[])[r] as Json & { events: Json[] };

describe("readOsvRecord", () => {
  it("reads an npm record with only the fields matching needs", () => {
    expect(readOsvRecord(fixture("osv/GHSA-vrga-0001-test1.json"))).toEqual({
      status: "accepted",
      skippedEntries: 0,
      advisory: {
        id: "GHSA-vrga-0001-test1",
        modified: "2026-10-01T12:00:00Z",
        aliases: ["CVE-2099-0001"],
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        databaseSeverity: "CRITICAL",
        affected: [
          {
            name: "virga-fixture-a",
            ranges: [
              {
                type: "SEMVER",
                events: [
                  { kind: "introduced", version: "0" },
                  { kind: "fixed", version: "4.17.21" },
                ],
              },
            ],
            versions: ["4.17.19", "4.17.20"],
            severity: null,
          },
        ],
      },
    });
  });

  it("keeps the npm entries of a mixed record and counts the others", () => {
    const result = readOsvRecord(fixture("osv/GHSA-vrga-0006-test6.json"));
    expect(result.status).toBe("accepted");
    if (result.status !== "accepted") return;
    expect(result.skippedEntries).toBe(1);
    expect(result.advisory.affected).toEqual([
      {
        name: "virga-fixture-c",
        ranges: [
          {
            type: "SEMVER",
            events: [
              { kind: "introduced", version: "3.0.0" },
              { kind: "limit", version: "4.0.0" },
            ],
          },
        ],
        versions: [],
        severity: [{ type: "CVSS_V3", score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }],
      },
    ]);
    expect(result.advisory.severity).toEqual([]);
    expect(result.advisory.databaseSeverity).toBeNull();
  });

  it("skips a record without npm packages and counts its entries", () => {
    expect(readOsvRecord(fixture("osv/PYSEC-2099-5.json"))).toEqual({
      status: "skipped",
      id: "PYSEC-2099-5",
      skippedEntries: 1,
    });
    expect(read((r) => Reflect.deleteProperty(r, "affected"))).toEqual({
      status: "skipped",
      id: "GHSA-vrga-base-0000",
      skippedEntries: 0,
    });
  });

  it("does not use a withdrawn record", () => {
    expect(readOsvRecord(fixture("osv/GHSA-vrga-0004-test4.json"))).toEqual({
      status: "withdrawn",
      id: "GHSA-vrga-0004-test4",
    });
  });

  it("still rejects a withdrawn record that is malformed", () => {
    expect(
      read((r) => {
        r.withdrawn = "2026-10-02T00:00:00Z";
        r.aliases = "CVE-2099-1000";
      }),
    ).toEqual({ status: "rejected", id: "GHSA-vrga-base-0000", reason: "aliases: not an array" });
  });

  it("treats null optional fields as missing", () => {
    const result = read((r) => {
      r.aliases = null;
      r.withdrawn = null;
      r.database_specific = null;
      r.schema_version = null;
      entry(r).versions = null;
      entry(r).severity = null;
    });
    expect(result.status).toBe("accepted");
  });

  it("ignores fields it does not need, whatever they hold", () => {
    const result = read((r) => {
      r.details = { not: "a string" };
      r.references = 7;
      r.credits = "x";
      r.database_specific = { cwe_ids: 3, severity: "LOW" };
      entry(r).ecosystem_specific = [1, 2];
      entry(r).database_specific = "x";
      (entry(r).package as Json).purl = 5;
    });
    expect(result.status).toBe("accepted");
    if (result.status === "accepted") expect(result.advisory.databaseSeverity).toBe("LOW");
  });

  it("does not validate the entries of other ecosystems beyond the package", () => {
    const result = read((r) => {
      r.affected.push({ package: { ecosystem: "PyPI", name: 3 }, ranges: "not an array" });
    });
    expect(result).toMatchObject({ status: "accepted", skippedEntries: 1 });
  });

  it.each<[string, (r: Json & { affected: Json[] }) => void, string]>([
    ["missing id", (r) => delete r.id, "id: missing"],
    ["an id with a space", (r) => (r.id = "GHSA vrga"), "id: invalid"],
    ["an empty id", (r) => (r.id = ""), "id: invalid"],
    ["an id longer than 128 characters", (r) => (r.id = `X-${"a".repeat(127)}`), "id: invalid"],
    ["missing modified", (r) => delete r.modified, "modified: missing"],
    ["modified not a string", (r) => (r.modified = 1), "modified: not a string"],
    ["schema version 2", (r) => (r.schema_version = "2.0.0"), "schema_version: unsupported"],
    [
      "schema version without patch",
      (r) => (r.schema_version = "1.7"),
      "schema_version: unsupported",
    ],
    ["aliases not an array", (r) => (r.aliases = "CVE-2099-1000"), "aliases: not an array"],
    ["an invalid alias", (r) => (r.aliases = ["CVE 2099"]), "aliases[0]: invalid"],
    [
      "too many aliases",
      (r) => (r.aliases = Array.from({ length: 101 }, (_, i) => `CVE-2099-${1000 + i}`)),
      "aliases: more than 100 entries",
    ],
    ["withdrawn not a string", (r) => (r.withdrawn = true), "withdrawn: not a string"],
    ["severity not an array", (r) => (r.severity = "HIGH"), "severity: not an array"],
    [
      "a severity without score",
      (r) => (r.severity = [{ type: "CVSS_V3" }]),
      "severity[0].score: missing",
    ],
    [
      "a severity type too long",
      (r) => (r.severity = [{ type: "X".repeat(33), score: "1" }]),
      "severity[0].type: longer than 32 characters",
    ],
    [
      "a severity score too long",
      (r) => (r.severity = [{ type: "CVSS_V3", score: "C".repeat(257) }]),
      "severity[0].score: longer than 256 characters",
    ],
    [
      "too many severities",
      (r) => (r.severity = Array.from({ length: 17 }, () => ({ type: "CVSS_V3", score: "x" }))),
      "severity: more than 16 entries",
    ],
    [
      "severity at the top and in a package",
      (r) => (entry(r).severity = [{ type: "CVSS_V3", score: "x" }]),
      "affected[0].severity: also set at the top level",
    ],
    [
      "database severity not a string",
      (r) => (r.database_specific = { severity: 4 }),
      "database_specific.severity: not a string",
    ],
    [
      "database_specific not an object",
      (r) => (r.database_specific = ["HIGH"]),
      "database_specific: not an object",
    ],
    ["affected not an array", (r) => (r.affected = {} as never), "affected: not an array"],
    [
      "too many affected entries",
      (r) => (r.affected = Array.from({ length: 1001 }, () => entry(base() as never))),
      "affected: more than 1000 entries",
    ],
    [
      "an affected entry not an object",
      (r) => (r.affected[0] = "npm" as never),
      "affected[0]: not an object",
    ],
    [
      "a package not an object",
      (r) => (entry(r).package = "npm"),
      "affected[0].package: not an object",
    ],
    [
      "an ecosystem not a string",
      (r) => (entry(r).package = { ecosystem: 1, name: "a" }),
      "affected[0].package.ecosystem: not a string",
    ],
    [
      "an npm name missing",
      (r) => (entry(r).package = { ecosystem: "npm" }),
      "affected[0].package.name: missing",
    ],
    [
      "an npm name too long",
      (r) => (entry(r).package = { ecosystem: "npm", name: "a".repeat(257) }),
      "affected[0].package.name: longer than 256 characters",
    ],
    ["ranges not an array", (r) => (entry(r).ranges = {}), "affected[0].ranges: not an array"],
    [
      "too many ranges",
      (r) => (entry(r).ranges = Array.from({ length: 101 }, () => range(base() as never))),
      "affected[0].ranges: more than 100 entries",
    ],
    [
      "a range not an object",
      (r) => (entry(r).ranges = [1]),
      "affected[0].ranges[0]: not an object",
    ],
    [
      "an unknown range type",
      (r) => (range(r).type = "SEMVER2"),
      "affected[0].ranges[0].type: unsupported",
    ],
    [
      "missing events",
      (r) => Reflect.deleteProperty(range(r), "events"),
      "affected[0].ranges[0].events: missing",
    ],
    ["no events", (r) => (range(r).events = []), "affected[0].ranges[0].events: empty"],
    [
      "too many events",
      (r) =>
        (range(r).events = [
          { introduced: "0" },
          ...Array.from({ length: 500 }, (_, i) => ({ fixed: `1.0.${i}` })),
        ]),
      "affected[0].ranges[0].events: more than 500 entries",
    ],
    [
      "an event with two types",
      (r) => (range(r).events[0] = { introduced: "0", fixed: "1.0.0" }),
      "affected[0].ranges[0].events[0]: not exactly one event type",
    ],
    [
      "an event without a known type",
      (r) => (range(r).events[0] = { introduces: "0" }),
      "affected[0].ranges[0].events[0]: not exactly one event type",
    ],
    [
      "an event value not a string",
      (r) => (range(r).events[1] = { fixed: 1 }),
      "affected[0].ranges[0].events[1].fixed: not a string",
    ],
    [
      "an empty event value",
      (r) => (range(r).events[1] = { fixed: "" }),
      "affected[0].ranges[0].events[1].fixed: empty",
    ],
    [
      "an event value too long",
      (r) => (range(r).events[1] = { fixed: `1.0.0-${"a".repeat(251)}` }),
      "affected[0].ranges[0].events[1].fixed: longer than 256 characters",
    ],
    [
      "no introduced event",
      (r) => (range(r).events = [{ fixed: "1.0.0" }]),
      "affected[0].ranges[0].events: no introduced event",
    ],
    [
      "fixed and last_affected in one range",
      (r) => range(r).events.push({ last_affected: "0.9.9" }),
      "affected[0].ranges[0].events: both fixed and last_affected",
    ],
    [
      "versions not an array",
      (r) => (entry(r).versions = "1.0.0"),
      "affected[0].versions: not an array",
    ],
    [
      "a version not a string",
      (r) => (entry(r).versions = [1]),
      "affected[0].versions[0]: not a string",
    ],
    [
      "a version too long",
      (r) => (entry(r).versions = [`1.0.0-${"a".repeat(251)}`]),
      "affected[0].versions[0]: longer than 256 characters",
    ],
    [
      "too many versions",
      (r) =>
        (entry(r).versions = Array.from({ length: OSV_LIMITS.versions + 1 }, (_, i) => `0.0.${i}`)),
      `affected[0].versions: more than ${OSV_LIMITS.versions} entries`,
    ],
  ])("rejects %s", (_, mutate, reason) => {
    const id = reason.startsWith("id:") ? null : "GHSA-vrga-base-0000";
    expect(read(mutate)).toEqual({ status: "rejected", id, reason });
  });

  it("rejects text that is not a JSON object", () => {
    expect(readOsvRecord("{")).toEqual({ status: "rejected", id: null, reason: "not valid JSON" });
    expect(readOsvRecord("[]")).toEqual({
      status: "rejected",
      id: null,
      reason: "not a JSON object",
    });
    expect(readOsvRecord("null")).toEqual({
      status: "rejected",
      id: null,
      reason: "not a JSON object",
    });
    expect(readOsvRecord(42 as never)).toEqual({
      status: "rejected",
      id: null,
      reason: "not text",
    });
  });

  it("rejects a record larger than the size limit before it parses it", () => {
    const padding = "x".repeat(OSV_LIMITS.recordBytes);
    const record = JSON.stringify({ ...base(), details: padding });
    expect(readOsvRecord(record)).toEqual({
      status: "rejected",
      id: null,
      reason: `larger than ${OSV_LIMITS.recordBytes} bytes`,
    });
  });

  it("counts the size in UTF-8 bytes", () => {
    const filler = "é".repeat(Math.floor(OSV_LIMITS.recordBytes / 2));
    const record = JSON.stringify({ ...base(), details: filler });
    expect(record.length).toBeLessThan(OSV_LIMITS.recordBytes);
    expect(readOsvRecord(record)).toMatchObject({ status: "rejected", id: null });
  });

  it("reads keys like __proto__ and constructor as plain data", () => {
    const text = `{"__proto__": {"polluted": true}, "id": "GHSA-vrga-base-0000", "modified": "x",
      "affected": [{"package": {"ecosystem": "npm", "name": "constructor"},
      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}`;
    const result = readOsvRecord(text);
    expect(result.status).toBe("accepted");
    expect(({} as Json).polluted).toBeUndefined();
  });
});

describe("readOsvFeed", () => {
  it("collects advisories, withdrawn and skipped IDs, and counts", () => {
    const feed = readOsvFeed(osvFixtures());
    expect(feed.advisories.map((a) => a.id).sort()).toEqual([
      "GHSA-vrga-0001-test1",
      "GHSA-vrga-0002-test2",
      "GHSA-vrga-0003-test3",
      "GHSA-vrga-0006-test6",
    ]);
    expect(feed.withdrawn).toEqual(["GHSA-vrga-0004-test4"]);
    expect(feed.skipped).toEqual(["PYSEC-2099-5"]);
    expect(feed.skippedEntries).toBe(2);
    expect(feed.rejected).toEqual([]);
  });

  it("rejects every record of an ID that occurs more than once", () => {
    const record = JSON.stringify(base());
    const feed = readOsvFeed([record, record, fixture("osv/GHSA-vrga-0001-test1.json")]);
    expect(feed.advisories.map((a) => a.id)).toEqual(["GHSA-vrga-0001-test1"]);
    expect(feed.rejected).toEqual([{ id: "GHSA-vrga-base-0000", reason: "duplicate id" }]);
  });

  it("drops an ID that has a rejected record", () => {
    const bad = { ...base(), aliases: 1 };
    const feed = readOsvFeed([JSON.stringify(base()), JSON.stringify(bad)]);
    expect(feed.advisories).toEqual([]);
    expect(feed.rejected).toEqual([{ id: "GHSA-vrga-base-0000", reason: "aliases: not an array" }]);
  });

  it("keeps rejections without an ID", () => {
    const feed = readOsvFeed(["{", JSON.stringify(base())]);
    expect(feed.advisories).toHaveLength(1);
    expect(feed.rejected).toEqual([{ id: null, reason: "not valid JSON" }]);
  });
});
