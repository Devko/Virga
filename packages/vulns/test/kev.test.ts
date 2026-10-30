import { describe, expect, it } from "vitest";
import { isKnownExploited, KEV_LIMITS, readKevCatalog } from "../src/kev.ts";
import { fixture } from "./helpers.ts";

type Json = Record<string, unknown>;

const entry = (cveID: unknown): Json => ({
  cveID,
  vendorProject: "Virga test",
  product: "p",
  vulnerabilityName: "n",
  dateAdded: "2099-01-01",
  shortDescription: "s",
  requiredAction: "r",
  dueDate: "2099-01-22",
});

const catalog = (mutate: (c: Json & { vulnerabilities: Json[] }) => void = () => {}): string => {
  const c = {
    title: "t",
    catalogVersion: "2099.01.02",
    dateReleased: "2099-01-02T00:00:00.000Z",
    count: 1,
    vulnerabilities: [entry("CVE-2099-0001")],
  };
  mutate(c);
  return JSON.stringify(c);
};

describe("readKevCatalog", () => {
  it("reads the CVE IDs, the catalog version and the release date", () => {
    const result = readKevCatalog(fixture("kev/catalog.json"));
    expect(result.status).toBe("accepted");
    if (result.status !== "accepted") return;
    expect(result.catalog.version).toBe("2099.01.01");
    expect(result.catalog.released).toBe("2099-01-01T12:00:00.000Z");
    expect([...result.catalog.cves].sort()).toEqual(["CVE-2099-0002", "CVE-2099-12345"]);
  });

  it("ignores the fields it does not need, whatever they hold", () => {
    const result = readKevCatalog(
      catalog((c) => {
        c.title = 1;
        c.vulnerabilities = [{ cveID: "CVE-2099-0001", notes: { x: 1 }, cwes: "no" }];
      }),
    );
    expect(result.status).toBe("accepted");
  });

  it("accepts an empty catalog and repeated IDs", () => {
    expect(
      readKevCatalog(
        catalog((c) => {
          c.count = 0;
          c.vulnerabilities = [];
        }),
      ).status,
    ).toBe("accepted");
    const twice = readKevCatalog(
      catalog((c) => {
        c.count = 2;
        c.vulnerabilities.push(entry("CVE-2099-0001"));
      }),
    );
    expect(twice.status === "accepted" && twice.catalog.cves.size).toBe(1);
  });

  it.each<[string, (c: Json & { vulnerabilities: Json[] }) => void, string]>([
    ["no catalog version", (c) => delete c.catalogVersion, "catalogVersion: missing"],
    ["a numeric catalog version", (c) => (c.catalogVersion = 2099), "catalogVersion: not a string"],
    [
      "a catalog version too long",
      (c) => (c.catalogVersion = "9".repeat(65)),
      "catalogVersion: longer than 64 characters",
    ],
    ["no release date", (c) => delete c.dateReleased, "dateReleased: missing"],
    ["no count", (c) => delete c.count, "count: missing"],
    ["a count that is not an integer", (c) => (c.count = 1.5), "count: not an integer"],
    ["a count that does not match", (c) => (c.count = 2), "count: 2 but 1 vulnerabilities"],
    [
      "no vulnerabilities",
      (c) => Reflect.deleteProperty(c, "vulnerabilities"),
      "vulnerabilities: missing",
    ],
    [
      "vulnerabilities not an array",
      (c) => (c.vulnerabilities = {} as never),
      "vulnerabilities: not an array",
    ],
    [
      "an entry that is not an object",
      (c) => (c.vulnerabilities = ["CVE-2099-0001"] as never),
      "vulnerabilities[0]: not an object",
    ],
    [
      "an entry without cveID",
      (c) => (c.vulnerabilities = [{}]),
      "vulnerabilities[0].cveID: missing",
    ],
    [
      "a lowercase cveID",
      (c) => (c.vulnerabilities = [entry("cve-2099-0001")]),
      "vulnerabilities[0].cveID: invalid",
    ],
    [
      "a short sequence number",
      (c) => (c.vulnerabilities = [entry("CVE-2099-123")]),
      "vulnerabilities[0].cveID: invalid",
    ],
    [
      "a two-digit year",
      (c) => (c.vulnerabilities = [entry("CVE-99-1234")]),
      "vulnerabilities[0].cveID: invalid",
    ],
    [
      "a sequence number of 20 digits",
      (c) => (c.vulnerabilities = [entry(`CVE-2099-${"1".repeat(20)}`)]),
      "vulnerabilities[0].cveID: invalid",
    ],
    [
      "a cveID with a newline",
      (c) => (c.vulnerabilities = [entry("CVE-2099-0001\n")]),
      "vulnerabilities[0].cveID: invalid",
    ],
    [
      "a GHSA ID",
      (c) => (c.vulnerabilities = [entry("GHSA-vrga-0001-test1")]),
      "vulnerabilities[0].cveID: invalid",
    ],
  ])("rejects %s", (_, mutate, reason) => {
    expect(readKevCatalog(catalog(mutate))).toEqual({ status: "rejected", reason });
  });

  it("rejects text that is not a JSON object", () => {
    expect(readKevCatalog("{")).toEqual({ status: "rejected", reason: "not valid JSON" });
    expect(readKevCatalog("[]")).toEqual({ status: "rejected", reason: "not a JSON object" });
    expect(readKevCatalog(undefined as never)).toEqual({ status: "rejected", reason: "not text" });
  });

  it("rejects more entries than the limit", () => {
    const text = catalog((c) => {
      c.count = KEV_LIMITS.entries + 1;
      c.vulnerabilities = Array.from({ length: KEV_LIMITS.entries + 1 }, () => ({
        cveID: "CVE-2099-0001",
      }));
    });
    expect(readKevCatalog(text)).toEqual({
      status: "rejected",
      reason: `vulnerabilities: more than ${KEV_LIMITS.entries} entries`,
    });
  });

  it("rejects a catalog larger than the size limit before it parses it", () => {
    const text = catalog((c) => {
      c.title = "x".repeat(KEV_LIMITS.catalogBytes);
    });
    expect(readKevCatalog(text)).toEqual({
      status: "rejected",
      reason: `larger than ${KEV_LIMITS.catalogBytes} bytes`,
    });
  });
});

describe("isKnownExploited", () => {
  const result = readKevCatalog(fixture("kev/catalog.json"));
  if (result.status !== "accepted") throw new Error("fixture rejected");
  const kev = result.catalog;

  it("matches the ID or any alias", () => {
    expect(isKnownExploited(kev, "CVE-2099-0002", [])).toBe(true);
    expect(isKnownExploited(kev, "GHSA-vrga-0002-test2", ["CVE-2099-0002"])).toBe(true);
    expect(isKnownExploited(kev, "GHSA-vrga-0002-test2", ["CVE-2099-9999", "CVE-2099-12345"])).toBe(
      true,
    );
    expect(isKnownExploited(kev, "GHSA-vrga-0001-test1", ["CVE-2099-0001"])).toBe(false);
    expect(isKnownExploited(kev, "GHSA-vrga-0001-test1", [])).toBe(false);
  });
});
