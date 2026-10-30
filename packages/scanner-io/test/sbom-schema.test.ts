// Decision 0010: the generator's SBOMs validate against the vendored
// CycloneDX 1.6 JSON schema. sbom.test.ts validates every SBOM it builds;
// this file checks the vendored files and the validator, and adds hostile
// names and versions. A limitation of the validator fails a test here.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dereference, type Schema } from "@cfworker/json-schema";
import { describe, expect, it } from "vitest";
import {
  buildWorkerSbom,
  PACKAGE_SOURCES,
  type SbomPackage,
  serializeSbom,
  type WorkerSbomInput,
} from "../src/sbom.ts";
import {
  loadSchema,
  OWN_ENTRIES,
  SCHEMA_DIR,
  SCHEMA_FILES,
  schemaProblems,
  UNCHECKED_FORMATS,
  VALIDATOR_FORMATS,
} from "./cdx-schema.ts";

/** As recorded in schema/cyclonedx-1.6/README.md. */
const VENDORED: Record<string, { bytes: number; sha256: string }> = {
  "bom-1.6.schema.json": {
    bytes: 262_666,
    sha256: "18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d",
  },
  "spdx.schema.json": {
    bytes: 14_830,
    sha256: "c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6",
  },
  "jsf-0.82.schema.json": {
    bytes: 8_058,
    sha256: "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
  },
};

// biome-ignore lint/suspicious/noExplicitAny: the mutations reach into any part of the document
type Doc = Record<string, any>;

const VERSION_ID = "0f8e7d6c-5b4a-4392-8a1b-0c9d8e7f6a5b";
const SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";

const input = (overrides: Partial<WorkerSbomInput> = {}): WorkerSbomInput => ({
  worker: { scriptName: "api-gateway", versionId: VERSION_ID },
  packages: [
    {
      purl: "pkg:npm/lodash@4.17.20",
      name: "lodash",
      version: "4.17.20",
      source: "package_dependencies",
      confidence: 2,
    },
  ],
  tool: { version: "0.1.0" },
  timestamp: Date.UTC(2026, 9, 30, 12, 0, 0),
  serialNumber: SERIAL,
  ...overrides,
});

/** The stored form, parsed back. */
const stored = (overrides: Partial<WorkerSbomInput> = {}) =>
  JSON.parse(serializeSbom(buildWorkerSbom(input(overrides))));

/** Every node of a schema that has `key`. */
function nodesWith(value: unknown, key: string, out: Record<string, unknown>[] = []) {
  if (Array.isArray(value)) {
    for (const item of value) nodesWith(item, key, out);
  } else if (value !== null && typeof value === "object") {
    const node = value as Record<string, unknown>;
    if (key in node) out.push(node);
    for (const item of Object.values(node)) nodesWith(item, key, out);
  }
  return out;
}

describe("CycloneDX schema validation (decision 0010)", () => {
  it.each(SCHEMA_FILES)("decision 0010: %s is the vendored file, unchanged", (name) => {
    const bytes = readFileSync(new URL(name, SCHEMA_DIR));
    expect({
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    }).toEqual(VENDORED[name]);
  });

  it("decision 0010: the validator has no format of its own for the guarded names", () => {
    expect(OWN_ENTRIES).toEqual([]);
  });

  it("decision 0010: every format in the schemas is checked by the validator or guarded", () => {
    const used = new Set<string>();
    for (const name of SCHEMA_FILES) {
      for (const node of nodesWith(loadSchema(name), "format")) {
        if (typeof node.format === "string") used.add(node.format);
      }
    }
    const unchecked = [...used].filter((f) => !VALIDATOR_FORMATS.has(f)).sort();
    expect(unchecked).toEqual([...UNCHECKED_FORMATS].sort());
    expect(used).toContain("date-time");
  });

  it("decision 0010: every $ref in the schemas resolves", () => {
    const schemas = SCHEMA_FILES.map(loadSchema);
    const lookup: Record<string, Schema | boolean> = Object.create(null);
    for (const schema of schemas) dereference(schema, lookup);
    const refs = schemas.flatMap((schema) => nodesWith(schema, "$ref"));
    expect(refs.length).toBeGreaterThan(100);
    const missing = refs
      .map((node) => (node as { __absolute_ref__?: string }).__absolute_ref__ ?? String(node.$ref))
      .filter((uri) => lookup[uri] === undefined);
    expect(missing).toEqual([]);
    // The two files bom-1.6 refers to are among them.
    expect(refs.map((node) => node.$ref)).toEqual(
      expect.arrayContaining(["spdx.schema.json", "jsf-0.82.schema.json#/definitions/signature"]),
    );
  });

  it("decision 0010: a generated SBOM validates", () => {
    expect(schemaProblems(stored())).toEqual([]);
  });

  // The validator must be live: each of these breaks the schema.
  it.each([
    ["a wrong format", (b: Doc) => (b.bomFormat = "SPDX")],
    ["a bad serial number", (b: Doc) => (b.serialNumber = "urn:uuid:x")],
    ["a version of zero", (b: Doc) => (b.version = 0)],
    ["an unknown member", (b: Doc) => (b.extra = true)],
    ["an unknown component type", (b: Doc) => (b.components[0].type = "lib")],
    ["a component without a name", (b: Doc) => delete b.components[0].name],
    ["an impossible timestamp", (b: Doc) => (b.metadata.timestamp = "2026-02-30T12:00:00.000Z")],
    [
      "an unknown SPDX license",
      (b: Doc) => (b.components[0].licenses = [{ license: { id: "NOPE-1.0" } }]),
    ],
    ["a signature without a value", (b: Doc) => (b.signature = { algorithm: "RS256" })],
  ])("decision 0010: the validator rejects %s", (_, mutate) => {
    const bom = stored();
    mutate(bom);
    expect(schemaProblems(bom).length).toBeGreaterThan(0);
  });

  it.each([
    [
      "iri-reference",
      (b: Doc) => (b.externalReferences = [{ type: "website", url: "https://x.test" }]),
    ],
    ["idn-email", (b: Doc) => (b.metadata.authors = [{ name: "a", email: "a@example.com" }])],
  ])("decision 0010: a document that reaches %s fails", (name, mutate) => {
    const bom = stored();
    mutate(bom);
    expect(schemaProblems(bom)).toContain(
      `reached format ${name}, which the validator cannot check`,
    );
  });

  describe("hostile names and versions (decision 0010)", () => {
    const hostile = [
      'x","components":[],"y":"',
      "</script><script>alert(1)</script>",
      ["{{7*7}}", "$", "{7*7}`$(id)`"].join(""),
      "\\\\'\"\\u0000",
      "日本語のパッケージ",
      "😀💥",
      "café ünïcødé",
      "a".repeat(512),
      " leading and trailing ",
      "-",
      "%00%2F..%2F",
      "../../etc/passwd",
    ];

    it("decision 0010: hostile package names and versions validate", () => {
      const packages: SbomPackage[] = hostile.map((text, i) => ({
        purl: `pkg:npm/p${i}@1.0.${i}`,
        name: text.slice(0, 512),
        version: text.slice(0, 256),
        source: PACKAGE_SOURCES[i % PACKAGE_SOURCES.length] ?? "banner",
        confidence: (i % 3) as 0 | 1 | 2,
      }));
      expect(schemaProblems(stored({ packages }))).toEqual([]);
    });

    const labelled = hostile.map((t) => [
      t.length > 40 ? `${t.slice(0, 8)}... (${t.length} characters)` : t,
      t,
    ]);

    it.each(labelled)("decision 0010: the script name %s validates", (_, scriptName) => {
      expect(schemaProblems(stored({ worker: { scriptName, versionId: VERSION_ID } }))).toEqual([]);
    });

    it("decision 0010: hostile purls, many packages and edge times validate", () => {
      const packages: SbomPackage[] = Array.from({ length: 1_000 }, (_, i) => ({
        purl:
          i % 2 === 0
            ? `pkg:npm/%40scope${i}/name@1.0.0-rc.${i}%2Bbuild`
            : `pkg:apk/alpine/musl${i}@1.2.4-r${i}?arch=x86_64&distro=3.19.1`,
        name: `n${i}`,
        version: `v${i}`,
        source: "sbom",
        confidence: 0,
      }));
      for (const timestamp of [0, Date.UTC(9999, 11, 31, 23, 59, 59, 999)]) {
        expect(schemaProblems(stored({ packages, timestamp }))).toEqual([]);
      }
      const { serialNumber: _, ...random } = input({ packages: [] });
      expect(schemaProblems(JSON.parse(serializeSbom(buildWorkerSbom(random))))).toEqual([]);
    });
  });
});
