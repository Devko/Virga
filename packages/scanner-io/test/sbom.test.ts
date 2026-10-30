import { describe, expect, it } from "vitest";
import {
  buildWorkerSbom,
  CYCLONEDX_SCHEMA,
  checkSbom,
  SbomInputError,
  type SbomPackage,
  serializeSbom,
  type WorkerSbomInput,
} from "../src/sbom.ts";
import { RIGHT_TO_LEFT_OVERRIDE } from "./chars.ts";

const SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";
const VERSION_ID = "0f8e7d6c-5b4a-4392-8a1b-0c9d8e7f6a5b";

const packages: SbomPackage[] = [
  {
    purl: "pkg:npm/lodash@4.17.20",
    name: "lodash",
    version: "4.17.20",
    source: "package_dependencies",
    confidence: 2,
  },
  {
    purl: "pkg:npm/%40babel/traverse@7.22.0",
    name: "@babel/traverse",
    version: "7.22.0",
    source: "sourcemap",
    confidence: 1,
  },
];

const input = (overrides: Partial<WorkerSbomInput> = {}): WorkerSbomInput => ({
  worker: { scriptName: "api-gateway", versionId: VERSION_ID },
  packages,
  tool: { version: "0.1.0" },
  timestamp: Date.UTC(2026, 9, 30, 12, 0, 0),
  serialNumber: SERIAL,
  ...overrides,
});

const clone = <T>(value: T): T => structuredClone(value);

// biome-ignore lint/suspicious/noExplicitAny: the mutations reach into any part of the document
type Doc = Record<string, any>;

describe("buildWorkerSbom", () => {
  it("emits a CycloneDX 1.6 document for one Worker version", () => {
    const bom = buildWorkerSbom(input());
    expect(bom).toEqual({
      $schema: CYCLONEDX_SCHEMA,
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber: SERIAL,
      version: 1,
      metadata: {
        timestamp: "2026-10-30T12:00:00.000Z",
        tools: { components: [{ type: "application", name: "virga", version: "0.1.0" }] },
        component: {
          type: "application",
          "bom-ref": `worker_version:${VERSION_ID}`,
          name: "api-gateway",
          version: VERSION_ID,
        },
      },
      components: [
        {
          type: "library",
          "bom-ref": "pkg:npm/%40babel/traverse@7.22.0",
          name: "@babel/traverse",
          version: "7.22.0",
          purl: "pkg:npm/%40babel/traverse@7.22.0",
          properties: [
            { name: "virga:confidence", value: "medium" },
            { name: "virga:source", value: "sourcemap" },
          ],
        },
        {
          type: "library",
          "bom-ref": "pkg:npm/lodash@4.17.20",
          name: "lodash",
          version: "4.17.20",
          purl: "pkg:npm/lodash@4.17.20",
          properties: [
            { name: "virga:confidence", value: "high" },
            { name: "virga:source", value: "package_dependencies" },
          ],
        },
      ],
    });
    expect(checkSbom(bom)).toEqual([]);
  });

  it("draws a random v4 serial number when none is given", () => {
    const { serialNumber: _, ...rest } = input();
    const a = buildWorkerSbom(rest);
    const b = buildWorkerSbom(rest);
    expect(a.serialNumber).toMatch(
      /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(a.serialNumber).not.toBe(b.serialNumber);
  });

  it("is deterministic: the same packages in any order give the same bytes", () => {
    const reversed = buildWorkerSbom(input({ packages: [...packages].reverse() }));
    expect(serializeSbom(reversed)).toBe(serializeSbom(buildWorkerSbom(input())));
  });

  it("keeps one component per purl, with the highest confidence", () => {
    const first = packages[0] as SbomPackage;
    const banner: SbomPackage = { ...first, source: "banner", confidence: 0 };
    const bom = buildWorkerSbom(input({ packages: [banner, ...packages] }));
    expect(bom.components).toHaveLength(2);
    expect(bom.components[1]?.properties).toEqual([
      { name: "virga:confidence", value: "high" },
      { name: "virga:source", value: "package_dependencies" },
    ]);
    const tie: SbomPackage = { ...first, source: "sbom" };
    const tied = buildWorkerSbom(input({ packages: [tie, ...packages] }));
    const again = buildWorkerSbom(input({ packages: [...packages, tie] }));
    expect(serializeSbom(tied)).toBe(serializeSbom(again));
  });

  it("emits an empty component list for a Worker without packages", () => {
    const bom = buildWorkerSbom(input({ packages: [] }));
    expect(bom.components).toEqual([]);
    expect(checkSbom(bom)).toEqual([]);
  });

  it("keeps strings from scanned accounts as JSON data", () => {
    const scriptName = 'x","components":[],"y":"</script><script>alert(1)</script>{{7*7}}\\';
    const name = ["@evil/pkg\"'`", "$", "{x}"].join("");
    const evil: SbomPackage = {
      purl: "pkg:npm/%40evil/pkg@1.0.0",
      name,
      version: "1.0.0",
      source: "banner",
      confidence: 0,
    };
    const bom = buildWorkerSbom(
      input({ worker: { scriptName, versionId: VERSION_ID }, packages: [evil] }),
    );
    const parsed = JSON.parse(serializeSbom(bom));
    expect(parsed.metadata.component.name).toBe(scriptName);
    expect(parsed.components).toHaveLength(1);
    expect(parsed.components[0].name).toBe(name);
    expect(parsed).toEqual(bom);
  });

  it.each([
    ["an invalid purl", { packages: [{ ...packages[0], purl: "npm/lodash" }] }],
    ["a purl with spaces", { packages: [{ ...packages[0], purl: "pkg:npm/a b@1" }] }],
    ["an empty package name", { packages: [{ ...packages[0], name: "" }] }],
    ["a name with a control character", { packages: [{ ...packages[0], name: "a\u0000" }] }],
    ["a version with a lone surrogate", { packages: [{ ...packages[0], version: "1\ud800" }] }],
    ["an unknown source", { packages: [{ ...packages[0], source: "guess" }] }],
    ["a confidence out of range", { packages: [{ ...packages[0], confidence: 3 }] }],
    [
      "a script name with a bidi override",
      { worker: { scriptName: `a${RIGHT_TO_LEFT_OVERRIDE}b`, versionId: VERSION_ID } },
    ],
    ["a version ID with spaces", { worker: { scriptName: "a", versionId: "a b" } }],
    ["a timestamp that is not a time", { timestamp: Number.NaN }],
    ["a serial number that is not a v1-5 UUID URN", { serialNumber: "urn:uuid:not-a-uuid" }],
    ["an empty tool version", { tool: { version: "" } }],
  ])("refuses %s", (_, overrides) => {
    expect(() => buildWorkerSbom(input(overrides as Partial<WorkerSbomInput>))).toThrow(
      SbomInputError,
    );
  });

  it("does not echo the refused value in the error", () => {
    const secretish = "cfat_should-not-be-echoed\u0000";
    try {
      buildWorkerSbom(input({ worker: { scriptName: secretish, versionId: VERSION_ID } }));
      throw new Error("expected a refusal");
    } catch (error) {
      expect(error).toBeInstanceOf(SbomInputError);
      expect(String((error as Error).message)).not.toContain("should-not-be-echoed");
    }
  });
});

describe("checkSbom", () => {
  const good = () => clone(buildWorkerSbom(input())) as unknown as Doc;

  it.each([
    ["a wrong spec version", (b: Doc) => (b.specVersion = "1.5")],
    ["a wrong format", (b: Doc) => (b.bomFormat = "SPDX")],
    ["a missing serial number", (b: Doc) => delete b.serialNumber],
    ["a bad serial number", (b: Doc) => (b.serialNumber = "urn:uuid:x")],
    ["a version of zero", (b: Doc) => (b.version = 0)],
    ["a fractional version", (b: Doc) => (b.version = 1.5)],
    ["an unknown top-level key", (b: Doc) => (b.extra = true)],
    ["a timestamp without zone", (b: Doc) => (b.metadata.timestamp = "2026-10-30T12:00:00")],
    ["an impossible date", (b: Doc) => (b.metadata.timestamp = "2026-02-30T12:00:00Z")],
    ["tools as the deprecated list", (b: Doc) => (b.metadata.tools = [])],
    ["a missing metadata component", (b: Doc) => delete b.metadata.component],
    ["components out of order", (b: Doc) => b.components.reverse()],
    ["a duplicate bom-ref", (b: Doc) => (b.components[1]["bom-ref"] = b.components[0]["bom-ref"])],
    ["a component without purl", (b: Doc) => delete b.components[0].purl],
    ["a bom-ref that is not the purl", (b: Doc) => (b.components[0]["bom-ref"] = "x")],
    ["an invalid purl", (b: Doc) => (b.components[0].purl = "pkg:npm/a b@1")],
    ["an unknown component type", (b: Doc) => (b.components[0].type = "lib")],
    ["a missing property", (b: Doc) => b.components[0].properties.pop()],
    ["a property with a bad value", (b: Doc) => (b.components[0].properties[0].value = "max")],
    ["properties out of order", (b: Doc) => b.components[0].properties.reverse()],
    ["a property value that is not text", (b: Doc) => (b.components[0].properties[1].value = 2)],
    ["an unknown component key", (b: Doc) => (b.components[0].scope = "required")],
    ["a non-object document", () => undefined, "replace"],
  ])("finds %s", (_, mutate, mode?: string) => {
    const bom = good();
    mutate(bom);
    const problems = checkSbom(mode === "replace" ? [] : bom);
    expect(problems.length).toBeGreaterThan(0);
    for (const problem of problems) expect(problem).not.toContain("lodash");
  });
});
