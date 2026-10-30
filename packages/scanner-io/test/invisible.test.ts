// R9 hardening, invisible characters: kept strings and SBOM text refuse
// characters that render as nothing (Unicode's Default_Ignorable_Code_Point).

import { describe, expect, it } from "vitest";
import { ScannerOutputRejected } from "../src/errors.ts";
import { readGitleaks } from "../src/gitleaks.ts";
import { readOsvScanner } from "../src/osv.ts";
import { buildWorkerSbom, checkSbom, SbomInputError, serializeSbom } from "../src/sbom.ts";
import { isCleanText, isInvisible } from "../src/text.ts";
import { readTrivy } from "../src/trivy.ts";
import { schemaProblems } from "./cdx-schema.ts";
import { gitleaksSample, json, osvSample, trivySample } from "./samples.ts";

/** The characters the round 9 review named, as code points. */
const NAMED = [
  0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x034f, 0x115f, 0x1160, 0x3164, 0xffa0, 0x180e, 0xe0000,
  0xe0001, 0xe0020, 0xe0041, 0xe007f,
];
const ch = (cp: number) => String.fromCodePoint(cp);

const rejection = (run: () => unknown) => {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(ScannerOutputRejected);
    return error as ScannerOutputRejected;
  }
  throw new Error("expected a rejection");
};

describe("invisible characters (R9 hardening)", () => {
  it.each(NAMED.map((cp) => [cp.toString(16).toUpperCase().padStart(4, "0"), cp]))(
    "R9 invisible characters: clean text refuses U+%s",
    (_, cp) => {
      expect(isCleanText(`a${ch(cp)}b`)).toBe(false);
      expect(isCleanText(ch(cp))).toBe(false);
    },
  );

  it("R9 invisible characters: the list is Unicode's Default_Ignorable_Code_Point", () => {
    const ignorable = /^\p{Default_Ignorable_Code_Point}$/u;
    const differ: string[] = [];
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      if (isInvisible(cp) !== ignorable.test(ch(cp))) differ.push(cp.toString(16));
    }
    expect(differ).toEqual([]);
  });

  it("R9 invisible characters: visible text stays clean", () => {
    for (const text of ["café", "日本語", "😀", "a b", "a b", "x-y_z.~", "Ünïcødé"]) {
      expect(isCleanText(text), text).toBe(true);
    }
  });

  it("R9 invisible characters: osv-scanner rejects them in a package name", () => {
    const sample = structuredClone(osvSample);
    const entry = sample.results[0]?.packages[0];
    if (entry) entry.package.name = `lod${ch(0x200b)}ash`;
    expect(rejection(() => readOsvScanner(json(sample)))).toMatchObject({
      reason: "invalid_text",
      at: "/results/0/packages/0/package/name",
    });
  });

  it("R9 invisible characters: Trivy rejects them in a target and a package name", () => {
    const sample = structuredClone(trivySample);
    const first = sample.Results[0];
    if (first) first.Target = `app${ch(0xe0041)}${ch(0xe007f)}`;
    expect(rejection(() => readTrivy(json(sample)))).toMatchObject({
      reason: "invalid_text",
      at: "/Results/0/Target",
    });
    const named = structuredClone(trivySample);
    const pkg = named.Results[0]?.Packages?.[0];
    if (pkg) pkg.Name = `mu${ch(0x3164)}sl`;
    expect(rejection(() => readTrivy(json(named)))).toMatchObject({
      reason: "invalid_text",
      at: "/Results/0/Packages/0/Name",
    });
  });

  it("R9 invisible characters: gitleaks rejects them in a file", () => {
    const findings = structuredClone(gitleaksSample) as Record<string, unknown>[];
    Object.assign(findings[0] ?? {}, { File: `worker${ch(0xfeff)}.js` });
    expect(rejection(() => readGitleaks(json(findings)))).toMatchObject({
      reason: "invalid_text",
      at: "/0/File",
    });
  });

  it("R9 invisible characters: the SBOM generator refuses them", () => {
    const base = {
      worker: { scriptName: "api", versionId: "0f8e7d6c-5b4a-4392-8a1b-0c9d8e7f6a5b" },
      packages: [
        {
          purl: "pkg:npm/lodash@4.17.20",
          name: "lodash",
          version: "4.17.20",
          source: "banner" as const,
          confidence: 1 as const,
        },
      ],
      tool: { version: "0.1.0" },
      timestamp: Date.UTC(2026, 9, 30),
    };
    const pkg = base.packages[0] as (typeof base.packages)[number];
    const cases = [
      { ...base, worker: { ...base.worker, scriptName: `api${ch(0x200d)}` } },
      { ...base, packages: [{ ...pkg, name: `lo${ch(0x034f)}dash` }] },
      { ...base, packages: [{ ...pkg, version: `4.17.20${ch(0xe0001)}` }] },
      { ...base, tool: { version: `0.1.0${ch(0x2060)}` } },
    ];
    for (const input of cases) expect(() => buildWorkerSbom(input)).toThrow(SbomInputError);
    const valid = buildWorkerSbom(base);
    expect(schemaProblems(JSON.parse(serializeSbom(valid)))).toEqual([]);
    const bom = structuredClone(valid) as unknown as { components: { name: string }[] };
    const first = bom.components[0];
    if (first) first.name = `lodash${ch(0x180e)}`;
    expect(checkSbom(bom).length).toBeGreaterThan(0);
  });
});
