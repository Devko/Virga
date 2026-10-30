// Gate 6 of phase 2: scanner output that breaks the schema or the size limits
// is rejected. Each run mutates a valid sample and checks that the reader
// either returns a result that meets its invariants or throws its own
// rejection, within a time bound.
//
// CI runs a fixed seed and iteration count. For a longer run:
//   SCANNER_IO_FUZZ_ITERATIONS=20000 SCANNER_IO_FUZZ_SEED=7 \
//     pnpm --filter @virga/scanner-io exec vitest run test/fuzz.test.ts
// A failure prints the seed and the iteration; rerun with that seed to replay it.

import { describe, expect, it } from "vitest";
import { REJECTION_REASONS, ScannerOutputRejected, type Tool } from "../src/errors.ts";
import { readGitleaks } from "../src/gitleaks.ts";
import { DEFAULT_LIMITS, type Limits, resolveLimits } from "../src/limits.ts";
import { readOsvScanner } from "../src/osv.ts";
import type { ReaderOptions, ScanReport } from "../src/report.ts";
import { readTrivy } from "../src/trivy.ts";
import { checkReport } from "./invariants.ts";
import { mutate, prng } from "./mutate.ts";
import { gitleaksSample, osvSample, SEEDED_BODIES, trivySample } from "./samples.ts";

const SEED = Number(process.env.SCANNER_IO_FUZZ_SEED ?? 20261030);
const ITERATIONS = Number(process.env.SCANNER_IO_FUZZ_ITERATIONS ?? 600);
/** Per run. Generous for slow CI machines; a run normally takes well under 50 ms. */
const RUN_MS = 2_000;

/** Small limits, so that oversized mutations stay cheap to build. */
const FUZZ_LIMITS: Limits = resolveLimits({
  maxBytes: 256 * 1024,
  maxDepth: 16,
  maxValues: 20_000,
  maxContainers: 2_000,
  maxArrayItems: 400,
  maxObjectKeys: 64,
  maxStringLength: 4096,
  maxPackages: 50,
  maxVulnerabilities: 50,
  maxSecrets: 20,
});

type Reader = (input: string | Uint8Array, options?: ReaderOptions) => ScanReport;

const readers: [Tool, Reader, unknown][] = [
  ["osv-scanner", readOsvScanner, osvSample],
  ["trivy", readTrivy, trivySample],
  ["gitleaks", readGitleaks, gitleaksSample],
];

const pieces = SEEDED_BODIES.flatMap((body) =>
  Array.from({ length: body.length - 5 }, (_, i) => body.slice(i, i + 6)),
);
const leaks = (text: string): string | undefined => pieces.find((p) => text.includes(p));

function fuzz(tool: Tool, read: Reader, sample: unknown, limits: Limits, seed: number, n: number) {
  const rng = prng(seed);
  const outcomes = { accepted: 0, rejected: new Map<string, number>() };
  for (let i = 0; i < n; i++) {
    const input = mutate(sample, rng, limits);
    const where = `${tool} seed ${seed} iteration ${i}`;
    const started = performance.now();
    let report: ScanReport | undefined;
    try {
      report = read(input, { limits });
    } catch (error) {
      if (!(error instanceof ScannerOutputRejected)) {
        throw new Error(`${where}: threw ${String(error)}`);
      }
      expect(error.tool, where).toBe(tool);
      expect(REJECTION_REASONS, where).toContain(error.reason);
      const leaked = leaks(`${error.message}\n${error.stack ?? ""}\n${error.at}`);
      expect(leaked, `${where}: rejection carries a secret`).toBeUndefined();
      outcomes.rejected.set(error.reason, (outcomes.rejected.get(error.reason) ?? 0) + 1);
    }
    const elapsed = performance.now() - started;
    expect(elapsed, `${where}: took ${elapsed.toFixed(0)} ms`).toBeLessThan(RUN_MS);
    if (report) {
      outcomes.accepted++;
      expect(checkReport(report, tool, limits), where).toEqual([]);
      expect(leaks(JSON.stringify(report)), `${where}: result carries a secret`).toBeUndefined();
    }
  }
  return outcomes;
}

describe("fuzz (gate 6)", () => {
  it.each(readers)("%s accepts its unmutated sample", (tool, read, sample) => {
    const report = read(JSON.stringify(sample), { limits: FUZZ_LIMITS });
    expect(checkReport(report, tool, FUZZ_LIMITS)).toEqual([]);
    expect(checkReport(read(JSON.stringify(sample)), tool, DEFAULT_LIMITS)).toEqual([]);
  });

  it.each(readers)(
    "%s returns a valid result or its own rejection for every mutation",
    (tool, read, sample) => {
      const outcomes = fuzz(tool, read, sample, FUZZ_LIMITS, SEED, ITERATIONS);
      // The mutations must reach both sides, or the test proves nothing.
      expect(outcomes.accepted).toBeGreaterThan(ITERATIONS / 20);
      const rejected = [...outcomes.rejected.values()].reduce((a, b) => a + b, 0);
      expect(rejected).toBeGreaterThan(ITERATIONS / 4);
      expect(outcomes.rejected.size).toBeGreaterThan(5);
    },
    120_000,
  );

  it.each(readers)(
    "%s holds at the default limits too",
    (tool, read, sample) => {
      fuzz(tool, read, sample, DEFAULT_LIMITS, SEED + 1, Math.max(10, Math.floor(ITERATIONS / 10)));
    },
    120_000,
  );
});
