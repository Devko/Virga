// R9-06: memory follows what the parser and the readers build, not the byte
// count. These tests build the most expensive inputs found for the default
// limits and check the heap they keep after a full collection, in Node.
// Node does not compress pointers, so the same objects take about twice the
// heap they take in workerd; docs/architecture/scanner-io.md has both sets
// of numbers.

import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";
import { Worker } from "node:worker_threads";
import { describe, expect, it } from "vitest";
import { Fields } from "../src/fields.ts";
import { parseJson } from "../src/json.ts";
import { DEFAULT_LIMITS, type Limits } from "../src/limits.ts";
import { ReportBuilder } from "../src/report.ts";
import { CJK, HOSTILE_SHAPES } from "./hostile.ts";

setFlagsFromString("--expose-gc");
const gc = runInNewContext("gc") as () => void;

/** Heap in use after two full collections, in bytes. */
const heap = (): number => {
  gc();
  gc();
  return process.memoryUsage().heapUsed;
};

/** Heap that `make` keeps, measured while its result is still reachable. */
function kept<T>(make: () => T): { bytes: number; value: T } {
  const before = heap();
  const value = make();
  const bytes = heap() - before;
  return { bytes, value };
}

const MB = 1_000_000;
const L: Limits = DEFAULT_LIMITS;
/** Node bound for the parsed tree; workerd keeps a little more than half. */
const TREE_LIMIT = 48 * MB;

describe("memory (R9-06)", () => {
  it.each(HOSTILE_SHAPES)(
    "R9-06: the tree of %s stays below the bound",
    (_, build) => {
      const text = build();
      expect(new TextEncoder().encode(text).length).toBeLessThanOrEqual(L.maxBytes);
      const { bytes, value } = kept(() => parseJson(text, L, "trivy"));
      expect(value).toBeTruthy();
      expect(bytes / MB).toBeLessThan(TREE_LIMIT / MB);
    },
    30_000,
  );

  it("R9-06: refuses the review's report of 499,996 values in empty objects", () => {
    const text = `[${Array.from({ length: 5 }, () => `[${new Array(99_998).fill("{}").join(",")}]`).join(",")}]`;
    expect(() => parseJson(text, L, "trivy")).toThrow(
      expect.objectContaining({ reason: "too_many_values" }),
    );
  });

  it("R9-06: counts containers and object keys", () => {
    const limits = { ...L, maxValues: 10, maxContainers: 3 };
    expect(() => parseJson("[[],[]]", limits, "trivy")).not.toThrow();
    expect(() => parseJson("[[],[],{}]", limits, "trivy")).toThrow(
      expect.objectContaining({ reason: "too_many_values" }),
    );
    // A member is two values: the key and the value.
    expect(() => parseJson('{"a":1,"b":2,"c":3,"d":4}', limits, "trivy")).not.toThrow();
    expect(() => parseJson('{"a":1,"b":2,"c":3,"d":4,"e":5}', limits, "trivy")).toThrow(
      expect.objectContaining({ reason: "too_many_values" }),
    );
  });

  it("R9-06: a long package name is not copied once per match", () => {
    const name = CJK.repeat(512);
    const version = `${"v".repeat(255)}${CJK}`;
    const { bytes } = kept(() => {
      const out = new ReportBuilder("osv-scanner", L, new Fields("osv-scanner"));
      const pkg = out.addPackage({ purl: null, ecosystem: "E".repeat(128), name, version });
      for (let i = 0; i < L.maxVulnerabilities; i++)
        out.addVulnerability(pkg, `GHSA-${i}`, [], null, []);
      return [out, out.build()];
    });
    // Before: 127 MB in Node for 50,000 matches.
    expect(bytes / MB).toBeLessThan(16);
  }, 30_000);

  it("R9-06: a long Trivy target is not copied once per secret", () => {
    const file = CJK.repeat(1024);
    const { bytes } = kept(() => {
      const out = new ReportBuilder("trivy", L, new Fields("trivy"));
      for (let i = 0; i < L.maxSecrets; i++) {
        out.addSecret({ ruleId: "r", file, line: i, endLine: i, prefix: null, masked: "********" });
      }
      return [out, out.build()];
    });
    // Before: 22 MB in Node for 10,000 secrets.
    expect(bytes / MB).toBeLessThan(4);
  }, 30_000);

  /** Runs a reader in a worker whose old generation is capped at `mb`. */
  const capped = (run: string, mb: number) =>
    new Promise<{ code: number; vulnerabilities?: number; error?: string }>((resolve) => {
      const worker = new Worker(new URL("./memory-worker.ts", import.meta.url), {
        workerData: run,
        resourceLimits: { maxOldGenerationSizeMb: mb },
      });
      let vulnerabilities: number | undefined;
      let error: string | undefined;
      worker.on("message", (m: { vulnerabilities: number }) => {
        vulnerabilities = m.vulnerabilities;
      });
      worker.on("error", (e: Error & { code?: string }) => {
        error = e.code ?? e.name;
      });
      worker.on("exit", (code) => resolve({ code, vulnerabilities, error }));
    });

  // The peak of the whole read, text and tree included. Before: the match
  // keys copied the package key once per match, 127 MB in Node.
  it.each(["osv", "trivy"])(
    "R9-06: %s matches of one long package fit a capped heap",
    async (run) => {
      const outcome = await capped(run, 64);
      expect(outcome).toEqual({ code: 0, vulnerabilities: L.maxVulnerabilities, error: undefined });
    },
    60_000,
  );

  // Text and tree of the worst parse: 77 MB in Node, 56 MB in workerd.
  it("R9-06: the worst parse fits a capped heap", async () => {
    const outcome = await capped("parse", 96);
    expect(outcome).toEqual({ code: 0, vulnerabilities: 0, error: undefined });
  }, 60_000);
});
