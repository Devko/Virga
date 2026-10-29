import { describe, expect, it } from "vitest";
import { readWorkerConfig } from "../lib/config.ts";
import { loadExports, moduleExports } from "../lib/exports.ts";
import { REPO_ROOT, worker } from "./helpers.ts";

describe("moduleExports", () => {
  it("reads re-exports, aliases, declarations and the default export", () => {
    const source = `
      export { A } from "./a.ts";
      export { B as Bee, C } from "./b.ts";
      export type { T } from "./t.ts";
      export { type U, D } from "./d.ts";
      export class E extends WorkerEntrypoint {}
      export abstract class F {}
      export async function g() {}
      export const h = 1;
      export * as ns from "./ns.ts";
      export default { fetch() {} };
    `;
    const { names, star } = moduleExports(source);
    expect([...names].sort()).toEqual(["A", "Bee", "C", "D", "E", "F", "default", "g", "h", "ns"]);
    expect(star).toBe(false);
  });

  it("ignores exports in comments and strings", () => {
    const { names } = moduleExports(`
      // export { Hidden } from "./x.ts";
      /* export class AlsoHidden {} */
      const s = "export { InString }";
      export { Real };
    `);
    expect([...names]).toEqual(["Real"]);
  });

  it("flags export * because its names are unknown", () => {
    expect(moduleExports(`export * from "./all.ts";`).star).toBe(true);
  });
});

describe("loadExports", () => {
  it("lists the broker and core entrypoints", () => {
    const broker = readWorkerConfig(REPO_ROOT, "broker");
    const core = readWorkerConfig(REPO_ROOT, "core");
    if (!broker || !core) throw new Error("configs missing");
    expect(loadExports(broker)?.names).toEqual(
      new Set(["ApiCaller", "RateBudget", "TokenIntake", "default"]),
    );
    expect(loadExports(core)?.names).toEqual(
      new Set([
        "AccountGraph",
        "Admin",
        "GraphReader",
        "DispatchWorkflow",
        "ScanWorkflow",
        "default",
      ]),
    );
  });

  it("returns null without a readable main module", () => {
    expect(loadExports(worker("web", { main: null }))).toBeNull();
    expect(loadExports(worker("web", { dir: "/nonexistent", main: "index.ts" }))).toBeNull();
  });
});
