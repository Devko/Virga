import { describe, expect, it } from "vitest";
import { COLLECTORS, RESOURCE_CLASSES } from "../src/index.ts";

describe("collector registry", () => {
  it("has at most one collector per resource class", () => {
    const classes = COLLECTORS.map((c) => c.resourceClass);
    expect(new Set(classes).size).toBe(classes.length);
    for (const c of classes) expect(RESOURCE_CLASSES).toContain(c);
  });

  it("orders without cycles", () => {
    const byClass = new Map(COLLECTORS.map((c) => [c.resourceClass, c]));
    const visiting = new Set<string>();
    const visit = (cls: string, depth = 0): void => {
      expect(depth).toBeLessThan(RESOURCE_CLASSES.length);
      if (visiting.has(cls)) throw new Error(`cycle at ${cls}`);
      visiting.add(cls);
      for (const dep of byClass.get(cls as never)?.after ?? []) visit(dep, depth + 1);
      visiting.delete(cls);
    };
    for (const c of COLLECTORS) visit(c.resourceClass);
  });
});
