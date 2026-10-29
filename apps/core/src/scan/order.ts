import type { Collector } from "@virga/collectors";

/**
 * Orders collectors so that every class runs after the classes in its
 * `after` list. Classes without a collector are ignored there, and ties keep
 * the input order, so the step sequence is stable across replays.
 */
export function orderCollectors(collectors: readonly Collector[]): Collector[] {
  const byClass = new Map<string, Collector>();
  for (const c of collectors) {
    if (byClass.has(c.resourceClass)) throw new Error(`two collectors for ${c.resourceClass}`);
    byClass.set(c.resourceClass, c);
  }
  const done = new Set<string>();
  const out: Collector[] = [];
  while (out.length < collectors.length) {
    const next = collectors.find(
      (c) =>
        !done.has(c.resourceClass) &&
        (c.after ?? []).every((dep) => done.has(dep) || !byClass.has(dep)),
    );
    if (!next) {
      const left = collectors.filter((c) => !done.has(c.resourceClass)).map((c) => c.resourceClass);
      throw new Error(`collector order has a cycle among ${left.join(", ")}`);
    }
    done.add(next.resourceClass);
    out.push(next);
  }
  return out;
}
