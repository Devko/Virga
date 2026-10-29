import { canonicalJson, LIMITS, type SignalRow } from "@virga/graph";
import { isObject, str } from "../platform/util.ts";
import type { CollectorContext } from "../types.ts";

/** Epoch milliseconds of an ISO 8601 timestamp, or null. */
export function epochMs(value: unknown): number | null {
  const text = str(value);
  if (!text) return null;
  const ms = Date.parse(text);
  return Number.isFinite(ms) ? ms : null;
}

/** True if a native ID fits the graph's limit; longer ones would fail the whole batch. */
export const fitsId = (nativeId: string): boolean => nativeId.length <= LIMITS.nativeId;

/** A display name clipped to the graph's limit. */
export function displayName(value: unknown): string | null {
  const text = str(value);
  return text && text.length > LIMITS.name ? text.slice(0, LIMITS.name) : text;
}

export interface Bounds {
  text: number;
  items: number;
  depth: number;
}

/** For `raw` and `other` values inside props. */
export const RAW_BOUNDS: Bounds = { text: 256, items: 20, depth: 4 };

/**
 * A size-limited JSON copy of an untrusted value: long strings are cut, long
 * lists and objects truncated, deep nesting dropped, keys sorted.
 */
export function bounded(value: unknown, limits: Bounds = RAW_BOUNDS, depth = 0): unknown {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string") {
    return value.length > limits.text ? `${value.slice(0, limits.text)}…` : value;
  }
  if (depth >= limits.depth) return null;
  if (Array.isArray(value)) {
    return value.slice(0, limits.items).map((v) => bounded(v, limits, depth + 1));
  }
  if (isObject(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .slice(0, limits.items)
        .map((key) => [key.slice(0, 64), bounded(value[key], limits, depth + 1)]),
    );
  }
  return null;
}

/** Sorts by canonical JSON and drops duplicates, so list props hash the same on every scan. */
export function canonicalList<T>(items: readonly T[]): T[] {
  const byJson = new Map<string, T>();
  for (const item of items) byJson.set(canonicalJson(item), item);
  return [...byJson.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, v]) => v);
}

/** Signals once per node and name, sorted, so output is deterministic. */
export function sortedSignals(rows: Iterable<SignalRow>): SignalRow[] {
  const byKey = new Map<string, SignalRow>();
  for (const row of rows) byKey.set(`${row.nodeId}\u0000${row.name}`, row);
  return [...byKey.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, v]) => v);
}

/** developers.cloudflare.com/api/resources/workers/subresources/beta/subresources/workers/methods/list */
interface CfWorker {
  id?: string;
  name?: string;
}

/** Every Worker in the account as script name and Worker ID (Workers API, beta). */
export async function listWorkers(
  ctx: CollectorContext,
): Promise<{ name: string; id: string | null }[]> {
  const path = `/accounts/${ctx.accountId}/workers/workers`;
  return (await ctx.api.all<CfWorker>(path, {}, { perPage: 100 })).flatMap((worker) => {
    const name = isObject(worker) ? str(worker.name) : null;
    return name ? [{ name, id: str(worker.id) }] : [];
  });
}
