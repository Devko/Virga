import { CfApiError, type CfQuery, type CfReader, NotFoundError } from "@virga/cf-api";
import {
  type EdgeInput,
  type EdgeType,
  edgeId,
  type JsonObject,
  type NodeInput,
  type NodeType,
  nodeId,
} from "@virga/graph";
import type { CollectorOutput } from "../types.ts";

// API responses are untrusted JSON: read every field through these.
export const str = (value: unknown): string | null =>
  typeof value === "string" && value !== "" ? value : null;
export const bool = (value: unknown): boolean | null => (typeof value === "boolean" ? value : null);
export const num = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;
export const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/** Lowercase hostname of a URL, or null if it does not parse. */
export function hostOf(url: unknown): string | null {
  const text = str(url);
  if (!text) return null;
  try {
    return str(new URL(text).hostname.toLowerCase());
  } catch {
    return null;
  }
}

const byKey = <T>(entries: Iterable<[string, T]>): T[] =>
  [...entries].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, v]) => v);

/** Collects nodes and edges once per ID and returns them sorted, so output is deterministic. */
export class GraphBuilder {
  readonly #nodes = new Map<string, NodeInput>();
  readonly #edges = new Map<string, EdgeInput>();

  node(type: NodeType, nativeId: string, name: string | null, props: JsonObject = {}): string {
    const id = nodeId(type, nativeId);
    this.#nodes.set(id, { type, nativeId, name, props });
    return id;
  }

  edge(type: EdgeType, src: string, dst: string, props: JsonObject = {}, key = ""): void {
    this.#edges.set(edgeId(type, src, dst, key), {
      type,
      src,
      dst,
      ...(key ? { key } : {}),
      props,
    });
  }

  output(): CollectorOutput {
    return { nodes: byKey(this.#nodes), edges: byKey(this.#edges) };
  }
}

export function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/** A plan with nothing to fetch still runs one empty chunk, so the class completes. */
export const nonEmpty = <T>(chunks: T[][]): T[][] => (chunks.length > 0 ? chunks : [[]]);

export const sortedUnique = (values: Iterable<string | null>): string[] =>
  [...new Set([...values].filter((v): v is string => v !== null))].sort();

/**
 * Reads of one listed item: an item deleted between the listing and the read
 * is absent, not an error that would fail the whole chunk on every retry.
 */
export async function unlessGone<T>(read: Promise<T>): Promise<T | null> {
  try {
    return await read;
  } catch (error) {
    if (error instanceof NotFoundError) return null;
    throw error;
  }
}

const MAX_PAGES = 1000;

/**
 * Page-based listing for endpoints whose `result_info` has no `total_pages`
 * (D1, KV, Hyperdrive). `CfReader.all` stops after the first page there, so a
 * short page ends the list instead.
 */
export async function listByPage<T>(
  api: CfReader,
  path: string,
  perPage: number,
  query: CfQuery = {},
): Promise<T[]> {
  const out: T[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const result = await api.get<T[] | null>(path, { ...query, page, per_page: perPage });
    const items = Array.isArray(result) ? result : [];
    out.push(...items);
    if (items.length < perPage) return out;
  }
  throw new CfApiError(0, path, [], `more than ${MAX_PAGES} pages on ${path}`);
}
