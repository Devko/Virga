import { createReader, NoPermissionError } from "@virga/cf-api";
import {
  type FixtureRoute,
  type FixtureTransportOptions,
  failure,
  fixtureTransport,
} from "@virga/cf-api/testing";
import {
  canonicalJson,
  type EdgeInput,
  edgeId,
  type InsightRow,
  type NodeInput,
  nodeId,
  type SignalRow,
} from "@virga/graph";
import { expect } from "vitest";
import type { Collector, CollectorContext, CollectorOutput } from "../../src/types.ts";

export type Routes = Record<string, FixtureRoute>;
export type GraphqlHandler = NonNullable<FixtureTransportOptions["graphql"]>;

/** The account ID of the documented examples. */
export const ACCOUNT = "023e105f4ecef8ad9ca31a8372d0c353";
export const BASE = `/accounts/${ACCOUNT}`;
/** Scan start, 2026-10-29T12:00:00Z. */
export const NOW = Date.UTC(2026, 9, 29, 12, 0, 0);

export function context(routes: Routes, graphql?: GraphqlHandler) {
  const transport = fixtureTransport(routes, graphql ? { graphql } : {});
  const ctx: CollectorContext = {
    accountId: ACCOUNT,
    scanId: "scan-1",
    api: createReader(transport),
    now: NOW,
  };
  return { ctx, transport };
}

export interface Run<U> {
  chunks: U[][];
  output: Required<CollectorOutput>;
  calls: string[];
}

const sorted = <T>(map: Map<string, T>) =>
  [...map.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([, v]) => v);

/** Runs plan and every chunk like the scan Workflow does, and merges the output. */
export async function run<U>(
  collector: Collector<U>,
  routes: Routes,
  graphql?: GraphqlHandler,
): Promise<Run<U>> {
  const { ctx, transport } = context(routes, graphql);
  // Units cross a Workflow step boundary, so they must survive serialization.
  const chunks = JSON.parse(JSON.stringify(await collector.plan(ctx))) as U[][];
  const nodes = new Map<string, NodeInput>();
  const edges = new Map<string, EdgeInput>();
  const signals = new Map<string, SignalRow>();
  const insights = new Map<string, InsightRow>();
  const truncated: string[] = [];
  for (const unit of chunks) {
    const out = await collector.collect(ctx, unit);
    expectSorted(out);
    for (const n of out.nodes) nodes.set(nodeId(n.type, n.nativeId), n);
    for (const e of out.edges) edges.set(edgeId(e.type, e.src, e.dst, e.key), e);
    for (const s of out.signals ?? []) signals.set(`${s.nodeId}#${s.name}`, s);
    for (const i of out.insights ?? []) insights.set(i.id, i);
    truncated.push(...(out.truncated ?? []));
  }
  return {
    chunks,
    output: {
      nodes: sorted(nodes),
      edges: sorted(edges),
      signals: sorted(signals),
      insights: sorted(insights),
      // In chunk order, as the scan records them.
      truncated,
    },
    calls: transport.calls,
  };
}

export function expectSorted(out: CollectorOutput): void {
  const nodeIds = out.nodes.map((n) => nodeId(n.type, n.nativeId));
  const edgeIds = out.edges.map((e) => edgeId(e.type, e.src, e.dst, e.key));
  const signalIds = (out.signals ?? []).map((s) => `${s.nodeId}\u0000${s.name}`);
  const insightIds = (out.insights ?? []).map((i) => i.id);
  for (const ids of [nodeIds, edgeIds, signalIds, insightIds]) {
    expect(ids).toEqual([...ids].sort());
    expect(new Set(ids).size).toBe(ids.length);
  }
}

/** Running twice yields byte-identical output and the same calls. */
export async function expectDeterministic<U>(
  collector: Collector<U>,
  routes: Routes,
  graphql?: GraphqlHandler,
) {
  const a = await run(collector, routes, graphql);
  const b = await run(collector, routes, graphql);
  expect(canonicalJson(b.output)).toBe(canonicalJson(a.output));
  expect(b.calls).toEqual(a.calls);
}

export function node(out: CollectorOutput, id: string): NodeInput {
  const found = out.nodes.find((n) => nodeId(n.type, n.nativeId) === id);
  if (!found) throw new Error(`no node ${id}`);
  return found;
}

export const nodeIds = (out: CollectorOutput, type?: string) =>
  out.nodes.filter((n) => !type || n.type === type).map((n) => nodeId(n.type, n.nativeId));

export const edgeIds = (out: CollectorOutput, type?: string) =>
  out.edges.filter((e) => !type || e.type === type).map((e) => edgeId(e.type, e.src, e.dst, e.key));

export function edge(out: CollectorOutput, id: string): EdgeInput {
  const found = out.edges.find((e) => edgeId(e.type, e.src, e.dst, e.key) === id);
  if (!found) throw new Error(`no edge ${id}`);
  return found;
}

/** Every node carries every contract prop: missing values are null, never omitted. */
export function expectProps(out: CollectorOutput, type: string, keys: string[]): void {
  const nodes = out.nodes.filter((n) => n.type === type);
  expect(nodes.length, type).toBeGreaterThan(0);
  for (const n of nodes) {
    expect(Object.keys(n.props ?? {}).sort(), n.nativeId).toEqual([...keys].sort());
  }
}

/** A run against these routes fails with NoPermissionError, in plan or in a chunk. */
export async function expectNoPermission<U>(
  collector: Collector<U>,
  routes: Routes,
  graphql?: GraphqlHandler,
) {
  await expect(run(collector, routes, graphql)).rejects.toBeInstanceOf(NoPermissionError);
}

export const denied = () => failure(403, 10000, "Authentication error");

/** The routes minus some paths, which the fixture transport then answers with 404. */
export const without = (routes: Routes, ...paths: string[]): Routes =>
  Object.fromEntries(Object.entries(routes).filter(([path]) => !paths.includes(path)));

/** Paths of the calls, without method and query. */
export const callPaths = (calls: string[]): string[] =>
  calls.map((c) => c.replace(/^(GET|POST) /, "").split("?")[0] ?? "");
