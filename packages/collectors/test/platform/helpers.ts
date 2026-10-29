import { createReader, NoPermissionError } from "@virga/cf-api";
import { failure, fixtureTransport } from "@virga/cf-api/testing";
import { canonicalJson, type EdgeInput, edgeId, type NodeInput, nodeId } from "@virga/graph";
import { expect } from "vitest";
import type { Collector, CollectorContext, CollectorOutput } from "../../src/types.ts";
import { ACCOUNT, type Routes } from "./fixtures/routes.ts";

export { ACCOUNT, type Routes } from "./fixtures/routes.ts";

export function context(routes: Routes) {
  const transport = fixtureTransport(routes);
  const ctx: CollectorContext = {
    accountId: ACCOUNT,
    scanId: "scan-1",
    api: createReader(transport),
    now: 0,
  };
  return { ctx, transport };
}

export interface Run<U> {
  chunks: U[][];
  output: CollectorOutput;
  calls: string[];
}

/** Runs plan and every chunk like the scan Workflow does, and merges the output. */
export async function run<U>(collector: Collector<U>, routes: Routes): Promise<Run<U>> {
  const { ctx, transport } = context(routes);
  // Units cross a Workflow step boundary, so they must survive serialization.
  const chunks = JSON.parse(JSON.stringify(await collector.plan(ctx))) as U[][];
  const nodes = new Map<string, NodeInput>();
  const edges = new Map<string, EdgeInput>();
  for (const unit of chunks) {
    const out = await collector.collect(ctx, unit);
    expectSorted(out);
    for (const n of out.nodes) nodes.set(nodeId(n.type, n.nativeId), n);
    for (const e of out.edges) edges.set(edgeId(e.type, e.src, e.dst, e.key), e);
  }
  const sorted = <T>(map: Map<string, T>) =>
    [...map.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([, v]) => v);
  return { chunks, output: { nodes: sorted(nodes), edges: sorted(edges) }, calls: transport.calls };
}

export function expectSorted(out: CollectorOutput): void {
  const nodeIds = out.nodes.map((n) => nodeId(n.type, n.nativeId));
  const edgeIds = out.edges.map((e) => edgeId(e.type, e.src, e.dst, e.key));
  expect(nodeIds).toEqual([...nodeIds].sort());
  expect(new Set(nodeIds).size).toBe(nodeIds.length);
  expect(edgeIds).toEqual([...edgeIds].sort());
  expect(new Set(edgeIds).size).toBe(edgeIds.length);
}

/** Running twice yields byte-identical output. */
export async function expectDeterministic<U>(collector: Collector<U>, routes: Routes) {
  const a = await run(collector, routes);
  const b = await run(collector, routes);
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
export async function expectNoPermission<U>(collector: Collector<U>, routes: Routes) {
  await expect(run(collector, routes)).rejects.toBeInstanceOf(NoPermissionError);
}

export const denied = () => failure(403, 10000, "Authentication error");

/** The routes minus some paths, which the fixture transport then answers with 404. */
export const without = (routes: Routes, ...paths: string[]): Routes =>
  Object.fromEntries(Object.entries(routes).filter(([path]) => !paths.includes(path)));
