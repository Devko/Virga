import type { Batch, EdgeInput, ExposureRow, NodeInput, VulnRow } from "@virga/graph";

/**
 * A deterministic synthetic account for scale tests: `workers` Workers, each
 * with a route, one deployed version, five packages from a shared pool, a D1
 * binding on every second Worker and a service binding on every fifth.
 * Every third route is public. Packages 0 to 9 of the pool are critical.
 */
export interface SyntheticGraph {
  batches: Batch[];
  exposure: ExposureRow[];
  vulns: VulnRow[];
  expectedHits: string[];
  nodeCount: number;
  edgeCount: number;
}

const PACKAGES = 500;
const DATABASES = 50;
const VULNERABLE = 10;

export function syntheticGraph(workers: number, scanId: string, chunk = 1000): SyntheticGraph {
  const nodes: NodeInput[] = [];
  const edges: EdgeInput[] = [];
  const pkg = (i: number, k: number) => (i * 7 + k * 13) % PACKAGES;
  const bindsDb = (i: number) => i % 2 === 0;
  const bindsService = (i: number) => i % 5 === 0 && i + 1 < workers;

  for (let p = 0; p < PACKAGES; p++) {
    nodes.push({ type: "package", nativeId: `pkg:npm/p${p}@1.0.0`, name: `p${p}` });
  }
  for (let d = 0; d < DATABASES; d++) nodes.push({ type: "d1_database", nativeId: `db${d}` });

  const exposure: ExposureRow[] = [];
  const expectedHits: string[] = [];
  for (let i = 0; i < workers; i++) {
    const script = `worker_script:w${i}`;
    const version = `worker_version:v${i}`;
    const route = `worker_route:r${i}`;
    nodes.push(
      { type: "worker_route", nativeId: `r${i}`, name: `w${i}.example.com/*` },
      { type: "worker_script", nativeId: `w${i}`, name: `w${i}` },
      { type: "worker_version", nativeId: `v${i}`, props: { script_node_id: script } },
    );
    edges.push(
      { type: "ROUTES_TO", src: route, dst: script },
      { type: "DEPLOYS", src: script, dst: version, props: { percentage: 100 } },
    );
    for (let k = 0; k < 5; k++) {
      edges.push({
        type: "CONTAINS",
        src: version,
        dst: `package:pkg:npm/p${pkg(i, k)}@1.0.0`,
        props: { confidence: 2 },
      });
    }
    if (bindsDb(i)) {
      edges.push({ type: "BINDS", src: version, dst: `d1_database:db${i % DATABASES}`, key: "DB" });
    }
    if (bindsService(i)) {
      edges.push({ type: "BINDS", src: version, dst: `worker_script:w${i + 1}`, key: "SVC" });
    }
    const isPublic = i % 3 === 0;
    exposure.push({ entryId: route, decision: isPublic ? "public" : "access", confidence: 2 });

    const vulnerable = [0, 1, 2, 3, 4].some((k) => pkg(i, k) < VULNERABLE);
    const reachesData = bindsDb(i) || (bindsService(i) && bindsDb(i + 1));
    if (isPublic && vulnerable && reachesData) expectedHits.push(`CF-001:${script}`);
  }

  const batches: Batch[] = [];
  for (let n = 0; n < nodes.length; n += chunk) {
    batches.push({ scanId, resourceClass: "workers", nodes: nodes.slice(n, n + chunk), edges: [] });
  }
  for (let e = 0; e < edges.length; e += chunk) {
    batches.push({ scanId, resourceClass: "workers", nodes: [], edges: edges.slice(e, e + chunk) });
  }
  const vulns: VulnRow[] = Array.from({ length: VULNERABLE }, (_, p) => ({
    packageId: `package:pkg:npm/p${p}@1.0.0`,
    vulnId: `GHSA-synthetic-${p}`,
    severityRank: 4,
    source: "synthetic",
  }));
  return {
    batches,
    exposure,
    vulns,
    expectedHits: expectedHits.sort(),
    nodeCount: nodes.length,
    edgeCount: edges.length,
  };
}
