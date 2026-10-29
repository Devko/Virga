import {
  applyBatch,
  beginScan,
  type Confidence,
  type EdgeType,
  type ExposureDecision,
  edgeId,
  type NodeType,
  prepareBatch,
  replaceExposure,
  type SqlRunner,
  setSignals,
  upsertVulns,
} from "@virga/graph";
import { runRule } from "./runtime.ts";
import type { CompiledRule, RuleFixture, VulnSeverity } from "./types.ts";

const SEVERITY_RANK: Record<VulnSeverity, 0 | 1 | 2 | 3 | 4> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const FIXTURE_SCAN = "fixture";

/** Loads a fixture into an empty, migrated graph through the regular write path. */
export async function loadFixture(db: SqlRunner, fixture: RuleFixture, at = 1): Promise<void> {
  beginScan(db, { id: FIXTURE_SCAN, kind: "fixture", at });
  const batch = await prepareBatch(
    {
      scanId: FIXTURE_SCAN,
      resourceClass: "fixture",
      nodes: fixture.nodes.map((n) => ({
        type: n.type as NodeType,
        nativeId: n.id,
        name: n.name ?? null,
        props: n.props ?? {},
      })),
      edges: fixture.edges.map((e) => ({
        type: e.type as EdgeType,
        src: e.src,
        dst: e.dst,
        key: e.key ?? "",
        props: e.props ?? {},
      })),
    },
    at,
  );
  applyBatch(db, batch);
  for (const e of fixture.edges.filter((edge) => edge.deleted)) {
    db.run(
      "UPDATE edges SET deleted_at = ? WHERE id = ?",
      at,
      edgeId(e.type as EdgeType, e.src, e.dst, e.key ?? ""),
    );
  }
  replaceExposure(
    db,
    (fixture.exposure ?? []).map((x) => ({
      entryId: x.entry,
      pathPrefix: x.path ?? "/",
      decision: x.decision as ExposureDecision,
      confidence: x.confidence as Confidence,
    })),
    at,
  );
  upsertVulns(
    db,
    (fixture.vulns ?? []).map((v) => ({
      packageId: v.package,
      vulnId: v.id,
      severityRank: SEVERITY_RANK[v.severity],
      kev: v.kev ?? false,
      status: v.status ?? "open",
      source: "fixture",
    })),
    at,
  );
  setSignals(
    db,
    (fixture.signals ?? []).map((s) => ({ nodeId: s.node, name: s.name, value: s.value })),
    at,
  );
}

export interface FixtureResult {
  passed: boolean;
  expected: string[];
  actual: string[];
}

const describeHit = (fingerprint: string, severity?: string) =>
  severity ? `${fingerprint} (${severity})` : fingerprint;

/**
 * Runs the rule against a loaded fixture and compares fingerprints, and
 * severities where the fixture names one.
 */
export function evaluateFixture(
  db: SqlRunner,
  rule: CompiledRule,
  fixture: RuleFixture,
): FixtureResult {
  const hits = runRule(db, rule, fixture.params);
  const bySeverity = new Map(hits.map((h) => [h.fingerprint, h.severity]));
  const expected = fixture.expect.map((e) => describeHit(e.fingerprint, e.severity)).sort();
  const actual = fixture.expect
    .filter((e) => bySeverity.has(e.fingerprint))
    .map((e) => describeHit(e.fingerprint, e.severity ? bySeverity.get(e.fingerprint) : undefined))
    .concat(
      hits
        .filter((h) => !fixture.expect.some((e) => e.fingerprint === h.fingerprint))
        .map((h) => describeHit(h.fingerprint, h.severity)),
    )
    .sort();
  return {
    passed: expected.length === actual.length && expected.every((e, i) => e === actual[i]),
    expected,
    actual,
  };
}
