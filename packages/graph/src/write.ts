import { canonicalJson, sha256 } from "./hash.ts";
import type { SqlRunner } from "./sql.ts";
import {
  type Batch,
  type Confidence,
  type CoverageStatus,
  EDGE_TYPES,
  type EdgeInput,
  type ExposureDecision,
  edgeId,
  LIMITS,
  NODE_TYPES,
  type NodeInput,
  nodeId,
} from "./types.ts";

interface PreparedNode {
  id: string;
  type: string;
  native_id: string;
  name: string | null;
  props: string;
  hash: string;
}

interface PreparedEdge {
  id: string;
  src: string;
  dst: string;
  type: string;
  key: string;
  props: string;
  hash: string;
}

/** A batch with IDs and content hashes computed, ready for the synchronous write. */
export interface PreparedBatch {
  scanId: string;
  resourceClass: string;
  at: number;
  nodes: PreparedNode[];
  edges: PreparedEdge[];
}

export interface BatchResult {
  nodes: number;
  edges: number;
  /** Rows created, changed or restored by this batch. */
  changed: number;
}

const nodeTypes = new Set<string>(NODE_TYPES);
const edgeTypes = new Set<string>(EDGE_TYPES);
const encoder = new TextEncoder();

function checkLength(value: string, max: number, what: string): void {
  if (value.length > max) throw new RangeError(`${what} longer than ${max} characters`);
}

function serializeProps(props: object | undefined, what: string): string {
  const json = canonicalJson(props ?? {});
  if (encoder.encode(json).length > LIMITS.propsBytes) {
    throw new RangeError(`${what}: props larger than ${LIMITS.propsBytes} bytes`);
  }
  return json;
}

async function prepareNode(node: NodeInput): Promise<PreparedNode> {
  if (!nodeTypes.has(node.type)) throw new TypeError(`unknown node type: ${node.type}`);
  checkLength(node.nativeId, LIMITS.nativeId, "nativeId");
  if (node.name) checkLength(node.name, LIMITS.name, "name");
  const id = nodeId(node.type, node.nativeId);
  const props = serializeProps(node.props, id);
  const name = node.name ?? null;
  return {
    id,
    type: node.type,
    native_id: node.nativeId,
    name,
    props,
    hash: await sha256(`${name ?? ""}\u0000${props}`),
  };
}

async function prepareEdge(edge: EdgeInput): Promise<PreparedEdge> {
  if (!edgeTypes.has(edge.type)) throw new TypeError(`unknown edge type: ${edge.type}`);
  const key = edge.key ?? "";
  checkLength(key, LIMITS.name, "edge key");
  const id = edgeId(edge.type, edge.src, edge.dst, key);
  const props = serializeProps(edge.props, id);
  return {
    id,
    src: edge.src,
    dst: edge.dst,
    type: edge.type,
    key,
    props,
    hash: await sha256(props),
  };
}

/** Validates a batch and computes IDs and hashes. Async because hashing uses Web Crypto. */
export async function prepareBatch(batch: Batch, at = Date.now()): Promise<PreparedBatch> {
  return {
    scanId: batch.scanId,
    resourceClass: batch.resourceClass,
    at,
    nodes: await Promise.all(batch.nodes.map(prepareNode)),
    edges: await Promise.all(batch.edges.map(prepareEdge)),
  };
}

/** Splits rows into JSON strings below the per-parameter size limit. */
function* jsonChunks(rows: readonly object[]): Generator<string> {
  let chunk: string[] = [];
  let size = 2;
  for (const row of rows) {
    const json = JSON.stringify(row);
    const bytes = encoder.encode(json).length + 1;
    if (chunk.length > 0 && size + bytes > LIMITS.batchBytes) {
      yield `[${chunk.join(",")}]`;
      chunk = [];
      size = 2;
    }
    chunk.push(json);
    size += bytes;
  }
  if (chunk.length > 0) yield `[${chunk.join(",")}]`;
}

// Rows are written in every scan (seen_scan), but content, changed_at and the
// history triggers only react when the hash changes or a tombstone is lifted.
const UPSERT_NODES = `
INSERT INTO nodes (id, type, native_id, class, name, props, hash, first_seen, changed_at, seen_scan)
SELECT j.value ->> '$.id', j.value ->> '$.type', j.value ->> '$.native_id', ?,
       j.value ->> '$.name', j.value ->> '$.props', j.value ->> '$.hash', ?, ?, ?
FROM json_each(?) AS j WHERE true
ON CONFLICT (id) DO UPDATE SET
  seen_scan  = excluded.seen_scan,
  class      = excluded.class,
  name       = CASE WHEN nodes.hash IS NOT excluded.hash THEN excluded.name ELSE nodes.name END,
  props      = CASE WHEN nodes.hash IS NOT excluded.hash THEN excluded.props ELSE nodes.props END,
  changed_at = CASE WHEN nodes.hash IS NOT excluded.hash OR nodes.deleted_at IS NOT NULL
                    THEN excluded.changed_at ELSE nodes.changed_at END,
  hash       = excluded.hash,
  deleted_at = NULL`;

const UPSERT_EDGES = `
INSERT INTO edges (id, src, dst, type, key, class, props, hash, first_seen, changed_at, seen_scan)
SELECT j.value ->> '$.id', j.value ->> '$.src', j.value ->> '$.dst', j.value ->> '$.type',
       j.value ->> '$.key', ?, j.value ->> '$.props', j.value ->> '$.hash', ?, ?, ?
FROM json_each(?) AS j WHERE true
ON CONFLICT (id) DO UPDATE SET
  seen_scan  = excluded.seen_scan,
  class      = excluded.class,
  props      = CASE WHEN edges.hash IS NOT excluded.hash THEN excluded.props ELSE edges.props END,
  changed_at = CASE WHEN edges.hash IS NOT excluded.hash OR edges.deleted_at IS NOT NULL
                    THEN excluded.changed_at ELSE edges.changed_at END,
  hash       = excluded.hash,
  deleted_at = NULL`;

function lastChangeSeq(db: SqlRunner): number {
  return db.query<{ seq: number | null }>("SELECT max(seq) AS seq FROM changes")[0]?.seq ?? 0;
}

/** Writes a prepared batch in one transaction. */
export function applyBatch(db: SqlRunner, batch: PreparedBatch): BatchResult {
  return db.transaction(() => {
    const before = lastChangeSeq(db);
    const { resourceClass: cls, at, scanId } = batch;
    for (const json of jsonChunks(batch.nodes)) db.run(UPSERT_NODES, cls, at, at, scanId, json);
    for (const json of jsonChunks(batch.edges)) db.run(UPSERT_EDGES, cls, at, at, scanId, json);
    return {
      nodes: batch.nodes.length,
      edges: batch.edges.length,
      changed: lastChangeSeq(db) - before,
    };
  });
}

/** Starts a scan and makes it the scan that history rows from sweeps refer to. */
export function beginScan(
  db: SqlRunner,
  scan: { id: string; kind: "full" | "partial" | "event" | "fixture"; at?: number },
): void {
  db.transaction(() => {
    db.run(
      "INSERT INTO scans (id, kind, started_at, status) VALUES (?, ?, ?, 'running')",
      scan.id,
      scan.kind,
      scan.at ?? Date.now(),
    );
    db.run(
      `INSERT INTO meta (key, value) VALUES ('current_scan', ?)
       ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
      scan.id,
    );
  });
}

export function finishScan(
  db: SqlRunner,
  scanId: string,
  status: "complete" | "failed",
  at = Date.now(),
): void {
  db.run("UPDATE scans SET status = ?, finished_at = ? WHERE id = ?", status, at, scanId);
}

export function recordCoverage(
  db: SqlRunner,
  coverage: {
    scanId: string;
    resourceClass: string;
    status: CoverageStatus;
    chunksTotal?: number;
    chunksDone?: number;
    detail?: string | null;
  },
): void {
  db.run(
    `INSERT INTO coverage (scan_id, resource_class, status, chunks_total, chunks_done, detail)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (scan_id, resource_class) DO UPDATE SET
       status = excluded.status, chunks_total = excluded.chunks_total,
       chunks_done = excluded.chunks_done, detail = excluded.detail`,
    coverage.scanId,
    coverage.resourceClass,
    coverage.status,
    coverage.chunksTotal ?? 0,
    coverage.chunksDone ?? 0,
    coverage.detail ?? null,
  );
}

export interface SweepResult {
  swept: boolean;
  nodes: number;
  edges: number;
}

/**
 * Tombstones rows of a resource class that the scan did not see, plus edges
 * that point to nodes tombstoned now. Does nothing unless the class has
 * coverage `complete` in this scan.
 */
export function sweep(
  db: SqlRunner,
  scanId: string,
  resourceClass: string,
  at = Date.now(),
): SweepResult {
  return db.transaction(() => {
    const status = db.query<{ status: string }>(
      "SELECT status FROM coverage WHERE scan_id = ? AND resource_class = ?",
      scanId,
      resourceClass,
    )[0]?.status;
    if (status !== "complete") return { swept: false, nodes: 0, edges: 0 };

    db.run(
      `INSERT INTO meta (key, value) VALUES ('current_scan', ?)
       ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
      scanId,
    );
    const count = (sql: string, ...params: (string | number)[]) =>
      db.query<{ n: number }>(sql, ...params)[0]?.n ?? 0;

    const nodes = count(
      `SELECT count(*) AS n FROM nodes
       WHERE class = ? AND deleted_at IS NULL AND seen_scan IS NOT ?`,
      resourceClass,
      scanId,
    );
    db.run(
      `UPDATE nodes SET deleted_at = ?
       WHERE class = ? AND deleted_at IS NULL AND seen_scan IS NOT ?`,
      at,
      resourceClass,
      scanId,
    );
    const edges = count(
      `SELECT count(*) AS n FROM edges
       WHERE deleted_at IS NULL AND (
         (class = ? AND seen_scan IS NOT ?)
         OR src IN (SELECT id FROM nodes WHERE deleted_at = ?)
         OR dst IN (SELECT id FROM nodes WHERE deleted_at = ?))`,
      resourceClass,
      scanId,
      at,
      at,
    );
    db.run(
      `UPDATE edges SET deleted_at = ?
       WHERE deleted_at IS NULL AND (
         (class = ? AND seen_scan IS NOT ?)
         OR src IN (SELECT id FROM nodes WHERE deleted_at = ?)
         OR dst IN (SELECT id FROM nodes WHERE deleted_at = ?))`,
      at,
      resourceClass,
      scanId,
      at,
      at,
    );
    return { swept: true, nodes, edges };
  });
}

export interface ExposureRow {
  entryId: string;
  pathPrefix?: string;
  decision: ExposureDecision;
  confidence: Confidence;
  reasonId?: string | null;
  reason?: string | null;
}

/** Replaces the whole exposure table with the evaluator's latest output. */
export function replaceExposure(
  db: SqlRunner,
  rows: readonly ExposureRow[],
  at = Date.now(),
): void {
  const data = rows.map((r) => ({
    entry_id: r.entryId,
    path_prefix: r.pathPrefix ?? "/",
    decision: r.decision,
    confidence: r.confidence,
    reason_id: r.reasonId ?? null,
    reason: r.reason ?? null,
  }));
  db.transaction(() => {
    db.run("DELETE FROM exposure");
    for (const json of jsonChunks(data)) {
      db.run(
        `INSERT INTO exposure (entry_id, path_prefix, decision, confidence, reason_id, reason, computed_at)
         SELECT j.value ->> '$.entry_id', j.value ->> '$.path_prefix', j.value ->> '$.decision',
                j.value ->> '$.confidence', j.value ->> '$.reason_id', j.value ->> '$.reason', ?
         FROM json_each(?) AS j`,
        at,
        json,
      );
    }
  });
}

export interface VulnRow {
  packageId: string;
  vulnId: string;
  severityRank: 0 | 1 | 2 | 3 | 4;
  kev?: boolean;
  aliases?: string[];
  fixedIn?: string | null;
  status?: "open" | "fixed" | "ignored";
  source: string;
}

export function upsertVulns(db: SqlRunner, rows: readonly VulnRow[], at = Date.now()): void {
  const data = rows.map((r) => ({
    package_id: r.packageId,
    vuln_id: r.vulnId,
    aliases: JSON.stringify(r.aliases ?? []),
    severity_rank: r.severityRank,
    kev: r.kev ? 1 : 0,
    fixed_in: r.fixedIn ?? null,
    status: r.status ?? "open",
    source: r.source,
  }));
  db.transaction(() => {
    for (const json of jsonChunks(data)) {
      db.run(
        `INSERT INTO vulns (package_id, vuln_id, aliases, severity_rank, kev, fixed_in, status, source, first_seen)
         SELECT j.value ->> '$.package_id', j.value ->> '$.vuln_id', j.value ->> '$.aliases',
                j.value ->> '$.severity_rank', j.value ->> '$.kev', j.value ->> '$.fixed_in',
                j.value ->> '$.status', j.value ->> '$.source', ?
         FROM json_each(?) AS j WHERE true
         ON CONFLICT (package_id, vuln_id) DO UPDATE SET
           aliases = excluded.aliases, severity_rank = excluded.severity_rank, kev = excluded.kev,
           fixed_in = excluded.fixed_in, status = excluded.status, source = excluded.source`,
        at,
        json,
      );
    }
  });
}

export interface SignalRow {
  nodeId: string;
  name: string;
  value: number | string | null;
}

export function setSignals(db: SqlRunner, rows: readonly SignalRow[], at = Date.now()): void {
  const data = rows.map((r) => ({ node_id: r.nodeId, name: r.name, value: r.value }));
  db.transaction(() => {
    for (const json of jsonChunks(data)) {
      db.run(
        `INSERT INTO signals (node_id, name, value, observed_at)
         SELECT j.value ->> '$.node_id', j.value ->> '$.name', j.value ->> '$.value', ?
         FROM json_each(?) AS j WHERE true
         ON CONFLICT (node_id, name) DO UPDATE SET
           value = excluded.value, observed_at = excluded.observed_at`,
        at,
        json,
      );
    }
  });
}

export interface InsightRow {
  id: string;
  type: string;
  severity: string | null;
  /** Node the insight is about, if the collector could resolve it. */
  subjectId: string | null;
  payload: Record<string, unknown>;
}

/**
 * Makes the insights table match the given complete set: upserts every row
 * and tombstones insights that are no longer reported. Call only with the
 * full result of a complete collector run.
 */
export function replaceInsights(db: SqlRunner, rows: readonly InsightRow[], at = Date.now()): void {
  const data = rows.map((r) => ({
    id: r.id,
    type: r.type,
    severity: r.severity,
    subject_id: r.subjectId,
    payload: JSON.stringify(r.payload),
  }));
  db.transaction(() => {
    db.run("UPDATE insights SET deleted_at = ? WHERE deleted_at IS NULL", at);
    for (const json of jsonChunks(data)) {
      db.run(
        `INSERT INTO insights (id, type, severity, subject_id, payload, first_seen)
         SELECT j.value ->> '$.id', j.value ->> '$.type', j.value ->> '$.severity',
                j.value ->> '$.subject_id', j.value ->> '$.payload', ?
         FROM json_each(?) AS j WHERE true
         ON CONFLICT (id) DO UPDATE SET
           type = excluded.type, severity = excluded.severity, subject_id = excluded.subject_id,
           payload = excluded.payload, deleted_at = NULL`,
        at,
        json,
      );
    }
  });
}
