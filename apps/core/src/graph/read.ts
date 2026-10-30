import type { Row, SqlRunner } from "@virga/graph";
import { type JsonRecord, untrusted } from "../untrusted.ts";
import {
  type EdgeView,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  type FindingDetail,
  type FindingFilters,
  type FindingPage,
  type FindingSeverity,
  type FindingStatus,
  type FindingView,
  type GraphSummary,
  type Neighborhood,
  type NodeView,
  type RuleRunStatus,
  type RuleRunView,
} from "./views.ts";

/** Read queries behind GraphReader. Pure reads; nothing here writes. */

export const FINDINGS_PAGE = { default: 50, max: 200 } as const;
export const NEIGHBORHOOD = { maxDepth: 2, defaultLimit: 100, maxLimit: 500 } as const;
const MAX_FINDING_NODES = 500;
// Edges read per hop, relative to the node limit, before the result is cut.
const EDGES_PER_NODE = 8;

// props and evidence columns hold JSON objects (CHECK json_valid in the schema).
const parseJson = (text: unknown): JsonRecord => {
  if (typeof text !== "string") return {};
  const value: unknown = JSON.parse(text);
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : {};
};

const str = (value: unknown): string | null => (typeof value === "string" ? value : null);
const int = (value: unknown): number | null => (typeof value === "number" ? value : null);

// rule_runs.missing is a JSON array of input names, or null; it has no json_valid check.
const stringList = (text: unknown): string[] => {
  if (typeof text !== "string") return [];
  try {
    const value: unknown = JSON.parse(text);
    return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
  } catch {
    return [];
  }
};

// As evaluateRules caps it (graph contract, scan semantics).
const MAX_RULE_ERROR = 500;

const NODE_COLUMNS = "id, type, native_id, class, name, props, first_seen, changed_at, deleted_at";
const EDGE_COLUMNS = "id, type, src, dst, key, class, props";

function nodeView(row: Row): NodeView {
  return {
    id: untrusted(String(row.id)),
    type: String(row.type),
    nativeId: untrusted(String(row.native_id)),
    class: String(row.class),
    name: row.name === null ? null : untrusted(String(row.name)),
    props: untrusted(parseJson(row.props)),
    firstSeen: Number(row.first_seen),
    changedAt: Number(row.changed_at),
    deletedAt: int(row.deleted_at),
  };
}

function edgeView(row: Row): EdgeView {
  return {
    id: untrusted(String(row.id)),
    type: String(row.type),
    src: untrusted(String(row.src)),
    dst: untrusted(String(row.dst)),
    key: untrusted(String(row.key)),
    class: String(row.class),
    props: untrusted(parseJson(row.props)),
  };
}

/**
 * The findings table as of `at`, which is the first `?` of the statement.
 * A suppression ends at its date, but the findings lifecycle stores that
 * only on the rule's next evaluated run (R3-07); while the rule stays
 * `not_evaluated` or `error`, the row stays `suppressed`. Reads show such a
 * finding as open and without its suppression, as the lifecycle will store
 * it. As there, a suppression lasts only while `suppressed_until` is after `at`.
 */
const FINDINGS_AT = `(
  SELECT fingerprint, rule_id, rule_version, severity, title, evidence, insight_id,
         first_seen, last_seen, resolved_at,
         CASE WHEN ended THEN 'open' ELSE status END AS status,
         CASE WHEN ended THEN NULL ELSE suppressed_until END AS suppressed_until,
         CASE WHEN ended THEN NULL ELSE suppressed_by END AS suppressed_by,
         CASE WHEN ended THEN NULL ELSE suppress_reason END AS suppress_reason
  FROM (SELECT *, status = 'suppressed' AND COALESCE(suppressed_until, 0) <= ? AS ended
        FROM findings)
)`;

const SEVERITY_RANK_SQL = `CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
  WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`;
const SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function findingView(row: Row): FindingView {
  const insightId = str(row.insight_id);
  return {
    fingerprint: untrusted(String(row.fingerprint)),
    ruleId: String(row.rule_id),
    ruleVersion: Number(row.rule_version),
    severity: row.severity as FindingSeverity,
    status: row.status as FindingStatus,
    title: String(row.title),
    evidence: untrusted(parseJson(row.evidence)),
    insightId: insightId === null ? null : untrusted(insightId),
    firstSeen: Number(row.first_seen),
    lastSeen: Number(row.last_seen),
    resolvedAt: int(row.resolved_at),
    suppressedUntil: int(row.suppressed_until),
  };
}

function ruleRunView(row: Row): RuleRunView {
  const error = str(row.error);
  return {
    ruleId: String(row.rule_id),
    status: row.status as RuleRunStatus,
    hits: Number(row.hits),
    undecided: Number(row.undecided),
    missing: stringList(row.missing),
    error: error === null ? null : untrusted(error.slice(0, MAX_RULE_ERROR)),
  };
}

export function graphSummary(db: SqlRunner, at = Date.now()): GraphSummary {
  const scan =
    db.query(
      `SELECT id, kind, status, started_at, finished_at FROM scans
       ORDER BY started_at DESC, id DESC LIMIT 1`,
    )[0] ?? null;
  const counts = (sql: string, ...params: string[]) =>
    Object.fromEntries(
      db.query<{ k: string; n: number }>(sql, ...params).map((r) => [r.k, Number(r.n)]),
    );

  const findings: GraphSummary["findings"] = { open: {}, resolved: {}, suppressed: {} };
  for (const row of db.query<{ status: FindingStatus; severity: FindingSeverity; n: number }>(
    `SELECT status, severity, count(*) AS n FROM ${FINDINGS_AT} GROUP BY status, severity`,
    at,
  )) {
    findings[row.status][row.severity] = Number(row.n);
  }

  const scanId = scan ? String(scan.id) : null;
  return {
    scan: scan && {
      id: String(scan.id),
      kind: String(scan.kind),
      status: String(scan.status),
      startedAt: Number(scan.started_at),
      finishedAt: int(scan.finished_at),
    },
    coverage: scanId
      ? db
          .query(
            `SELECT resource_class, status, chunks_total, chunks_done, detail FROM coverage
             WHERE scan_id = ? ORDER BY resource_class`,
            scanId,
          )
          .map((r) => ({
            resourceClass: String(r.resource_class),
            status: String(r.status),
            chunksTotal: Number(r.chunks_total),
            chunksDone: Number(r.chunks_done),
            detail: r.detail === null ? null : untrusted(String(r.detail)),
          }))
      : [],
    nodes: counts(
      "SELECT class AS k, count(*) AS n FROM nodes WHERE deleted_at IS NULL GROUP BY class",
    ),
    findings,
    exposure: counts("SELECT decision AS k, count(*) AS n FROM exposure GROUP BY decision"),
    rules: scanId
      ? counts(
          "SELECT status AS k, count(*) AS n FROM rule_runs WHERE scan_id = ? GROUP BY status",
          scanId,
        )
      : {},
    ruleRuns: scanId
      ? db
          .query(
            `SELECT rule_id, status, hits, undecided, missing, error FROM rule_runs
             WHERE scan_id = ? ORDER BY rule_id`,
            scanId,
          )
          .map(ruleRunView)
      : [],
  };
}

const asList = <T extends string>(
  value: T | T[] | undefined,
  allowed: readonly T[],
  what: string,
): T[] | null => {
  if (value === undefined) return null;
  const list = Array.isArray(value) ? value : [value];
  for (const v of list) if (!allowed.includes(v)) throw new TypeError(`invalid ${what}`);
  return list.length > 0 ? list : null;
};

const encodeCursor = (rank: number, fingerprint: string) => `${rank}:${fingerprint}`;

function decodeCursor(cursor: string): { rank: number; fingerprint: string } {
  const match = /^([0-4]):(.+)$/s.exec(cursor);
  if (!match?.[1] || !match[2] || cursor.length > 2048) throw new TypeError("invalid cursor");
  return { rank: Number(match[1]), fingerprint: match[2] };
}

/** Findings as of `at` by severity (critical first), then fingerprint, in keyset pages. */
export function listFindings(
  db: SqlRunner,
  filters: FindingFilters = {},
  at = Date.now(),
): FindingPage {
  const statuses = asList(filters.status, FINDING_STATUSES, "status");
  const severities = asList(filters.severity, FINDING_SEVERITIES, "severity");
  const limit = filters.limit ?? FINDINGS_PAGE.default;
  if (!Number.isInteger(limit) || limit < 1 || limit > FINDINGS_PAGE.max) {
    throw new RangeError(`limit must be 1 to ${FINDINGS_PAGE.max}`);
  }
  const after = filters.cursor === undefined ? null : decodeCursor(filters.cursor);
  const statusJson = statuses && JSON.stringify(statuses);
  const severityJson = severities && JSON.stringify(severities);

  const rows = db.query(
    `WITH f AS (SELECT *, ${SEVERITY_RANK_SQL} AS sev_rank FROM ${FINDINGS_AT})
     SELECT * FROM f
     WHERE (? IS NULL OR status IN (SELECT value FROM json_each(?)))
       AND (? IS NULL OR severity IN (SELECT value FROM json_each(?)))
       AND (? IS NULL OR sev_rank < ? OR (sev_rank = ? AND fingerprint > ?))
     ORDER BY sev_rank DESC, fingerprint ASC
     LIMIT ?`,
    at,
    statusJson,
    statusJson,
    severityJson,
    severityJson,
    after?.rank ?? null,
    after?.rank ?? null,
    after?.rank ?? null,
    after?.fingerprint ?? null,
    limit + 1,
  );
  const page = rows.slice(0, limit).map(findingView);
  const last = page.at(-1);
  return {
    findings: page,
    cursor:
      rows.length > limit && last
        ? encodeCursor(SEVERITY_RANK[last.severity], last.fingerprint)
        : null,
  };
}

export function getFinding(
  db: SqlRunner,
  fingerprint: string,
  at = Date.now(),
): FindingDetail | null {
  const row = db.query(`SELECT * FROM ${FINDINGS_AT} WHERE fingerprint = ?`, at, fingerprint)[0];
  if (!row) return null;
  const subjects = db
    .query<{ node_id: string; role: string }>(
      `SELECT node_id, role FROM finding_nodes WHERE fingerprint = ?
       ORDER BY role, node_id LIMIT ?`,
      fingerprint,
      MAX_FINDING_NODES,
    )
    .map((r) => ({ nodeId: untrusted(r.node_id), role: r.role }));
  const nodes = db
    .query(
      `SELECT ${NODE_COLUMNS} FROM nodes WHERE id IN (SELECT value FROM json_each(?)) ORDER BY id`,
      JSON.stringify([...new Set(subjects.map((s) => s.nodeId))]),
    )
    .map(nodeView);
  const by = str(row.suppressed_by);
  const reason = str(row.suppress_reason);
  return {
    ...findingView(row),
    suppressedBy: by === null ? null : untrusted(by),
    suppressReason: reason === null ? null : untrusted(reason),
    subjects,
    nodes,
  };
}

/**
 * Live nodes and edges up to `depth` hops from a node, in both directions.
 * Returns null when the node does not exist or is tombstoned.
 */
export function neighborhood(
  db: SqlRunner,
  nodeId: string,
  options: { depth?: number; limit?: number } = {},
): Neighborhood | null {
  const depth = options.depth ?? 1;
  const limit = options.limit ?? NEIGHBORHOOD.defaultLimit;
  if (!Number.isInteger(depth) || depth < 1 || depth > NEIGHBORHOOD.maxDepth) {
    throw new RangeError(`depth must be 1 to ${NEIGHBORHOOD.maxDepth}`);
  }
  if (!Number.isInteger(limit) || limit < 1 || limit > NEIGHBORHOOD.maxLimit) {
    throw new RangeError(`limit must be 1 to ${NEIGHBORHOOD.maxLimit}`);
  }
  const root = db.query(
    `SELECT ${NODE_COLUMNS} FROM nodes WHERE id = ? AND deleted_at IS NULL`,
    nodeId,
  )[0];
  if (!root) return null;

  const visited = new Set([nodeId]);
  const edges = new Map<string, Row>();
  const edgeLimit = limit * EDGES_PER_NODE;
  let truncated = false;
  let frontier = [nodeId];

  for (let hop = 0; hop < depth && frontier.length > 0; hop++) {
    const ids = JSON.stringify(frontier);
    const next: string[] = [];
    for (const column of ["src", "dst"] as const) {
      const rows = db.query(
        `SELECT ${EDGE_COLUMNS} FROM edges
         WHERE deleted_at IS NULL AND ${column} IN (SELECT value FROM json_each(?))
         ORDER BY id LIMIT ?`,
        ids,
        edgeLimit + 1,
      );
      if (rows.length > edgeLimit) truncated = true;
      for (const row of rows.slice(0, edgeLimit)) {
        const other = String(column === "src" ? row.dst : row.src);
        if (!visited.has(other)) {
          if (visited.size >= limit) {
            truncated = true;
            continue;
          }
          visited.add(other);
          next.push(other);
        }
        edges.set(String(row.id), row);
      }
    }
    frontier = next;
  }

  const nodes = db
    .query(
      `SELECT ${NODE_COLUMNS} FROM nodes
       WHERE deleted_at IS NULL AND id IN (SELECT value FROM json_each(?)) ORDER BY id`,
      JSON.stringify([...visited]),
    )
    .map(nodeView);
  const live = new Set<string>(nodes.map((n) => n.id));
  return {
    root: untrusted(nodeId),
    depth,
    nodes,
    edges: [...edges.values()]
      .filter((e) => visited.has(String(e.src)) && visited.has(String(e.dst)))
      .sort((a, b) => (String(a.id) < String(b.id) ? -1 : 1))
      .map(edgeView),
    missing: [...visited]
      .filter((id) => !live.has(id))
      .sort()
      .map(untrusted),
    truncated,
  };
}
