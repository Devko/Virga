import { LIMITS, NODE_TYPES, type Row, type SqlRunner, type SqlValue } from "@virga/graph";
import { runRule } from "./runtime.ts";
import { type CompiledRule, RULE_SEVERITIES, type RuleSeverity } from "./types.ts";

export interface RuleRunSummary {
  ruleId: string;
  status: "evaluated" | "not_evaluated" | "error";
  /** Rows the rule returned; 0 unless evaluated. */
  hits: number;
  /** Resource classes or derived tables without complete coverage. */
  missing: string[];
  /** Findings created, or reopened after they were resolved. */
  opened: number;
  /** Open or suppressed findings resolved because the rule no longer returns them. */
  resolved: number;
  error?: string;
}

/**
 * Runs rules for a scan and maintains the findings lifecycle
 * (docs/architecture/data-model.md, "Findings lifecycle"):
 *
 * - A rule whose `requires` includes a resource class without `complete`
 *   coverage in this scan is `not_evaluated` and changes no finding; its
 *   query does not run. Derived inputs (`exposure`, `vulns`, `packages`)
 *   count as complete once their producing step marked them complete in
 *   `coverage`.
 * - Hits upsert findings by fingerprint (open, last_seen, evidence,
 *   finding_nodes); a resolved finding that reappears is reopened.
 * - Open findings of an evaluated rule that are no longer returned are
 *   resolved.
 * - Expired suppressions return to open; suppressed findings stay
 *   suppressed while the suppression lasts unless their severity rises.
 * - One row per rule in `rule_runs`.
 *
 * Output contract. Every row a rule returns has
 * - `rule_id`: the rule's ID;
 * - `fingerprint`: `<rule_id>:` followed by a key that is stable across
 *   scans and unique in the result (D-10: one finding per subject);
 * - `severity`: one of `RULE_SEVERITIES`;
 * - `subject_id`: the ID (`<type>:<native_id>`) of the node the finding is
 *   about.
 * A row that breaks the contract makes the run an `error`.
 *
 * Evidence is every other column, stored by column name as a JSON object in
 * `findings.evidence`. Text that parses as a JSON array (`json_group_array`,
 * `json_array`) is stored parsed, any other value as returned. Text from the
 * scanned account belongs inside such an array, so a name that happens to
 * look like JSON is never mistaken for one. Lists keep at most 100 items and
 * strings at most 2,048 characters; `_truncated` maps each shortened list to
 * its full length.
 *
 * `finding_nodes` holds `subject_id` with role `subject`, plus every node ID
 * of an evidence list whose items are all node IDs (nulls ignored), with the
 * column name as role. It is replaced on every hit and kept on resolve.
 *
 * `title` is the rule title. Title, rule version and evidence are refreshed
 * on every hit; `first_seen` never changes.
 *
 * Suppression details: while a suppression lasts (`suppressed_until` after
 * `at`), `severity` keeps the level the suppression accepted, and a hit with
 * a higher severity ends it. A finding that returns to open, or is resolved,
 * loses its suppression fields. Suppressed findings that are no longer
 * returned are resolved like open ones.
 *
 * A rule that names an insight type in `enriches` links each finding to the
 * first live insight of that type whose subject is one of the finding's
 * nodes (`insight_id`).
 *
 * Each rule's finding changes and its `rule_runs` row commit in one
 * transaction. A rule whose query fails or whose output breaks the contract
 * is `error`, changes no finding, and does not stop the rules after it.
 * `at` is the evaluation time in epoch milliseconds.
 */
export function evaluateRules(
  db: SqlRunner,
  rules: readonly CompiledRule[],
  scanId: string,
  at = Date.now(),
): RuleRunSummary[] {
  const complete = new Set(
    db
      .query<{ resource_class: string }>(
        "SELECT resource_class FROM coverage WHERE scan_id = ? AND status = 'complete'",
        scanId,
      )
      .map((row) => row.resource_class),
  );
  return rules.map((rule): RuleRunSummary => {
    const missing = rule.requires.filter((input) => !complete.has(input));
    const summary = { ruleId: rule.id, hits: 0, missing, opened: 0, resolved: 0 };
    if (missing.length > 0) {
      recordRun(db, scanId, rule.id, "not_evaluated", 0, missing);
      return { ...summary, status: "not_evaluated" };
    }
    try {
      const hits = prepareHits(rule, runRule(db, rule));
      const counts = db.transaction(() => {
        const result = applyHits(db, rule, hits, at);
        recordRun(db, scanId, rule.id, "evaluated", hits.length, null);
        return result;
      });
      return { ...summary, status: "evaluated", hits: hits.length, ...counts };
    } catch (error) {
      recordRun(db, scanId, rule.id, "error", 0, null);
      const message = error instanceof Error ? error.message : String(error);
      return { ...summary, status: "error", error: message.slice(0, MAX_ERROR) };
    }
  });
}

const CONTRACT_COLUMNS = new Set(["rule_id", "fingerprint", "severity", "subject_id"]);
const SEVERITY_RANK: Record<RuleSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
const MAX_LIST = 100;
const MAX_STRING = 2048;
const MAX_FINGERPRINT = 2048;
const MAX_EVIDENCE_BYTES = 256 * 1024;
const MAX_ERROR = 500;
// Statements take their rows as one JSON parameter, well below the 2 MB
// string limit of Durable Object SQL.
const JSON_PARAM_BYTES = 1_000_000;

const nodeTypes = new Set<string>(NODE_TYPES);
const severities = new Set<string>(RULE_SEVERITIES);
const encoder = new TextEncoder();

interface Hit {
  fingerprint: string;
  severity: RuleSeverity;
  evidence: string;
  nodes: { node: string; role: string }[];
}

interface StoredFinding {
  fingerprint: string;
  status: "open" | "resolved" | "suppressed";
  severity: RuleSeverity;
  suppressed_until: number | null;
}

function isNodeId(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const colon = value.indexOf(":");
  return (
    colon > 0 &&
    colon < value.length - 1 &&
    value.length - colon - 1 <= LIMITS.nativeId &&
    nodeTypes.has(value.slice(0, colon))
  );
}

const clip = (value: unknown): unknown =>
  typeof value === "string" && value.length > MAX_STRING ? value.slice(0, MAX_STRING) : value;

function evidenceValue(value: SqlValue, where: string, column: string): unknown {
  if (typeof value === "object" && value !== null) {
    throw new Error(`${where}: column ${column} is a blob`);
  }
  if (typeof value === "string" && value.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(value);
      if (Array.isArray(parsed)) return parsed;
    } catch {}
  }
  return value;
}

/** Validates rule output against the contract and builds evidence and node links. */
function prepareHits(rule: CompiledRule, rows: readonly Row[]): Hit[] {
  const seen = new Set<string>();
  // Messages name rows by position: values may come from the scanned account.
  return rows.map((row, index) => {
    const where = `${rule.id}: row ${index + 1}`;
    if (row.rule_id !== rule.id) throw new Error(`${where}: rule_id is not ${rule.id}`);
    const { fingerprint, severity, subject_id: subject } = row;
    if (
      typeof fingerprint !== "string" ||
      !fingerprint.startsWith(`${rule.id}:`) ||
      fingerprint.length > MAX_FINGERPRINT
    ) {
      throw new Error(`${where}: fingerprint must start with ${rule.id}: and fit the limit`);
    }
    if (seen.has(fingerprint)) throw new Error(`${where}: duplicate fingerprint`);
    seen.add(fingerprint);
    if (typeof severity !== "string" || !severities.has(severity)) {
      throw new Error(`${where}: invalid severity`);
    }
    if (!isNodeId(subject)) throw new Error(`${where}: subject_id is not a node ID`);

    const evidence: Record<string, unknown> = {};
    const truncated: Record<string, number> = {};
    const nodes = [{ node: subject, role: "subject" }];
    for (const [column, value] of Object.entries(row)) {
      if (CONTRACT_COLUMNS.has(column)) continue;
      const parsed = evidenceValue(value, where, column);
      if (!Array.isArray(parsed)) {
        evidence[column] = clip(parsed);
        continue;
      }
      if (parsed.length > MAX_LIST) truncated[column] = parsed.length;
      const items = parsed.slice(0, MAX_LIST).map(clip);
      evidence[column] = items;
      const present = items.filter((item) => item !== null);
      if (present.length > 0 && present.every(isNodeId)) {
        for (const node of new Set(present)) nodes.push({ node, role: column });
      }
    }
    if (Object.keys(truncated).length > 0) evidence._truncated = truncated;
    const json = JSON.stringify(evidence);
    if (encoder.encode(json).length > MAX_EVIDENCE_BYTES) {
      throw new Error(`${where}: evidence larger than ${MAX_EVIDENCE_BYTES} bytes`);
    }
    return { fingerprint, severity: severity as RuleSeverity, evidence: json, nodes };
  });
}

const UPSERT_FINDINGS = `
INSERT INTO findings (fingerprint, rule_id, rule_version, severity, status, title, evidence,
                      insight_id, first_seen, last_seen)
SELECT j.value ->> '$.fingerprint', ?, ?, j.value ->> '$.severity', j.value ->> '$.status', ?,
       j.value ->> '$.evidence', j.value ->> '$.insight_id', ?, ?
FROM json_each(?) AS j WHERE true
ON CONFLICT (fingerprint) DO UPDATE SET
  rule_id          = excluded.rule_id,
  rule_version     = excluded.rule_version,
  severity         = excluded.severity,
  status           = excluded.status,
  title            = excluded.title,
  evidence         = excluded.evidence,
  insight_id       = excluded.insight_id,
  last_seen        = excluded.last_seen,
  resolved_at      = NULL,
  suppressed_until = CASE WHEN excluded.status = 'suppressed' THEN findings.suppressed_until END,
  suppressed_by    = CASE WHEN excluded.status = 'suppressed' THEN findings.suppressed_by END,
  suppress_reason  = CASE WHEN excluded.status = 'suppressed' THEN findings.suppress_reason END`;

const CLEAR_NODES =
  "DELETE FROM finding_nodes WHERE fingerprint IN (SELECT value FROM json_each(?))";

const INSERT_NODES = `
INSERT OR IGNORE INTO finding_nodes (fingerprint, node_id, role)
SELECT j.value ->> '$.fingerprint', j.value ->> '$.node', j.value ->> '$.role'
FROM json_each(?) AS j`;

const RESOLVE = `
UPDATE findings
SET status = 'resolved', resolved_at = ?,
    suppressed_until = NULL, suppressed_by = NULL, suppress_reason = NULL
WHERE fingerprint IN (SELECT value FROM json_each(?))`;

function applyHits(
  db: SqlRunner,
  rule: CompiledRule,
  hits: readonly Hit[],
  at: number,
): { opened: number; resolved: number } {
  const stored = new Map(
    db
      .query<StoredFinding & Row>(
        "SELECT fingerprint, status, severity, suppressed_until FROM findings WHERE rule_id = ?",
        rule.id,
      )
      .map((finding) => [finding.fingerprint, finding]),
  );
  const insightFor = insightLookup(db, rule);
  let opened = 0;
  const rows = hits.map((hit) => {
    const before = stored.get(hit.fingerprint);
    let status: StoredFinding["status"] = "open";
    let severity = hit.severity;
    if (!before || before.status === "resolved") {
      opened++;
    } else if (
      before.status === "suppressed" &&
      (before.suppressed_until ?? 0) > at &&
      SEVERITY_RANK[hit.severity] <= SEVERITY_RANK[before.severity]
    ) {
      status = "suppressed";
      severity = before.severity;
    }
    return {
      fingerprint: hit.fingerprint,
      severity,
      status,
      evidence: hit.evidence,
      insight_id: insightFor(hit),
    };
  });

  const returned = new Set(hits.map((hit) => hit.fingerprint));
  const gone = [...stored.values()]
    .filter((finding) => finding.status !== "resolved" && !returned.has(finding.fingerprint))
    .map((finding) => finding.fingerprint);
  const links = hits.flatMap((hit) =>
    hit.nodes.map(({ node, role }) => ({ fingerprint: hit.fingerprint, node, role })),
  );

  for (const json of jsonChunks(rows)) {
    db.run(UPSERT_FINDINGS, rule.id, rule.version, rule.title, at, at, json);
  }
  for (const json of jsonChunks([...returned])) db.run(CLEAR_NODES, json);
  for (const json of jsonChunks(links)) db.run(INSERT_NODES, json);
  for (const json of jsonChunks(gone)) db.run(RESOLVE, at, json);
  return { opened, resolved: gone.length };
}

function insightLookup(db: SqlRunner, rule: CompiledRule): (hit: Hit) => string | null {
  if (!rule.enriches) return () => null;
  const bySubject = new Map<string, string>();
  const rows = db.query<{ id: string; subject_id: string }>(
    `SELECT id, subject_id FROM insights
     WHERE type = ? AND subject_id IS NOT NULL AND deleted_at IS NULL ORDER BY id`,
    rule.enriches,
  );
  for (const row of rows) if (!bySubject.has(row.subject_id)) bySubject.set(row.subject_id, row.id);
  return (hit) => {
    for (const { node } of hit.nodes) {
      const id = bySubject.get(node);
      if (id) return id;
    }
    return null;
  };
}

function recordRun(
  db: SqlRunner,
  scanId: string,
  ruleId: string,
  status: RuleRunSummary["status"],
  hits: number,
  missing: string[] | null,
): void {
  db.run(
    `INSERT INTO rule_runs (scan_id, rule_id, status, hits, missing) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (scan_id, rule_id) DO UPDATE SET
       status = excluded.status, hits = excluded.hits, missing = excluded.missing`,
    scanId,
    ruleId,
    status,
    hits,
    missing ? JSON.stringify(missing) : null,
  );
}

function* jsonChunks(items: readonly unknown[]): Generator<string> {
  let chunk: string[] = [];
  let size = 2;
  for (const item of items) {
    const json = JSON.stringify(item);
    const bytes = encoder.encode(json).length + 1;
    if (chunk.length > 0 && size + bytes > JSON_PARAM_BYTES) {
      yield `[${chunk.join(",")}]`;
      chunk = [];
      size = 2;
    }
    chunk.push(json);
    size += bytes;
  }
  if (chunk.length > 0) yield `[${chunk.join(",")}]`;
}
