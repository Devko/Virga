/**
 * Schema migrations for the per-account graph database.
 *
 * Each scanned account has its own SQLite database (one Durable Object), so no
 * table carries an account column. Times are Unix epoch milliseconds, `props`
 * columns hold JSON objects, and confidence is ordinal: 0 low, 1 medium, 2 high.
 */

export interface Migration {
  version: number;
  name: string;
  sql: string;
}

const historyTrigger = (table: "nodes" | "edges", object: "node" | "edge", snapshot: string) => `
CREATE TRIGGER ${table}_history_insert AFTER INSERT ON ${table}
BEGIN
  INSERT INTO changes (scan_id, at, object, object_id, op, before, after)
  VALUES (new.seen_scan, new.changed_at, '${object}', new.id, 'create', NULL, ${snapshot.replaceAll("$", "new")});
END;

CREATE TRIGGER ${table}_history_update AFTER UPDATE ON ${table}
WHEN old.hash IS NOT new.hash OR old.deleted_at IS NOT new.deleted_at
BEGIN
  INSERT INTO changes (scan_id, at, object, object_id, op, before, after)
  VALUES (
    CASE WHEN new.deleted_at IS NOT NULL
      THEN (SELECT value FROM meta WHERE key = 'current_scan')
      ELSE new.seen_scan END,
    COALESCE(new.deleted_at, new.changed_at),
    '${object}',
    new.id,
    CASE
      WHEN new.deleted_at IS NOT NULL THEN 'delete'
      WHEN old.deleted_at IS NOT NULL THEN 'restore'
      ELSE 'update'
    END,
    ${snapshot.replaceAll("$", "old")},
    CASE WHEN new.deleted_at IS NOT NULL THEN NULL ELSE ${snapshot.replaceAll("$", "new")} END
  );
END;
`;

const INIT = `
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE scans (
  id          TEXT PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('full', 'partial', 'event', 'fixture')),
  started_at  INTEGER NOT NULL,
  finished_at INTEGER,
  status      TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed'))
);

CREATE TABLE coverage (
  scan_id        TEXT NOT NULL,
  resource_class TEXT NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('complete', 'partial', 'no_permission', 'error', 'skipped')),
  chunks_total   INTEGER NOT NULL DEFAULT 0,
  chunks_done    INTEGER NOT NULL DEFAULT 0,
  detail         TEXT,
  PRIMARY KEY (scan_id, resource_class)
);

CREATE TABLE nodes (
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL,
  native_id   TEXT NOT NULL,
  class       TEXT NOT NULL,
  name        TEXT,
  props       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(props)),
  hash        TEXT NOT NULL,
  first_seen  INTEGER NOT NULL,
  changed_at  INTEGER NOT NULL,
  seen_scan   TEXT,
  deleted_at  INTEGER
);
CREATE INDEX nodes_type ON nodes (type) WHERE deleted_at IS NULL;
CREATE INDEX nodes_class ON nodes (class) WHERE deleted_at IS NULL;

CREATE TABLE edges (
  id          TEXT PRIMARY KEY,
  src         TEXT NOT NULL,
  dst         TEXT NOT NULL,
  type        TEXT NOT NULL,
  key         TEXT NOT NULL DEFAULT '',
  class       TEXT NOT NULL,
  props       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(props)),
  hash        TEXT NOT NULL,
  first_seen  INTEGER NOT NULL,
  changed_at  INTEGER NOT NULL,
  seen_scan   TEXT,
  deleted_at  INTEGER,
  UNIQUE (src, type, dst, key)
);
CREATE INDEX edges_src ON edges (src, type) WHERE deleted_at IS NULL;
CREATE INDEX edges_dst ON edges (dst, type) WHERE deleted_at IS NULL;
CREATE INDEX edges_class ON edges (class) WHERE deleted_at IS NULL;

CREATE TABLE signals (
  node_id     TEXT NOT NULL,
  name        TEXT NOT NULL,
  value,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY (node_id, name)
);

CREATE TABLE changes (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id    TEXT,
  at         INTEGER NOT NULL,
  object     TEXT NOT NULL CHECK (object IN ('node', 'edge')),
  object_id  TEXT NOT NULL,
  op         TEXT NOT NULL CHECK (op IN ('create', 'update', 'delete', 'restore')),
  before     TEXT CHECK (before IS NULL OR json_valid(before)),
  after      TEXT CHECK (after IS NULL OR json_valid(after))
);
CREATE INDEX changes_object ON changes (object_id, seq);

CREATE TABLE dirty (
  node_id   TEXT PRIMARY KEY,
  marked_at INTEGER NOT NULL,
  audit_id  TEXT
);

CREATE TABLE exposure (
  entry_id    TEXT NOT NULL,
  path_prefix TEXT NOT NULL DEFAULT '/',
  decision    TEXT NOT NULL CHECK (decision IN ('public', 'access', 'service_auth', 'private', 'blocked', 'unknown')),
  confidence  INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 2),
  reason_id   TEXT,
  reason      TEXT,
  computed_at INTEGER NOT NULL,
  PRIMARY KEY (entry_id, path_prefix)
);

CREATE TABLE vulns (
  package_id    TEXT NOT NULL,
  vuln_id       TEXT NOT NULL,
  aliases       TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(aliases)),
  severity_rank INTEGER NOT NULL CHECK (severity_rank BETWEEN 0 AND 4),
  kev           INTEGER NOT NULL DEFAULT 0 CHECK (kev IN (0, 1)),
  fixed_in      TEXT,
  status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'ignored')),
  source        TEXT NOT NULL,
  first_seen    INTEGER NOT NULL,
  PRIMARY KEY (package_id, vuln_id)
);

CREATE TABLE insights (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL,
  severity   TEXT,
  subject_id TEXT,
  payload    TEXT NOT NULL CHECK (json_valid(payload)),
  first_seen INTEGER NOT NULL,
  deleted_at INTEGER
);

CREATE TABLE findings (
  fingerprint      TEXT PRIMARY KEY,
  rule_id          TEXT NOT NULL,
  rule_version     INTEGER NOT NULL,
  severity         TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  status           TEXT NOT NULL CHECK (status IN ('open', 'resolved', 'suppressed')),
  title            TEXT NOT NULL,
  evidence         TEXT NOT NULL CHECK (json_valid(evidence)),
  insight_id       TEXT,
  first_seen       INTEGER NOT NULL,
  last_seen        INTEGER NOT NULL,
  resolved_at      INTEGER,
  suppressed_until INTEGER,
  suppressed_by    TEXT,
  suppress_reason  TEXT
);
CREATE INDEX findings_rule ON findings (rule_id, status);

CREATE TABLE finding_nodes (
  fingerprint TEXT NOT NULL,
  node_id     TEXT NOT NULL,
  role        TEXT NOT NULL,
  PRIMARY KEY (fingerprint, node_id, role)
);

CREATE TABLE rule_runs (
  scan_id  TEXT NOT NULL,
  rule_id  TEXT NOT NULL,
  status   TEXT NOT NULL CHECK (status IN ('evaluated', 'not_evaluated', 'error')),
  hits     INTEGER NOT NULL DEFAULT 0,
  missing  TEXT,
  PRIMARY KEY (scan_id, rule_id)
);

CREATE TABLE events (
  audit_id TEXT PRIMARY KEY,
  at       INTEGER NOT NULL,
  action   TEXT NOT NULL,
  actor    TEXT,
  resource TEXT,
  node_id  TEXT,
  payload  TEXT NOT NULL CHECK (json_valid(payload))
);
CREATE INDEX events_at ON events (at);

${historyTrigger("nodes", "node", "json_object('name', $.name, 'props', json($.props))")}
${historyTrigger("edges", "edge", "json_object('key', $.key, 'props', json($.props))")}
`;

// `hits` counts decided rows only; `undecided` counts the rows a rule could not
// decide, and `error` says why a run is `error` (capped by evaluateRules).
const RULE_RUN_DETAILS = `
ALTER TABLE rule_runs ADD COLUMN undecided INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rule_runs ADD COLUMN error TEXT;
`;

export const MIGRATIONS: readonly Migration[] = [
  { version: 1, name: "init", sql: INIT },
  { version: 2, name: "rule_runs_undecided_error", sql: RULE_RUN_DETAILS },
];

export const SCHEMA_VERSION = MIGRATIONS[MIGRATIONS.length - 1]?.version ?? 0;
