-- Account graph schema, draft v0 (one SQLite database per scanned account)
-- Times are Unix epoch milliseconds. props are JSON objects. confidence: 0 low, 1 medium, 2 high.

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE scans (
  id          TEXT PRIMARY KEY,              -- Workflow instance ID
  kind        TEXT NOT NULL CHECK (kind IN ('full', 'partial', 'event')),
  started_at  INTEGER NOT NULL,
  finished_at INTEGER,
  status      TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed'))
);

-- Coverage per resource class and scan. Decides tombstones and "not evaluated".
CREATE TABLE coverage (
  scan_id        TEXT NOT NULL REFERENCES scans(id),
  resource_class TEXT NOT NULL,              -- e.g. 'workers', 'dns', 'access'
  status         TEXT NOT NULL CHECK (status IN ('complete', 'partial', 'no_permission', 'error', 'skipped')),
  chunks_total   INTEGER NOT NULL DEFAULT 0,
  chunks_done    INTEGER NOT NULL DEFAULT 0,
  detail         TEXT,
  PRIMARY KEY (scan_id, resource_class)
);

CREATE TABLE nodes (
  id          TEXT PRIMARY KEY,              -- '<type>:<native_id>'
  type        TEXT NOT NULL,
  native_id   TEXT NOT NULL,
  name        TEXT,                          -- display name, e.g. route pattern or hostname
  props       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(props)),
  hash        TEXT NOT NULL,                 -- hash of canonical (name, props)
  first_seen  INTEGER NOT NULL,
  changed_at  INTEGER NOT NULL,              -- last hash change
  seen_scan   TEXT,                          -- last scan that observed the row
  deleted_at  INTEGER                        -- tombstone
);
CREATE INDEX nodes_type ON nodes (type) WHERE deleted_at IS NULL;

CREATE TABLE edges (
  id          TEXT PRIMARY KEY,              -- hash of (src, type, dst, key)
  src         TEXT NOT NULL,
  dst         TEXT NOT NULL,
  type        TEXT NOT NULL,
  key         TEXT NOT NULL DEFAULT '',      -- binding name, policy decision, ...
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

-- Volatile signals (traffic, token last use, last login). Updated in place, outside hash and history,
-- so that changing counters do not rewrite nodes or flood the changes table.
CREATE TABLE signals (
  node_id     TEXT NOT NULL,
  name        TEXT NOT NULL,                 -- 'invocations_30d', 'last_used_at', ...
  value,                                     -- number or text
  observed_at INTEGER NOT NULL,
  PRIMARY KEY (node_id, name)
);

-- Attribute history: one row per changed node or edge, enables diff between any two scans.
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

-- Dirty marks from audit events; drained by targeted refetch.
CREATE TABLE dirty (
  node_id   TEXT PRIMARY KEY,
  marked_at INTEGER NOT NULL,
  audit_id  TEXT
);

-- Output of the TypeScript exposure evaluator.
CREATE TABLE exposure (
  entry_id    TEXT NOT NULL,
  path_prefix TEXT NOT NULL DEFAULT '/',
  decision    TEXT NOT NULL CHECK (decision IN ('public', 'access', 'service_auth', 'private', 'blocked', 'unknown')),
  confidence  INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 2),
  reason_id   TEXT,                          -- deciding node, e.g. Access app or ruleset
  reason      TEXT,
  computed_at INTEGER NOT NULL,
  PRIMARY KEY (entry_id, path_prefix)
);

-- Advisory matches per package (from osv-scanner, Trivy, rematch job).
CREATE TABLE vulns (
  package_id    TEXT NOT NULL,
  vuln_id       TEXT NOT NULL,               -- GHSA-/CVE-/OSV ID
  aliases       TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(aliases)),
  severity_rank INTEGER NOT NULL CHECK (severity_rank BETWEEN 0 AND 4),  -- 0 none .. 4 critical
  kev           INTEGER NOT NULL DEFAULT 0 CHECK (kev IN (0, 1)),
  fixed_in      TEXT,
  status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'ignored')),
  source        TEXT NOT NULL,
  first_seen    INTEGER NOT NULL,
  PRIMARY KEY (package_id, vuln_id)
);

-- Native Security Insights, kept as inputs that findings can reference.
CREATE TABLE insights (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL,
  severity   TEXT,
  subject_id TEXT,                           -- node the insight is about, if resolvable
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
  insight_id       TEXT,                     -- enriched Security Insight
  first_seen       INTEGER NOT NULL,
  last_seen        INTEGER NOT NULL,
  resolved_at      INTEGER,
  suppressed_until INTEGER,
  suppressed_by    TEXT,
  suppress_reason  TEXT
);
CREATE INDEX findings_rule ON findings (rule_id, status);

-- Replaces the AFFECTS edge: which nodes a finding is about.
CREATE TABLE finding_nodes (
  fingerprint TEXT NOT NULL REFERENCES findings(fingerprint),
  node_id     TEXT NOT NULL,
  role        TEXT NOT NULL,                 -- 'subject', 'entry_point', 'data_store', ...
  PRIMARY KEY (fingerprint, node_id, role)
);

-- Rule evaluation status per scan; 'not_evaluated' when a required collector lacks coverage.
CREATE TABLE rule_runs (
  scan_id  TEXT NOT NULL,
  rule_id  TEXT NOT NULL,
  status   TEXT NOT NULL CHECK (status IN ('evaluated', 'not_evaluated', 'error')),
  hits     INTEGER NOT NULL DEFAULT 0,
  missing  TEXT,                             -- resource classes without coverage
  PRIMARY KEY (scan_id, rule_id)
);

-- Audit Logs v2 events relevant for detection rules, idempotent by audit log ID.
CREATE TABLE events (
  audit_id    TEXT PRIMARY KEY,
  at          INTEGER NOT NULL,
  action      TEXT NOT NULL,
  actor       TEXT,                          -- pseudonymized where personal
  resource    TEXT,
  node_id     TEXT,
  payload     TEXT NOT NULL CHECK (json_valid(payload))
);
CREATE INDEX events_at ON events (at);
