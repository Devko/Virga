-- The account index: which accounts exist, when they are due, and one row per
-- scan. Graph data stays in each account's Durable Object; this database only
-- schedules and summarizes. Times are Unix epoch milliseconds.
CREATE TABLE accounts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused')),
  -- Daily by default (D-09); hourly is opt-in for small accounts.
  cadence_hours INTEGER NOT NULL DEFAULT 24 CHECK (cadence_hours BETWEEN 1 AND 720),
  profile TEXT NOT NULL DEFAULT 'inventory' CHECK (profile IN ('inventory', 'workload')),
  created_at INTEGER NOT NULL,
  -- Start time of the last finished scan, whatever its outcome.
  last_scan_at INTEGER
) STRICT;

-- One row per scan Workflow instance; id is the instance ID.
CREATE TABLE scan_runs (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'partial', 'failed')),
  summary TEXT CHECK (summary IS NULL OR json_valid(summary))
) STRICT;

CREATE INDEX scan_runs_account ON scan_runs (account_id, started_at);
CREATE INDEX scan_runs_running ON scan_runs (account_id) WHERE status = 'running';
