-- The tool audit trail (design spec, "Audit trail"): one row per request to
-- the web Worker's JSON API and per MCP tool call. It never holds a request
-- body, a token, a header value or a string from a scanned account. The
-- hourly dispatcher deletes rows older than 90 days. Times are Unix epoch
-- milliseconds.
CREATE TABLE tool_audit (
  -- Newest first is `ORDER BY id DESC`; ids are never reused.
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  -- The Access identity: a lowercase email, or a service token's client ID.
  identity TEXT NOT NULL CHECK (length(identity) BETWEEN 1 AND 320),
  identity_type TEXT NOT NULL CHECK (identity_type IN ('email', 'service_token')),
  -- `ui` for the SPA's own requests, `api` for other API clients, `mcp` for tool calls.
  channel TEXT NOT NULL CHECK (channel IN ('ui', 'api', 'mcp')),
  -- A route template such as `GET /api/accounts/{id}/findings`, or an MCP tool name.
  action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 100),
  account_id TEXT CHECK (
    account_id IS NULL OR (length(account_id) = 32 AND account_id NOT GLOB '*[^0-9a-f]*')
  ),
  -- The HTTP status for API requests; `ok`, `not_found`, `error` or `refused` for tool calls.
  outcome TEXT NOT NULL CHECK (length(outcome) BETWEEN 1 AND 32)
) STRICT;

CREATE INDEX tool_audit_at ON tool_audit (at);
