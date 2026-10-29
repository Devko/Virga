/**
 * One allowed read. `pattern` is a v4 path where `:name` matches exactly one
 * non-empty path segment, for example
 * `/accounts/:account_id/workers/scripts/:script_name/settings`.
 * Every rule must be a read. POST is allowed only for GraphQL queries.
 */
export interface ReadRule {
  method: "GET" | "POST";
  pattern: string;
  /** Collector or feature that needs it. */
  usedBy: string;
}
