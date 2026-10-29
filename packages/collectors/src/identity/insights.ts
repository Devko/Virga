import { CfApiError } from "@virga/cf-api";
import type { InsightRow } from "@virga/graph";
import { isObject, num, str } from "../platform/util.ts";
import type { Collector } from "../types.ts";
import { type Bounds, bounded } from "./util.ts";

/**
 * developers.cloudflare.com/api/resources/security_center/subresources/insights/methods/list
 * The result is an object with the issues of one page, not an array.
 */
interface CfInsightPage {
  count?: number;
  issues?: unknown;
}

const INSIGHTS_PER_PAGE = 1000;
const MAX_PAGES = 100;
// Keeps the original fields while bounding what an untrusted payload can add to the table.
const PAYLOAD_BOUNDS: Bounds = { text: 2048, items: 100, depth: 6 };

/** Top-level fields of an issue, as listed in the API reference. */
const FIELDS = [
  "id",
  "dismissed",
  "has_extended_context",
  "issue_class",
  "issue_type",
  "payload",
  "resolve_link",
  "resolve_text",
  "severity",
  "since",
  "source",
  "status",
  "subject",
  "timestamp",
  "user_classification",
];

function insightRow(issue: Record<string, unknown>): InsightRow | null {
  const id = str(issue.id);
  if (!id) return null;
  const payload: Record<string, unknown> = {};
  for (const field of FIELDS) {
    if (field in issue) payload[field] = bounded(issue[field], PAYLOAD_BOUNDS);
  }
  return {
    id,
    type: str(issue.issue_type) ?? "unknown",
    severity: str(issue.severity),
    // The API documents no subject format to map to a node; rules can match payload.subject.
    subjectId: null,
    payload,
  };
}

/**
 * Security Center insights for the account, as the complete current set:
 * the scan replaces the insights table with it, so it runs as one chunk.
 */
export const insightsCollector: Collector<never> = {
  resourceClass: "insights",
  permissions: ["Account Security Center Insights"],

  async plan() {
    return [[]];
  },

  async collect(ctx) {
    const path = `/accounts/${ctx.accountId}/security-center/insights`;
    const rows = new Map<string, InsightRow>();
    for (let page = 1; page <= MAX_PAGES; page++) {
      const result = await ctx.api.get<CfInsightPage | null>(path, {
        page,
        per_page: INSIGHTS_PER_PAGE,
      });
      const issues = Array.isArray(result?.issues) ? result.issues : [];
      for (const issue of issues.filter(isObject)) {
        const row = insightRow(issue);
        if (row) rows.set(row.id, row);
      }
      const count = num(result?.count);
      const seen = (page - 1) * INSIGHTS_PER_PAGE + issues.length;
      if (issues.length < INSIGHTS_PER_PAGE || (count !== null && seen >= count)) {
        const insights = [...rows.values()].sort((a, b) =>
          a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
        );
        return { nodes: [], edges: [], insights };
      }
    }
    throw new CfApiError(0, path, [], `more than ${MAX_PAGES} pages on ${path}`);
  },
};
