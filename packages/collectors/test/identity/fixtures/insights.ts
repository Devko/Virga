// Source: https://developers.cloudflare.com/api/resources/security_center/subresources/insights/methods/list/
// The first issue is the documented 200 example; the others vary it within the schema.
// Insight names: https://developers.cloudflare.com/security/security-insights/
// `result` is an object { count, issues, page, per_page } with up to 1,000 issues per page.

import type { CfQuery } from "@virga/cf-api";
import { envelope } from "@virga/cf-api/testing";

export const exampleIssue = {
  id: "id",
  dismissed: false,
  has_extended_context: false,
  issue_class: "always_use_https_not_enabled",
  issue_type: "compliance_violation",
  payload: {
    detection_method:
      "We detected security rules referencing multiple IP addresses directly in the rules.",
    zone_tag: "zone_tag",
  },
  resolve_link: "resolve_link",
  resolve_text: "resolve_text",
  severity: "Low",
  since: "2019-12-27T18:11:19.117Z",
  source: "cloudflare",
  status: "active",
  subject: "example.com",
  timestamp: "2019-12-27T18:11:19.117Z",
  user_classification: "false_positive",
};

/** "Unprotected Cloudflare Tunnels"; the reference names no issue_class values, so this one is illustrative. */
export const tunnelIssue = {
  id: "b2f0c6a4-unprotected-tunnel",
  dismissed: false,
  has_extended_context: false,
  issue_class: "unprotected_tunnel",
  issue_type: "exposed_infrastructure",
  payload: { detection_method: "We detected a tunnel hostname without Access." },
  severity: "Critical",
  since: "2026-10-01T00:00:00Z",
  source: "cloudflare",
  status: "active",
  subject: "tunnel.example.com",
  timestamp: "2026-10-28T00:00:00Z",
  unknown_field: "dropped",
};

/** Issues for two pages of 1,000. */
export const manyIssues = Array.from({ length: 1001 }, (_, i) => ({
  ...exampleIssue,
  id: `issue-${String(i).padStart(4, "0")}`,
}));

/** GET /security-center/insights in pages of `per_page`. */
export function insightsRoute(issues: object[]) {
  return (q: CfQuery) => {
    const page = Number(q.page);
    const perPage = Number(q.per_page);
    return envelope({
      count: issues.length,
      issues: issues.slice((page - 1) * perPage, page * perPage),
      page,
      per_page: perPage,
    });
  };
}
