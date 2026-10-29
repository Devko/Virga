// Sources:
// https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-workers-metrics/
// (query shape and the documented response: viewer.accounts[].workersInvocationsAdaptive[]
// with sum { requests errors } and dimensions { scriptName })
// https://developers.cloudflare.com/api/resources/workers/subresources/beta/subresources/workers/methods/list/

import type { CfQuery } from "@virga/cf-api";
import { envelope } from "@virga/cf-api/testing";
import type { GraphqlHandler } from "../helpers.ts";

export const trafficWorkers = [
  { id: "e8f70fdbc8b1fb0b8ddb1af166186758", name: "my-worker" },
  { id: "c81a2d22c29840ed9d61681a3270dbff", name: "api-worker" },
  // No traffic in the window.
  { id: "6c2d7e1f3a4b5c8d9e0f1a2b3c4d5e6f", name: "legacy-worker" },
];

export const workersListRoute = (q: CfQuery) =>
  envelope(trafficWorkers, {
    count: trafficWorkers.length,
    page: Number(q.page),
    per_page: Number(q.per_page),
    total_pages: 1,
  });

const row = (scriptName: string, requests: number, errors: number) => ({
  dimensions: { scriptName },
  sum: { errors, requests },
});

/** Rows as the API groups them; my-worker comes in two rows that must be summed. */
export const trafficRows = [
  row("my-worker", 1200, 3),
  row("api-worker", 50, 0),
  row("my-worker", 34, 1),
  // Deleted since: no worker_script node, so no signal.
  row("removed-worker", 9, 9),
];

export interface GraphqlCall {
  query: string;
  variables: Record<string, unknown> | undefined;
}

/** A GraphQL handler that records each call and answers with `rows`. */
export function trafficGraphql(rows: object[] = trafficRows) {
  const calls: GraphqlCall[] = [];
  const handler: GraphqlHandler = (query, variables) => {
    calls.push({ query, variables });
    return {
      status: 200,
      data: { viewer: { accounts: [{ workersInvocationsAdaptive: rows }] } },
      errors: null,
    };
  };
  return { handler, calls };
}
