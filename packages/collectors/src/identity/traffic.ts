import { CfApiError, NoPermissionError } from "@virga/cf-api";
import { nodeId, type SignalRow } from "@virga/graph";
import { isObject, num, str } from "../platform/util.ts";
import type { Collector } from "../types.ts";
import { listWorkers, sortedSignals } from "./util.ts";

export const TRAFFIC_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
/** Rows per query; one row per script, since the only dimension is the script name. */
export const TRAFFIC_LIMIT = 10_000;

/**
 * Workers invocations summed per script over the window. Variable types and
 * fields as in developers.cloudflare.com/analytics/graphql-api/tutorials/querying-workers-metrics/
 */
export const TRAFFIC_QUERY = `query WorkersTraffic($accountTag: string, $start: string, $end: string) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      workersInvocationsAdaptive(limit: ${TRAFFIC_LIMIT}, filter: { datetime_geq: $start, datetime_leq: $end }) {
        sum { requests errors }
        dimensions { scriptName }
      }
    }
  }
}`;

interface TrafficData {
  viewer?: { accounts?: { workersInvocationsAdaptive?: unknown }[] };
}

/**
 * Signals `invocations_30d` and `errors_30d` on every Worker script, from one
 * GraphQL query over the 30 days before the scan started. Scripts without
 * traffic get 0, so a value from an earlier scan never lingers.
 */
export const trafficCollector: Collector<never> = {
  resourceClass: "traffic",
  after: ["workers"],
  permissions: ["Account Analytics Read", "Workers Metadata Read-Only"],

  async plan() {
    return [[]];
  },

  async collect(ctx) {
    const scripts = [...new Set((await listWorkers(ctx)).map((w) => w.name))];
    const data = await ctx.api.graphql<TrafficData>(TRAFFIC_QUERY, {
      accountTag: ctx.accountId,
      start: new Date(ctx.now - TRAFFIC_WINDOW_MS).toISOString(),
      end: new Date(ctx.now).toISOString(),
    });
    const accounts = data?.viewer?.accounts;
    if (!Array.isArray(accounts) || accounts.length === 0) {
      // An account the analytics API does not show is not an account without traffic.
      throw new NoPermissionError(403, "/graphql", [
        { code: 0, message: "account not visible to the analytics API" },
      ]);
    }
    const rows = accounts[0]?.workersInvocationsAdaptive;
    const groups = (Array.isArray(rows) ? rows : []).filter(isObject);
    if (groups.length >= TRAFFIC_LIMIT) {
      throw new CfApiError(0, "/graphql", [], `more than ${TRAFFIC_LIMIT} scripts with traffic`);
    }
    const totals = new Map<string, { requests: number; errors: number }>();
    for (const group of groups) {
      const script = isObject(group.dimensions) ? str(group.dimensions.scriptName) : null;
      if (!script) continue;
      const sum = isObject(group.sum) ? group.sum : {};
      const total = totals.get(script) ?? { requests: 0, errors: 0 };
      total.requests += num(sum.requests) ?? 0;
      total.errors += num(sum.errors) ?? 0;
      totals.set(script, total);
    }
    const signals: SignalRow[] = scripts.flatMap((script) => {
      const id = nodeId("worker_script", script);
      const total = totals.get(script);
      return [
        { nodeId: id, name: "invocations_30d", value: total?.requests ?? 0 },
        { nodeId: id, name: "errors_30d", value: total?.errors ?? 0 },
      ];
    });
    return { nodes: [], edges: [], signals: sortedSignals(signals) };
  },
};
