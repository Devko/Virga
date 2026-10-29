import { isAllowedRead } from "./allowlist/index.ts";
import { NOT_ALLOWED_CODE } from "./errors.ts";
import type { CfEnvelope, CfGraphqlResponse, CfQuery, CfResponse, CfTransport } from "./types.ts";

/**
 * A route returns an envelope (status 200), a full response (to simulate
 * 403, 429, ...), or a function of the query (to simulate pagination).
 */
export type FixtureRoute = CfEnvelope | CfResponse | ((query: CfQuery) => CfEnvelope | CfResponse);

export interface FixtureTransportOptions {
  /** Refuse paths that are not on the read allowlist, like the broker. Default true. */
  enforceAllowlist?: boolean;
  /** Handler for GraphQL queries. */
  graphql?: (query: string, variables?: Record<string, unknown>) => CfGraphqlResponse;
}

export interface FixtureTransport extends CfTransport {
  /** Every call in order, as `GET /path?query`. */
  readonly calls: string[];
}

const isResponse = (value: CfEnvelope | CfResponse): value is CfResponse =>
  "status" in value && "body" in value;

/** Builds an envelope around a result, for fixtures. */
export function envelope<T>(result: T, resultInfo?: CfEnvelope["result_info"]): CfEnvelope<T> {
  return {
    success: true,
    errors: [],
    messages: [],
    result,
    ...(resultInfo ? { result_info: resultInfo } : {}),
  };
}

/** Builds an error response, for fixtures. */
export function failure(status: number, code: number, message: string): CfResponse<null> {
  return { status, body: { success: false, errors: [{ code, message }], result: null } };
}

/** In-memory transport for tests. Unknown paths return 404. No network. */
export function fixtureTransport(
  routes: Record<string, FixtureRoute>,
  options: FixtureTransportOptions = {},
): FixtureTransport {
  const calls: string[] = [];
  const enforce = options.enforceAllowlist ?? true;
  return {
    calls,
    async get(path: string, query: CfQuery = {}): Promise<CfResponse> {
      const qs = Object.entries(query)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => `${k}=${String(v)}`)
        .join("&");
      calls.push(`GET ${path}${qs ? `?${qs}` : ""}`);
      if (enforce && !isAllowedRead("GET", path)) {
        return failure(400, NOT_ALLOWED_CODE, `not on the read allowlist: GET ${path}`);
      }
      const route = routes[path];
      if (route === undefined) return failure(404, 7003, `no fixture for ${path}`);
      const value = typeof route === "function" ? route(query) : route;
      return isResponse(value) ? value : { status: 200, body: value };
    },
    async graphql(query: string, variables?: Record<string, unknown>) {
      calls.push("POST /graphql");
      if (!options.graphql) return { status: 200, data: null, errors: [{ message: "no fixture" }] };
      return options.graphql(query, variables);
    },
  };
}
