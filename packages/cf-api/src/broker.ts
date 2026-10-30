import type { CfGraphqlResponse, CfQuery, CfResponse, CfTransport } from "./types.ts";

/**
 * RPC surface of the broker's `ApiCaller` entrypoint, as seen through a
 * service binding. The broker looks up the account's token, enforces the
 * read allowlist and the rate budget, and calls the Cloudflare API.
 *
 * Before it uses a token whose last passed write check is 24 hours old, the
 * broker runs the check again (TM-04). A token that fails is deleted and the
 * call answers 401, which the reader turns into `NoPermissionError`. A check
 * that gets no answer keeps the token and fails the call with 503, or 429
 * with `retryAfter`: a `CfApiError` or `RateLimitedError`, which core retries.
 */
export interface BrokerApi {
  get(accountId: string, path: string, query?: CfQuery): Promise<CfResponse>;
  graphql(
    accountId: string,
    query: string,
    variables?: Record<string, unknown>,
  ): Promise<CfGraphqlResponse>;
}

/** A transport for one account that goes through the broker. */
export function brokerTransport(broker: BrokerApi, accountId: string): CfTransport {
  return {
    get: (path, query) => broker.get(accountId, path, query),
    graphql: (query, variables) => broker.graphql(accountId, query, variables),
  };
}
