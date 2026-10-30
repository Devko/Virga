import { WorkerEntrypoint } from "cloudflare:workers";
import type { BrokerApi, CfGraphqlResponse, CfQuery, CfResponse } from "@virga/cf-api";
import type { BrokerEnv } from "./env.ts";
import { usableToken } from "./token-check.ts";
import {
  BROKER_ERROR_CODE,
  brokerErrorMessage,
  checkGraphql,
  checkRest,
  failure,
  graphqlPost,
  graphqlRefused,
  refused,
  restGet,
} from "./upstream.ts";

/**
 * Read calls for the scan Workflow and the collectors, through a service
 * binding. Looks up the account's token, checks it again first when its last
 * passed check is 24 hours old (TM-04, `usableToken`), then sends allowlisted
 * reads only.
 */
export class ApiCaller extends WorkerEntrypoint<BrokerEnv> implements BrokerApi {
  async get(accountId: string, path: string, query?: CfQuery): Promise<CfResponse> {
    const refusal = checkRest(accountId, path, query);
    if (refusal) return refused(refusal);
    try {
      const usable = await usableToken(this.env, accountId);
      if (!usable.ok) {
        return {
          ...failure(usable.status, usable.code, usable.message),
          ...(usable.retryAfter !== undefined ? { retryAfter: usable.retryAfter } : {}),
        };
      }
      return await restGet({ env: this.env, accountId, token: usable.token }, path, query);
    } catch (error) {
      return failure(500, BROKER_ERROR_CODE, brokerErrorMessage(error));
    }
  }

  async graphql(
    accountId: string,
    query: string,
    variables?: Record<string, unknown>,
  ): Promise<CfGraphqlResponse> {
    const refusal = checkGraphql(accountId, query, variables);
    if (refusal) return graphqlRefused(refusal);
    try {
      const usable = await usableToken(this.env, accountId);
      if (!usable.ok) {
        return { status: usable.status, data: null, errors: [{ message: usable.message }] };
      }
      return await graphqlPost({ env: this.env, accountId, token: usable.token }, query, variables);
    } catch (error) {
      return { status: 500, data: null, errors: [{ message: brokerErrorMessage(error) }] };
    }
  }
}
