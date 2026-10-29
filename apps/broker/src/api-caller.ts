import { WorkerEntrypoint } from "cloudflare:workers";
import type { BrokerApi, CfGraphqlResponse, CfQuery, CfResponse } from "@virga/cf-api";
import type { BrokerEnv } from "./env.ts";
import { loadMasterKey } from "./master-key.ts";
import {
  BROKER_ERROR_CODE,
  brokerErrorMessage,
  checkGraphql,
  checkRest,
  failure,
  graphqlPost,
  graphqlRefused,
  NO_TOKEN_CODE,
  refused,
  restGet,
} from "./upstream.ts";
import { getToken } from "./vault.ts";

/**
 * Read calls for the scan Workflow and the collectors, through a service
 * binding. Looks up the account's token, then sends allowlisted reads only.
 */
export class ApiCaller extends WorkerEntrypoint<BrokerEnv> implements BrokerApi {
  async get(accountId: string, path: string, query?: CfQuery): Promise<CfResponse> {
    const refusal = checkRest(accountId, path, query);
    if (refusal) return refused(refusal);
    try {
      const token = await this.tokenOf(accountId);
      if (token === null) return failure(401, NO_TOKEN_CODE, "no token stored for this account");
      return await restGet({ env: this.env, accountId, token }, path, query);
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
      const token = await this.tokenOf(accountId);
      if (token === null) {
        return {
          status: 401,
          data: null,
          errors: [{ message: "no token stored for this account" }],
        };
      }
      return await graphqlPost({ env: this.env, accountId, token }, query, variables);
    } catch (error) {
      return { status: 500, data: null, errors: [{ message: brokerErrorMessage(error) }] };
    }
  }

  private async tokenOf(accountId: string): Promise<string | null> {
    const master = await loadMasterKey(this.env);
    return (await getToken(this.env.VAULT, master, accountId))?.token ?? null;
  }
}
