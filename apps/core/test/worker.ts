import { WorkerEntrypoint } from "cloudflare:workers";
import type { BrokerApi, CfGraphqlResponse, CfQuery, CfResponse } from "@virga/cf-api";
import { fixtureTransport } from "@virga/cf-api/testing";
import type { Collector } from "@virga/collectors";
import { ScanWorkflow } from "../src/index.ts";
import { apiRoutes, initialState } from "./fixtures/api.ts";
import { dnsStub, storageStub } from "./stubs.ts";

/**
 * Test entry module: the Worker's own exports, plus a fixture broker and a
 * scan Workflow with stub collectors. Named re-exports, so the plugin sees
 * every class (it does not follow `export *`).
 */
export { AccountGraph, DispatchWorkflow, default, ScanWorkflow } from "../src/index.ts";

/**
 * Stands in for the broker's ApiCaller behind the BROKER service binding.
 * Every account looks like the fixture account: two zones, no R2 access.
 */
export class FixtureBroker extends WorkerEntrypoint<Env> implements BrokerApi {
  async get(accountId: string, path: string, query?: CfQuery): Promise<CfResponse> {
    return fixtureTransport(apiRoutes(accountId, initialState())).get(path, query);
  }

  async graphql(): Promise<CfGraphqlResponse> {
    return { status: 400, data: null, errors: [{ message: "no GraphQL fixture" }] };
  }
}

/** The production scan with stub collectors; the reader still goes through BROKER. */
export class TestScanWorkflow extends ScanWorkflow {
  protected override collectors(): readonly Collector[] {
    return [dnsStub, storageStub];
  }
}
