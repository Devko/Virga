import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { type BrokerApi, brokerTransport, type CfReader, createReader } from "@virga/cf-api";
import { COLLECTORS, type Collector } from "@virga/collectors";
import { d1ScanIndex, dueAccounts } from "../index-db.ts";
import { type DispatchSummary, runDispatch, type ScanParamsPayload } from "./dispatch.ts";
import { assertAccountId } from "./ids.ts";
import { runScan } from "./run.ts";
import { workflowStep } from "./step.ts";
import type { ScanSummary } from "./types.ts";

/**
 * A full scan of one account (params `{ accountId }`). The logic is in
 * runScan; this class only wires the bindings.
 */
export class ScanWorkflow extends WorkflowEntrypoint<Env, ScanParamsPayload> {
  /** The collectors to run. Tests override it. */
  protected collectors(): readonly Collector[] {
    return COLLECTORS;
  }

  /** API access for one account: through the broker, which holds the token. */
  protected reader(accountId: string): CfReader {
    return createReader(brokerTransport(this.env.BROKER as unknown as BrokerApi, accountId));
  }

  override async run(
    event: Readonly<WorkflowEvent<ScanParamsPayload>>,
    step: WorkflowStep,
  ): Promise<ScanSummary> {
    const accountId = event.payload?.accountId;
    assertAccountId(accountId);
    const graphs = this.env.ACCOUNT_GRAPH;
    return runScan(
      {
        step: workflowStep(step),
        graph: () => graphs.get(graphs.idFromName(accountId)),
        index: d1ScanIndex(this.env.INDEX),
        reader: (id) => this.reader(id),
        collectors: this.collectors(),
      },
      { accountId, scanId: event.instanceId, now: event.timestamp.getTime() },
    );
  }
}

/**
 * Runs on the `schedules` of its binding (hourly, UTC) and starts the scans
 * of all accounts that are due.
 */
export class DispatchWorkflow extends WorkflowEntrypoint<Env> {
  override async run(
    event: Readonly<WorkflowEvent<unknown>>,
    step: WorkflowStep,
  ): Promise<DispatchSummary> {
    const at = event.schedule?.scheduledTime ?? event.timestamp.getTime();
    return runDispatch(
      {
        step: workflowStep(step),
        dueAccounts: (time, options) => dueAccounts(this.env.INDEX, time, options),
        scans: this.env.SCAN_WORKFLOW,
      },
      at,
    );
  }
}
