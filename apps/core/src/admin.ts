import { WorkerEntrypoint } from "cloudflare:workers";
import {
  type AccountRow,
  getAccount,
  type NewAccount,
  runningScan,
  upsertAccount,
} from "./index-db.ts";
import { assertAccountId, manualScanInstanceId } from "./scan/ids.ts";

export type TriggerResult =
  | { started: true; id: string }
  | { started: false; reason: "unknown_account" | "running" | "exists"; id: string | null };

/**
 * Account administration for the web Worker. Minimal for now: register an
 * account in the index and start a scan by hand. Tokens are stored through
 * the broker's TokenIntake, never here.
 */
export class Admin extends WorkerEntrypoint<Env> {
  /** Adds the account or updates its name, cadence and profile. */
  async addAccount(input: NewAccount): Promise<AccountRow> {
    return upsertAccount(this.env.INDEX, input, Date.now());
  }

  /** Starts a scan now unless one is running. */
  async triggerScan(accountId: string): Promise<TriggerResult> {
    assertAccountId(accountId);
    const now = Date.now();
    if (!(await getAccount(this.env.INDEX, accountId))) {
      return { started: false, reason: "unknown_account", id: null };
    }
    const running = await runningScan(this.env.INDEX, accountId, now);
    if (running) return { started: false, reason: "running", id: running };

    const id = manualScanInstanceId(accountId, now);
    // createBatch reports a taken ID instead of throwing like create.
    const { created } = await this.env.SCAN_WORKFLOW.createBatch({
      instances: [{ id, params: { accountId } }],
    });
    return created.length > 0 ? { started: true, id } : { started: false, reason: "exists", id };
  }
}
