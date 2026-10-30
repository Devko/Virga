import { WorkerEntrypoint } from "cloudflare:workers";
import {
  type AccountRow,
  deleteAccount,
  getAccount,
  type NewAccount,
  runningScan,
  upsertAccount,
} from "./index-db.ts";
import { assertAccountId, manualScanInstanceId } from "./scan/ids.ts";

export type TriggerResult =
  | { started: true; id: string }
  | { started: false; reason: "unknown_account" | "running" | "exists"; id: string | null };

/** `removed` says whether the account was in the index. */
export type RemoveResult = { removed: boolean };

/**
 * Account administration for the web Worker: register an account in the
 * index, start a scan by hand, and remove an account. Tokens are stored and
 * removed through the broker's TokenIntake, never here.
 */
export class Admin extends WorkerEntrypoint<Env> {
  /**
   * Adds the account or updates its name, cadence and profile. An account
   * that was removed may be scanned again from here on.
   */
  async addAccount(input: NewAccount): Promise<AccountRow> {
    const account = await upsertAccount(this.env.INDEX, input, Date.now());
    const graphs = this.env.ACCOUNT_GRAPH;
    await graphs.get(graphs.idFromName(account.id)).clearRemoved();
    return account;
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

  /**
   * Removes the account: its rows in the index (`accounts`, `scan_runs`),
   * then its whole graph. Without the index rows the dispatcher no longer
   * picks the account, and a scan instance that begins later, for example
   * one that was queued, stops at its begin step without writing. The
   * emptied graph refuses to begin a scan until addAccount (R4-03). A scan
   * that still runs is refused at its next write. Idempotent, so a retry
   * after a partial failure finishes the job. The token stays in the broker
   * until TokenIntake.remove deletes it.
   */
  async removeAccount(accountId: string): Promise<RemoveResult> {
    assertAccountId(accountId);
    const removed = await deleteAccount(this.env.INDEX, accountId);
    const graphs = this.env.ACCOUNT_GRAPH;
    await graphs.get(graphs.idFromName(accountId)).deleteAll();
    return { removed };
  }
}
