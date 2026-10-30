import { WorkerEntrypoint } from "cloudflare:workers";
import {
  type AccountRow,
  checkNewAccount,
  deleteAccount,
  getAccount,
  markRemoving,
  type NewAccount,
  runningScan,
  upsertAccount,
} from "./index-db.ts";
import { assertAccountId, manualScanInstanceId } from "./scan/ids.ts";

export type TriggerResult =
  | { started: true; id: string }
  | {
      started: false;
      reason: "unknown_account" | "removing" | "running" | "exists";
      id: string | null;
    };

/** `removed` says whether the account was in the index. */
export type RemoveResult = { removed: boolean };

// Module functions, not methods: every method of an entrypoint is callable over RPC.

const graphOf = (env: Env, accountId: string) =>
  env.ACCOUNT_GRAPH.get(env.ACCOUNT_GRAPH.idFromName(accountId));

/**
 * Removes the account in an order that never hides an account whose graph
 * is left (R5-08): mark the index row `removing`, delete the graph, then
 * delete the index rows. A step that fails leaves the account listed as
 * `removing`, and running the removal again finishes it.
 */
async function remove(env: Env, accountId: string): Promise<boolean> {
  const listed = await markRemoving(env.INDEX, accountId, Date.now());
  await graphOf(env, accountId).deleteAll();
  await deleteAccount(env.INDEX, accountId);
  return listed;
}

/**
 * Account administration for the web Worker: register an account in the
 * index, start a scan by hand, and remove an account. Tokens are stored and
 * removed through the broker's TokenIntake, never here.
 */
export class Admin extends WorkerEntrypoint<Env> {
  /**
   * Adds the account or updates its name, cadence and profile. An account
   * that was removed may be scanned again from here on. A removal that did
   * not finish is finished first, so the account starts from nothing.
   */
  async addAccount(input: NewAccount): Promise<AccountRow> {
    checkNewAccount(input);
    if ((await getAccount(this.env.INDEX, input.id))?.status === "removing") {
      await remove(this.env, input.id);
    }
    const account = await upsertAccount(this.env.INDEX, input, Date.now());
    await graphOf(this.env, account.id).clearRemoved();
    return account;
  }

  /** Starts a scan now unless the account is unknown or being removed, or a scan is running. */
  async triggerScan(accountId: string): Promise<TriggerResult> {
    assertAccountId(accountId);
    const now = Date.now();
    const account = await getAccount(this.env.INDEX, accountId);
    if (!account) return { started: false, reason: "unknown_account", id: null };
    if (account.status === "removing") return { started: false, reason: "removing", id: null };
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
   * Removes the account: marks its index row `removing`, deletes its whole
   * graph, then its rows in the index (`accounts`, `scan_runs`). Until the
   * last step the account stays listed as `removing`, so a removal that
   * fails part way never hides an account whose graph is left (R5-08).
   *
   * From the first step on, the dispatcher and triggerScan start no scan of
   * the account, and a scan instance that begins later, for example one that
   * was queued, stops at its begin step without writing. The emptied graph
   * also refuses to begin a scan until addAccount (R4-03). A scan that still
   * runs is refused at its next write after the graph is deleted, and gets
   * no index row back. Idempotent, so a retry after a partial failure
   * finishes the job. The token stays in the broker until TokenIntake.remove
   * deletes it.
   */
  async removeAccount(accountId: string): Promise<RemoveResult> {
    assertAccountId(accountId);
    return { removed: await remove(this.env, accountId) };
  }
}
