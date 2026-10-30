import {
  type AccountRow,
  checkNewAccount,
  deleteAccount,
  getAccount,
  markRemoving,
  type NewAccount,
  upsertAccount,
} from "./index-db.ts";

/**
 * Adding and removing an account. Both run inside the account's graph object
 * (AccountGraph.addAccount, AccountGraph.removeAccount), one at a time per
 * account (TM-09): otherwise a removal that marked the account before a
 * re-add finished could delete the new index row, or delete the new graph
 * after the add cleared its `removed` marker.
 */

/** What an account change uses: the account index and the account's own graph. */
export interface AccountChanges {
  index: D1Database;
  /** Deletes the account's whole graph and sets its `removed` marker. */
  deleteGraph(): Promise<void>;
  /** Clears the `removed` marker, so scans of the account can begin again. */
  clearRemoved(): Promise<void> | void;
}

/**
 * Removes the account in an order that never hides an account whose graph
 * is left (R5-08): mark the index row `removing`, delete the graph, then
 * delete the index rows. A step that fails leaves the account listed as
 * `removing`, and running the removal again finishes it. Returns whether
 * the account was in the index.
 */
export async function removeAccount(changes: AccountChanges, accountId: string): Promise<boolean> {
  const listed = await markRemoving(changes.index, accountId, Date.now());
  await changes.deleteGraph();
  await deleteAccount(changes.index, accountId);
  return listed;
}

/**
 * Adds the account or updates its name, cadence and profile, then lets
 * scans of it begin. A removal that did not finish is finished first, so
 * the account starts from nothing.
 */
export async function addAccount(changes: AccountChanges, input: NewAccount): Promise<AccountRow> {
  const checked = checkNewAccount(input);
  if ((await getAccount(changes.index, checked.id))?.status === "removing") {
    await removeAccount(changes, checked.id);
  }
  const account = await upsertAccount(changes.index, checked, Date.now());
  await changes.clearRemoved();
  return account;
}

/**
 * Runs tasks one at a time, in the order they arrive. A task that fails does
 * not stop the next one. The queue lives in memory: it serializes the calls
 * one Durable Object instance receives, which is every call for its ID.
 */
export class Serial {
  private last: Promise<unknown> = Promise.resolve();

  run<T>(task: () => Promise<T>): Promise<T> {
    const result = this.last.then(task);
    this.last = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}
