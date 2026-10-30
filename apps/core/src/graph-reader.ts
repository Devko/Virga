import { WorkerEntrypoint } from "cloudflare:workers";
import type {
  FindingDetail,
  FindingFilters,
  FindingPage,
  GraphSummary,
  Neighborhood,
} from "./graph/views.ts";
import {
  type AccountRow,
  getAccount,
  latestRun,
  listAccounts,
  type ScanRunRow,
} from "./index-db.ts";
import { assertAccountId } from "./scan/ids.ts";

export interface ScanSummaryView {
  account: AccountRow;
  /** The latest row in scan_runs, running or finished. */
  lastRun: ScanRunRow | null;
  graph: GraphSummary;
}

const MAX_ID = 2048;

function text(value: unknown, what: string): string {
  if (typeof value !== "string" || value === "" || value.length > MAX_ID) {
    throw new TypeError(`invalid ${what}`);
  }
  return value;
}

// Module functions, not methods: every method of an entrypoint is callable
// over RPC whatever its TypeScript visibility, and a graph stub has write methods.

async function knownAccount(env: Env, accountId: string): Promise<AccountRow | null> {
  assertAccountId(accountId);
  return getAccount(env.INDEX, accountId);
}

const graphOf = (env: Env, account: AccountRow) =>
  env.ACCOUNT_GRAPH.get(env.ACCOUNT_GRAPH.idFromName(account.id));

/**
 * Read-only RPC for the web Worker. Every method but `listAccounts` takes the
 * account ID and returns null for an account that is not in the index, so a
 * caller cannot create graph objects for arbitrary IDs. Values typed
 * `Untrusted` come from the scanned account or from onboarding input.
 */
export class GraphReader extends WorkerEntrypoint<Env> {
  /** Every account in the index, by name, then ID; at most 1,000. Reads only the index. */
  async listAccounts(): Promise<AccountRow[]> {
    return listAccounts(this.env.INDEX);
  }

  async getScanSummary(accountId: string): Promise<ScanSummaryView | null> {
    const account = await knownAccount(this.env, accountId);
    if (!account) return null;
    const [lastRun, graph] = await Promise.all([
      latestRun(this.env.INDEX, account.id),
      graphOf(this.env, account).scanSummary(),
    ]);
    return { account, lastRun, graph };
  }

  async listFindings(accountId: string, filters?: FindingFilters): Promise<FindingPage | null> {
    const account = await knownAccount(this.env, accountId);
    return account ? await graphOf(this.env, account).listFindings(filters) : null;
  }

  async getFinding(accountId: string, fingerprint: string): Promise<FindingDetail | null> {
    const key = text(fingerprint, "fingerprint");
    const account = await knownAccount(this.env, accountId);
    return account ? await graphOf(this.env, account).getFinding(key) : null;
  }

  /** Nodes and edges around a node, `depth` 1 or 2 hops, at most `limit` nodes. */
  async getNeighborhood(
    accountId: string,
    nodeId: string,
    options?: { depth?: number; limit?: number },
  ): Promise<Neighborhood | null> {
    const id = text(nodeId, "node ID");
    const account = await knownAccount(this.env, accountId);
    return account ? await graphOf(this.env, account).getNeighborhood(id, options) : null;
  }
}
