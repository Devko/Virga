import { WorkerEntrypoint } from "cloudflare:workers";
import type {
  AdminRpc,
  FindingFilters,
  GraphReaderRpc,
  IntakeResult,
  NewAccount,
  Profile,
  TokenIntakeRpc,
  Untrusted,
} from "../src/rpc.ts";
import {
  ACCOUNT,
  ACCOUNT_REMOVAL_FAILS,
  accounts,
  detail,
  findings,
  hugeNeighborhood,
  neighborhood,
  REMOVING_ACCOUNT,
  REMOVING_UNREADABLE,
  removingSummary,
  summary,
  TOKEN_REMOVAL_FAILS,
} from "./fixtures.ts";

/**
 * Test entry module: the Worker, plus stubs for core's GraphReader and Admin
 * and the broker's TokenIntake behind the service bindings
 * (vitest.config.ts). The stubs run in this isolate and record their calls.
 */
export { default } from "../src/index.ts";

export const calls: { method: string; args: unknown[] }[] = [];
const record = (method: string, args: unknown[]) => calls.push({ method, args });

const known = (accountId: string) => accountId === ACCOUNT;

export class StubGraphReader extends WorkerEntrypoint<Env> implements GraphReaderRpc {
  async listAccounts() {
    record("listAccounts", []);
    return accounts;
  }

  async getScanSummary(accountId: string) {
    record("getScanSummary", [accountId]);
    if (accountId === REMOVING_ACCOUNT) return removingSummary;
    if (accountId === REMOVING_UNREADABLE) throw new Error(`graph of ${accountId} is half deleted`);
    return known(accountId) ? summary : null;
  }

  async listFindings(accountId: string, filters?: FindingFilters) {
    record("listFindings", [accountId, filters]);
    if (!known(accountId)) return null;
    const limit = filters?.limit ?? 50;
    return {
      findings: findings.slice(0, limit),
      cursor: limit < findings.length ? "1:next" : null,
    };
  }

  async getFinding(accountId: string, fingerprint: string) {
    record("getFinding", [accountId, fingerprint]);
    return known(accountId) && fingerprint === detail.fingerprint ? detail : null;
  }

  async getNeighborhood(accountId: string, nodeId: string, options?: object) {
    record("getNeighborhood", [accountId, nodeId, options]);
    if (!known(accountId)) return null;
    if (nodeId === "boom") throw new Error(`graph failure near ${nodeId}`);
    return nodeId === "huge" ? hugeNeighborhood() : neighborhood;
  }
}

export class StubAdmin extends WorkerEntrypoint<Env> implements AdminRpc {
  async addAccount(input: NewAccount) {
    record("addAccount", [input]);
    if (input.name === "fail") throw new Error("index unavailable");
    return {
      id: input.id,
      name: input.name as Untrusted<string>,
      status: "active" as const,
      cadenceHours: input.cadenceHours ?? 24,
      profile: input.profile ?? "inventory",
      createdAt: 1,
      lastScanAt: null,
    };
  }

  async triggerScan(accountId: string) {
    record("triggerScan", [accountId]);
    if (accountId === REMOVING_ACCOUNT) {
      return { started: false as const, reason: "removing" as const, id: null };
    }
    if (!known(accountId))
      return { started: false as const, reason: "unknown_account" as const, id: null };
    return { started: true as const, id: `scan-${accountId}-202610290715-manual` };
  }

  async removeAccount(accountId: string) {
    record("removeAccount", [accountId]);
    if (accountId === ACCOUNT_REMOVAL_FAILS) throw new Error("index unavailable");
    return {
      removed:
        known(accountId) || accountId === REMOVING_ACCOUNT || accountId === REMOVING_UNREADABLE,
    };
  }
}

/** Tokens starting with `reject` fail the write check with a message that quotes the token. */
export class StubTokenIntake extends WorkerEntrypoint<Env> implements TokenIntakeRpc {
  async store(accountId: string, token: string, profile: Profile): Promise<IntakeResult> {
    record("store", [accountId, token, profile]);
    if (token.startsWith("throw")) throw new Error(`vault failure for ${token}`);
    const rejected = token.startsWith("reject");
    return {
      ok: !rejected,
      accountId,
      tokenId: "ed17574386854bf78a67040be0a770b0",
      expiresOn: "2026-12-01T00:00:00Z",
      permissionGroups: ["Workers Metadata Read-Only", `echo ${token}`],
      reasons: rejected ? [{ code: "not_read_only", message: `token ${token} can write` }] : [],
      warnings: [],
      stored: !rejected,
      removed: false,
      retryable: false,
    };
  }

  async remove(accountId: string) {
    record("remove", [accountId]);
    if (accountId === TOKEN_REMOVAL_FAILS) throw new Error(`vault unavailable for ${accountId}`);
    return { removed: known(accountId) || accountId === ACCOUNT_REMOVAL_FAILS };
  }
}
