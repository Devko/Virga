import { WorkerEntrypoint } from "cloudflare:workers";
import type { BrokerEnv } from "./env.ts";
import { loadMasterKey } from "./master-key.ts";
import { type IntakeResult, recheckToken, rejected, writeCheck } from "./token-check.ts";
import { ACCOUNT_ID, brokerErrorMessage } from "./upstream.ts";
import { deleteToken, getToken, putToken, TOKEN_PROFILES, type TokenProfile } from "./vault.ts";

export type { IntakeResult } from "./token-check.ts";

const TOKEN_FORMAT = /^[A-Za-z0-9_-]{20,256}$/;
// Global API Keys, user tokens and Wrangler OAuth tokens (token formats reference).
const OTHER_CREDENTIALS = ["cfk_", "cfut_", "cfoat_"];

/**
 * Onboarding for the web Worker, through a service binding. It can store,
 * recheck and remove a token, but never use one for anything else or return it.
 */
export class TokenIntake extends WorkerEntrypoint<BrokerEnv> {
  async store(accountId: string, token: string, profile: TokenProfile): Promise<IntakeResult> {
    if (typeof accountId !== "string" || !ACCOUNT_ID.test(accountId)) {
      return rejected(accountId, "invalid_input", "account ID must be 32 hex characters");
    }
    if (!TOKEN_PROFILES.includes(profile)) {
      return rejected(accountId, "invalid_input", "profile must be inventory or workload");
    }
    if (typeof token !== "string" || !TOKEN_FORMAT.test(token)) {
      return rejected(accountId, "invalid_input", "token has an unexpected format");
    }
    if (OTHER_CREDENTIALS.some((prefix) => token.startsWith(prefix))) {
      return rejected(accountId, "not_account_token", "an account API token (cfat_) is required");
    }
    try {
      // Fails before the token goes anywhere if the vault cannot store it.
      const master = await loadMasterKey(this.env);
      const check = await writeCheck(this.env, accountId, token, profile);
      if (!check.ok || check.tokenId === null) return { ...check, stored: false, removed: false };
      await putToken(this.env.VAULT, master, {
        accountId,
        tokenId: check.tokenId,
        profile,
        token,
        expiresOn: check.expiresOn,
        now: Date.now(),
      });
      return { ...check, stored: true, removed: false };
    } catch (error) {
      return rejected(accountId, "broker_error", brokerErrorMessage(error), { retryable: true });
    }
  }

  /**
   * Runs the write check again on the stored token, as ApiCaller does before
   * it uses a token whose check is 24 hours old (TM-04). A token that fails
   * is deleted; one whose check got no answer is kept unchanged.
   */
  async recheck(accountId: string): Promise<IntakeResult> {
    if (typeof accountId !== "string" || !ACCOUNT_ID.test(accountId)) {
      return rejected(accountId, "invalid_input", "account ID must be 32 hex characters");
    }
    try {
      const master = await loadMasterKey(this.env);
      const found = await getToken(this.env.VAULT, master, accountId);
      if (!found) return rejected(accountId, "not_found", "no token stored for this account");
      return await recheckToken(this.env, found);
    } catch (error) {
      return rejected(accountId, "broker_error", brokerErrorMessage(error), {
        stored: true,
        retryable: true,
      });
    }
  }

  /**
   * Offboarding: deletes the stored token, then clears the account's rate
   * budget. `removed` says whether a token was stored. Idempotent, so a retry
   * after a failure finishes the job; a failure throws.
   */
  async remove(accountId: string): Promise<{ removed: boolean }> {
    if (typeof accountId !== "string" || !ACCOUNT_ID.test(accountId)) return { removed: false };
    const removed = await deleteToken(this.env.VAULT, accountId);
    const budgets = this.env.RATE_BUDGET;
    await budgets.get(budgets.idFromName(accountId)).clear();
    return { removed };
  }
}
