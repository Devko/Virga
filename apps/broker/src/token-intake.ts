import { WorkerEntrypoint } from "cloudflare:workers";
import type { CfResponse } from "@virga/cf-api";
import type { BrokerEnv } from "./env.ts";
import { loadMasterKey } from "./master-key.ts";
import { ACCOUNT_ID, brokerErrorMessage, restGet } from "./upstream.ts";
import {
  deleteToken,
  getToken,
  markChecked,
  putToken,
  TOKEN_PROFILES,
  type TokenProfile,
} from "./vault.ts";
import {
  type CheckIssue,
  checkToken,
  type IssueCode,
  TOKEN_ID,
  type TokenDetails,
  type VerifiedToken,
  type WriteCheckResult,
} from "./write-check.ts";

export interface IntakeResult extends WriteCheckResult {
  /** The vault holds this account's token after the call. */
  stored: boolean;
  /** recheck: the stored token failed the check and was deleted. */
  removed: boolean;
  /** The check could not finish (rate limit, Cloudflare unavailable); nothing changed. */
  retryable: boolean;
}

type Checked = WriteCheckResult & { retryable: boolean };

const TOKEN_FORMAT = /^[A-Za-z0-9_-]{20,256}$/;
// Global API Keys, user tokens and Wrangler OAuth tokens (token formats reference).
const OTHER_CREDENTIALS = ["cfk_", "cfut_", "cfoat_"];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function rejected(
  accountId: unknown,
  code: IssueCode,
  message: string,
  extra: Partial<IntakeResult> = {},
): IntakeResult {
  return {
    ok: false,
    accountId: typeof accountId === "string" ? accountId.slice(0, 64) : "",
    tokenId: null,
    expiresOn: null,
    permissionGroups: [],
    reasons: [{ code, message }],
    warnings: [],
    stored: false,
    removed: false,
    retryable: false,
    ...extra,
  };
}

const retryableStatus = (status: number) => status === 429 || status >= 500;

function describe(response: CfResponse): string {
  const errors = response.body.errors
    .slice(0, 3)
    .map((e) => `${e.code} ${String(e.message).slice(0, 100)}`)
    .join("; ");
  return `HTTP ${response.status}${errors ? ` (${errors})` : ""}`;
}

const succeeded = (response: CfResponse) =>
  response.status === 200 && response.body.success === true;

/**
 * The onboarding write check. Both calls go through the same path as every
 * other read (allowlist, account check, rate budget).
 */
async function writeCheck(
  env: BrokerEnv,
  accountId: string,
  token: string,
  profile: TokenProfile,
): Promise<Checked> {
  const upstream = { env, accountId, token };
  const verify = await restGet(upstream, `/accounts/${accountId}/tokens/verify`);
  if (!succeeded(verify)) {
    return rejected(accountId, "verify_failed", `token verification failed: ${describe(verify)}`, {
      retryable: retryableStatus(verify.status),
    });
  }
  const verified: VerifiedToken = isRecord(verify.body.result) ? verify.body.result : {};
  const tokenId = typeof verified.id === "string" ? verified.id : null;
  let details: TokenDetails = {};
  if (tokenId !== null && TOKEN_ID.test(tokenId)) {
    const response = await restGet(upstream, `/accounts/${accountId}/tokens/${tokenId}`);
    if (!succeeded(response)) {
      const denied = response.status === 401 || response.status === 403;
      return rejected(
        accountId,
        "details_unavailable",
        denied
          ? "the token cannot read its own policies; add Account API Tokens Read"
          : `token details failed: ${describe(response)}`,
        { tokenId, retryable: !denied && retryableStatus(response.status) },
      );
    }
    details = isRecord(response.body.result) ? response.body.result : {};
  }
  return {
    ...checkToken({ accountId, profile, verify: verified, details, now: Date.now() }),
    retryable: false,
  };
}

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
      const check = await writeCheck(this.env, accountId, token, profile);
      if (!check.ok || check.tokenId === null) return { ...check, stored: false, removed: false };
      const master = await loadMasterKey(this.env);
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
   * Runs the write check again on the stored token. A token that fails is
   * deleted; one whose check could not finish is kept unchanged.
   */
  async recheck(accountId: string): Promise<IntakeResult> {
    if (typeof accountId !== "string" || !ACCOUNT_ID.test(accountId)) {
      return rejected(accountId, "invalid_input", "account ID must be 32 hex characters");
    }
    try {
      const master = await loadMasterKey(this.env);
      const found = await getToken(this.env.VAULT, master, accountId);
      if (!found) return rejected(accountId, "not_found", "no token stored for this account");
      const check = await writeCheck(this.env, accountId, found.token, found.entry.profile);
      if (check.ok && check.tokenId !== found.entry.tokenId) {
        const mismatch: CheckIssue = {
          code: "token_mismatch",
          message: "the stored token now verifies as another token ID",
        };
        check.ok = false;
        check.reasons.push(mismatch);
      }
      if (check.ok) {
        await markChecked(this.env.VAULT, accountId, check.expiresOn, Date.now());
        return { ...check, stored: true, removed: false };
      }
      if (check.retryable) return { ...check, stored: true, removed: false };
      const removed = await deleteToken(this.env.VAULT, accountId);
      return { ...check, stored: false, removed };
    } catch (error) {
      return rejected(accountId, "broker_error", brokerErrorMessage(error), {
        stored: true,
        retryable: true,
      });
    }
  }

  async remove(accountId: string): Promise<{ removed: boolean }> {
    if (typeof accountId !== "string" || !ACCOUNT_ID.test(accountId)) return { removed: false };
    return { removed: await deleteToken(this.env.VAULT, accountId) };
  }
}
