import type { CfResponse } from "@virga/cf-api";
import type { BrokerEnv } from "./env.ts";
import { loadMasterKey } from "./master-key.ts";
import {
  BROKER_ERROR_CODE,
  NO_TOKEN_CODE,
  RECHECK_FAILED_CODE,
  RECHECK_UNAVAILABLE_CODE,
  restGet,
} from "./upstream.ts";
import {
  claimRecheck,
  deleteToken,
  getToken,
  markChecked,
  releaseRecheck,
  type TokenProfile,
  type VaultEntry,
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

/**
 * The write check against the Cloudflare API: at onboarding
 * (`TokenIntake.store`), on request (`TokenIntake.recheck`), and before use
 * (`ApiCaller`, TM-04). Nothing here returns or logs the token.
 */

export interface IntakeResult extends WriteCheckResult {
  /** The vault holds this account's token after the call. */
  stored: boolean;
  /** recheck: the stored token failed the check and was deleted. */
  removed: boolean;
  /** The check got no answer (rate limit, Cloudflare unavailable or unreachable); nothing changed. */
  retryable: boolean;
  /** Seconds to wait before a retry, set when the check was rate-limited. */
  retryAfter?: number;
}

type Checked = WriteCheckResult & { retryable: boolean; retryAfter?: number };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export function rejected(
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

/**
 * Cloudflare gave no answer about the token: a rate limit, a 5xx, no
 * connection, or a body that is not a v4 envelope. A retry may succeed.
 */
function unanswered(response: CfResponse): Pick<Checked, "retryable" | "retryAfter"> {
  const retryable =
    response.status === 429 ||
    response.status >= 500 ||
    response.body.errors.some((e) => e.code === BROKER_ERROR_CODE);
  return {
    retryable,
    ...(retryable && response.retryAfter !== undefined ? { retryAfter: response.retryAfter } : {}),
  };
}

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
 * The write check. Both calls go through the same path as every other read
 * (allowlist, account check, rate budget).
 */
export async function writeCheck(
  env: BrokerEnv,
  accountId: string,
  token: string,
  profile: TokenProfile,
): Promise<Checked> {
  const upstream = { env, accountId, token };
  const verify = await restGet(upstream, `/accounts/${accountId}/tokens/verify`);
  if (!succeeded(verify)) {
    return rejected(
      accountId,
      "verify_failed",
      `token verification failed: ${describe(verify)}`,
      unanswered(verify),
    );
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
        { tokenId, ...(denied ? {} : unanswered(response)) },
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
 * Runs the write check again on a stored token. A token that fails is
 * deleted; one whose check got no answer is kept unchanged.
 */
export async function recheckToken(
  env: BrokerEnv,
  stored: { entry: VaultEntry; token: string },
): Promise<IntakeResult> {
  const { entry, token } = stored;
  const check = await writeCheck(env, entry.accountId, token, entry.profile);
  if (check.ok && check.tokenId !== entry.tokenId) {
    const mismatch: CheckIssue = {
      code: "token_mismatch",
      message: "the stored token now verifies as another token ID",
    };
    check.ok = false;
    check.reasons.push(mismatch);
  }
  if (check.ok) {
    await markChecked(env.VAULT, entry.accountId, entry.tokenId, check.expiresOn, Date.now());
    return { ...check, stored: true, removed: false };
  }
  if (check.retryable) return { ...check, stored: true, removed: false };
  const removed = await deleteToken(env.VAULT, entry.accountId, entry.tokenId);
  return { ...check, stored: false, removed };
}

/**
 * A token is checked again before use once its last passed check is this
 * old (TM-04): `now - checkedAt >= 24 h`.
 */
export const RECHECK_AFTER_MS = 24 * 60 * 60 * 1000;
/** A check time ahead of the clock by more than this is due too (a bad clock or row). */
const CLOCK_SKEW_MS = 60_000;
/** How long one call holds the recheck of an account before another may take it. */
export const RECHECK_CLAIM_MS = 30_000;
/** How long a call waits for another call's recheck before it fails closed. */
export const RECHECK_WAIT_MS = 10_000;
const RECHECK_POLL_MS = 200;
const LISTED_REASONS = 3;

/** Whether a token whose last passed check was at `checkedAt` must be checked before use. */
export function isRecheckDue(checkedAt: number, now: number): boolean {
  const age = now - checkedAt;
  return !(age < RECHECK_AFTER_MS && age >= -CLOCK_SKEW_MS);
}

export type UsableToken =
  | { ok: true; token: string }
  | { ok: false; status: number; code: number; message: string; retryAfter?: number };

const listed = (result: IntakeResult) =>
  result.reasons
    .slice(0, LISTED_REASONS)
    .map((r) => `${r.code}: ${r.message}`)
    .join("; ");

function outcomeOf(result: IntakeResult, token: string): UsableToken {
  if (result.ok) return { ok: true, token };
  if (result.retryable) {
    console.warn("broker: token recheck could not run", result.accountId);
    const limited = result.retryAfter !== undefined;
    return {
      ok: false,
      status: limited ? 429 : 503,
      code: RECHECK_UNAVAILABLE_CODE,
      message: `the token recheck could not run (${listed(result)}); nothing was sent, retry later`,
      ...(limited ? { retryAfter: result.retryAfter } : {}),
    };
  }
  // Account ID and reason codes only: messages quote strings from the API.
  const codes = [...new Set(result.reasons.map((r) => r.code))].join(",");
  console.warn("broker: token failed its recheck and was deleted", result.accountId, codes);
  return {
    ok: false,
    status: 401,
    code: RECHECK_FAILED_CODE,
    message: `the stored token failed its recheck and was deleted (${listed(result)}); onboard the account again with a read-only token`,
  };
}

/**
 * The account's token for one `ApiCaller` call (TM-04). A token whose check
 * is due is checked again first, by one call per account at a time (a claim
 * on the vault row); other calls wait up to `waitMs` for it, then fail
 * closed. The outcome of a recheck:
 *
 * - passed: the check time is recorded and the call is served;
 * - failed: the token is deleted and the call fails with 401 and
 *   RECHECK_FAILED_CODE, which the reader turns into NoPermissionError;
 * - no answer: the token is kept and the call fails closed with
 *   RECHECK_UNAVAILABLE_CODE, 429 with `retryAfter` after a rate limit and
 *   503 otherwise. The next call tries again.
 */
export async function usableToken(
  env: BrokerEnv,
  accountId: string,
  options: { waitMs?: number } = {},
): Promise<UsableToken> {
  const master = await loadMasterKey(env);
  const giveUpAt = Date.now() + (options.waitMs ?? RECHECK_WAIT_MS);
  for (;;) {
    const found = await getToken(env.VAULT, master, accountId);
    if (!found) {
      return {
        ok: false,
        status: 401,
        code: NO_TOKEN_CODE,
        message: "no token stored for this account",
      };
    }
    const now = Date.now();
    if (!isRecheckDue(found.entry.checkedAt, now)) return { ok: true, token: found.token };
    const until = now + RECHECK_CLAIM_MS;
    if (await claimRecheck(env.VAULT, found.entry, now, until)) {
      try {
        return outcomeOf(await recheckToken(env, found), found.token);
      } finally {
        // A pass or a deletion has ended the claim already.
        await releaseRecheck(env.VAULT, accountId, until);
      }
    }
    if (now >= giveUpAt) {
      return {
        ok: false,
        status: 503,
        code: RECHECK_UNAVAILABLE_CODE,
        message: "a recheck of the account's token is still running; nothing was sent, retry later",
      };
    }
    await scheduler.wait(RECHECK_POLL_MS);
  }
}
