import type { TokenProfile } from "./vault.ts";

// Shapes of GET /accounts/{account_id}/tokens/verify and
// GET /accounts/{account_id}/tokens/{token_id}, fields used here only.
// https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/verify/
// https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/get/

export interface VerifiedToken {
  id?: unknown;
  status?: unknown;
  expires_on?: unknown;
  not_before?: unknown;
}

export interface TokenPolicy {
  id?: unknown;
  effect?: unknown;
  permission_groups?: unknown;
  resources?: unknown;
}

export interface TokenDetails extends VerifiedToken {
  policies?: unknown;
}

export type IssueCode =
  | "invalid_input"
  | "broker_error"
  | "not_account_token"
  | "verify_failed"
  | "not_active"
  | "details_unavailable"
  | "token_mismatch"
  | "no_policies"
  | "not_read_only"
  | "no_expiry"
  | "expired"
  | "expiry_too_far"
  | "not_yet_valid"
  | "account_not_covered"
  | "foreign_resource"
  | "reaches_content"
  | "not_found";

export interface CheckIssue {
  code: IssueCode;
  message: string;
}

/** Outcome of the onboarding write check. Never contains the token. */
export interface WriteCheckResult {
  ok: boolean;
  accountId: string;
  tokenId: string | null;
  expiresOn: string | null;
  /** Allow-effect permission group names, as Cloudflare reports them. */
  permissionGroups: string[];
  reasons: CheckIssue[];
  warnings: CheckIssue[];
}

export const MAX_TOKEN_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000;

const READ_SUFFIXES = [" Read", "Read-Only", " Metadata Read"];

// Read groups whose names do not end in a read suffix. Each is described as
// "Grants read access" in the API token permissions reference.
const READ_NAMES = new Set(["Account Security Center Insights", "Zone Security Center Insights"]);

const WRITE_MARKERS = /write|edit|admin|editor|revoke|purge/i;

// Read groups that reach code or data rather than metadata (D-14).
const CONTENT_NAMES = new Set([
  "Workers Scripts Read",
  "D1 Read",
  "Workers KV Storage Read",
  "Workers R2 Storage Read",
  "Pages Read",
]);

export type GroupClass = "read" | "write" | "unknown";

/** Classifies a permission group by name. Anything not clearly a read fails closed. */
export function classifyPermissionGroup(name: string): GroupClass {
  if (WRITE_MARKERS.test(name)) return "write";
  if (READ_NAMES.has(name) || READ_SUFFIXES.some((s) => name.endsWith(s))) return "read";
  return "unknown";
}

const reachesContent = (name: string) => CONTENT_NAMES.has(name) || name.includes("Content Read");

// Strings from the API end up in results shown in the UI; keep them short.
const clip = (value: string, max = 120) => (value.length > max ? `${value.slice(0, max)}…` : value);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const str = (value: unknown): string | null => (typeof value === "string" ? value : null);

export const TOKEN_ID = /^[A-Za-z0-9]{1,32}$/;

export interface CheckInput {
  accountId: string;
  profile: TokenProfile;
  verify: VerifiedToken;
  details: TokenDetails;
  now: number;
}

/**
 * Decides whether a token may be stored: active, this account only, every
 * allow-effect permission group a read, and an expiry no more than 90 days ahead.
 */
export function checkToken(input: CheckInput): WriteCheckResult {
  const { accountId, verify, details, now } = input;
  const reasons: CheckIssue[] = [];
  const warnings: CheckIssue[] = [];
  const tokenId = str(verify.id);
  const result = (expiresOn: string | null, permissionGroups: string[]): WriteCheckResult => ({
    ok: reasons.length === 0,
    accountId,
    tokenId,
    expiresOn,
    permissionGroups,
    reasons,
    warnings,
  });

  if (tokenId === null || !TOKEN_ID.test(tokenId)) {
    reasons.push({ code: "verify_failed", message: "token verification returned no token ID" });
    return result(null, []);
  }
  if (details.id !== undefined && details.id !== tokenId) {
    reasons.push({ code: "token_mismatch", message: "token details belong to another token" });
  }
  for (const status of [verify.status, details.status]) {
    if (status !== undefined && status !== "active") {
      reasons.push({
        code: "not_active",
        message: `token status is ${clip(String(status), 20)}, not active`,
      });
      break;
    }
  }
  if (verify.status === undefined) {
    reasons.push({ code: "not_active", message: "token verification returned no status" });
  }

  const expiresOn = str(details.expires_on) ?? str(verify.expires_on);
  checkExpiry(expiresOn, now, reasons);
  const notBefore = str(details.not_before) ?? str(verify.not_before);
  if (notBefore !== null && Date.parse(notBefore) > now) {
    reasons.push({
      code: "not_yet_valid",
      message: `token is not valid before ${clip(notBefore)}`,
    });
  }

  const groups = checkPolicies(accountId, details.policies, reasons);
  if (input.profile === "inventory") {
    for (const name of groups.filter(reachesContent)) {
      warnings.push({
        code: "reaches_content",
        message: `${clip(name)} reads code or data; the inventory profile needs metadata only`,
      });
    }
  }
  return result(expiresOn, groups);
}

function checkExpiry(expiresOn: string | null, now: number, reasons: CheckIssue[]): void {
  if (expiresOn === null) {
    reasons.push({ code: "no_expiry", message: "token has no expiry; set one within 90 days" });
    return;
  }
  const at = Date.parse(expiresOn);
  if (Number.isNaN(at)) {
    reasons.push({ code: "no_expiry", message: "token expiry is not a valid date" });
  } else if (at <= now) {
    reasons.push({ code: "expired", message: `token expired on ${clip(expiresOn)}` });
  } else if (at - now > MAX_TOKEN_LIFETIME_MS) {
    reasons.push({
      code: "expiry_too_far",
      message: `token expires on ${clip(expiresOn)}, more than 90 days ahead`,
    });
  }
}

const ACCOUNT_RESOURCE = "com.cloudflare.api.account.";
const ZONE_RESOURCE = /^com\.cloudflare\.api\.account\.zone\.[0-9a-f]{32}$/;

/** Returns the allow-effect group names and records every problem found. */
function checkPolicies(accountId: string, policies: unknown, reasons: CheckIssue[]): string[] {
  const allow = Array.isArray(policies)
    ? policies.filter((p): p is TokenPolicy => isRecord(p) && p.effect === "allow")
    : [];
  if (allow.length === 0) {
    reasons.push({ code: "no_policies", message: "token has no allow policy" });
    return [];
  }
  const names: string[] = [];
  let covered = false;
  for (const policy of allow) {
    const groups = Array.isArray(policy.permission_groups) ? policy.permission_groups : [];
    if (groups.length === 0) {
      reasons.push({ code: "no_policies", message: "an allow policy has no permission groups" });
    }
    for (const group of groups) {
      const name = isRecord(group) ? str(group.name) : null;
      if (name === null) {
        const id = isRecord(group) ? str(group.id) : null;
        reasons.push({
          code: "not_read_only",
          message: `permission group ${clip(id ?? "without ID")} has no name`,
        });
        continue;
      }
      names.push(name);
      const kind = classifyPermissionGroup(name);
      if (kind !== "read") {
        reasons.push({
          code: "not_read_only",
          message:
            kind === "write"
              ? `${clip(name)} can change the account`
              : `${clip(name)} is not a known read permission`,
        });
      }
    }
    const resources = isRecord(policy.resources) ? Object.keys(policy.resources) : [];
    for (const key of resources) {
      if (key === `${ACCOUNT_RESOURCE}${accountId}`) covered = true;
      else if (!ZONE_RESOURCE.test(key)) {
        reasons.push({
          code: "foreign_resource",
          message: `resource ${clip(key)} is not this account or one of its zones`,
        });
      }
    }
  }
  if (!covered) {
    reasons.push({
      code: "account_not_covered",
      message: `no allow policy includes account ${accountId}`,
    });
  }
  return [...new Set(names)];
}
