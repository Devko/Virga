import type { ReadRule } from "./types.ts";

/**
 * Reads used by the identity collectors (access, tunnels, tokens, members,
 * insights, traffic). Owned by the identity collectors work package.
 *
 * Deliberately absent: single service tokens and identity providers, and
 * every Access endpoint that is not a listing.
 */
export const IDENTITY_READS: readonly ReadRule[] = [
  // access
  { method: "GET", pattern: "/accounts/:account_id/access/apps", usedBy: "access" },
  {
    method: "GET",
    pattern: "/accounts/:account_id/access/apps/:app_id/policies",
    usedBy: "access",
  },
  { method: "GET", pattern: "/accounts/:account_id/access/policies", usedBy: "access" },
  { method: "GET", pattern: "/accounts/:account_id/access/groups", usedBy: "access" },
  { method: "GET", pattern: "/accounts/:account_id/access/service_tokens", usedBy: "access" },
  {
    method: "GET",
    pattern: "/accounts/:account_id/access/identity_providers",
    usedBy: "access",
  },
  { method: "GET", pattern: "/accounts/:account_id/workers/workers", usedBy: "access" },
];
