import type { ReadRule } from "./types.ts";

/**
 * Reads used by the identity collectors (access, tunnels, tokens, members,
 * insights, traffic). Owned by the identity collectors work package.
 *
 * Deliberately absent: tunnel and Mesh node tokens
 * (`/cfd_tunnel/:tunnel_id/token`, `/warp_connector/:tunnel_id/token`),
 * single service tokens and identity providers, tunnel connections and
 * management, and every Access endpoint that is not a listing.
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
  // tunnels
  { method: "GET", pattern: "/accounts/:account_id/tunnels", usedBy: "tunnels" },
  {
    method: "GET",
    pattern: "/accounts/:account_id/cfd_tunnel/:tunnel_id/configurations",
    usedBy: "tunnels",
  },
  // tokens
  { method: "GET", pattern: "/accounts/:account_id/tokens", usedBy: "tokens" },
];
