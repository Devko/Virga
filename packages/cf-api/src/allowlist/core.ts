import type { ReadRule } from "./types.ts";

/**
 * Reads used by onboarding and by the broker itself. The write check uses the
 * two token reads at onboarding and again before a token is used once its
 * last check is 24 hours old (TM-04). Owned by the broker work package.
 */
export const CORE_READS: readonly ReadRule[] = [
  { method: "GET", pattern: "/accounts/:account_id/tokens/verify", usedBy: "onboarding" },
  { method: "GET", pattern: "/accounts/:account_id/tokens/:token_id", usedBy: "onboarding" },
  { method: "POST", pattern: "/graphql", usedBy: "traffic" },
];
