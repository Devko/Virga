import type { ReadRule } from "./types.ts";

/** Reads used by onboarding and by the broker itself. Owned by the broker work package. */
export const CORE_READS: readonly ReadRule[] = [
  { method: "GET", pattern: "/accounts/:account_id/tokens/verify", usedBy: "onboarding" },
  { method: "GET", pattern: "/accounts/:account_id/tokens/:token_id", usedBy: "onboarding" },
  { method: "POST", pattern: "/graphql", usedBy: "traffic" },
];
