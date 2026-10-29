import type { ReadRule } from "./types.ts";

/**
 * Reads used by the identity collectors (access, tunnels, tokens, members,
 * insights, traffic). Owned by the identity collectors work package.
 */
export const IDENTITY_READS: readonly ReadRule[] = [];
