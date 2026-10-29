import type { ReadRule } from "./types.ts";

/**
 * Reads used by the platform collectors (zones, dns, workers, pages, storage).
 * Owned by the platform collectors work package.
 */
export const PLATFORM_READS: readonly ReadRule[] = [];
