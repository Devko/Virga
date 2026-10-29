import type { ReadRule } from "./types.ts";

/**
 * Reads used by the platform collectors (zones, dns, workers, pages, storage).
 * Owned by the platform collectors work package.
 *
 * Metadata only. Deliberately absent: script content
 * (`/workers/scripts/:script_name`, `.../content`), KV keys and values, R2
 * objects, D1 queries and secret values.
 */
export const PLATFORM_READS: readonly ReadRule[] = [
  // zones
  { method: "GET", pattern: "/zones", usedBy: "zones" },
  // dns
  { method: "GET", pattern: "/zones", usedBy: "dns" },
  { method: "GET", pattern: "/zones/:zone_id/dns_records", usedBy: "dns" },
];
