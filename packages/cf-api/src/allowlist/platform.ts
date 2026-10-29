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
  // workers
  { method: "GET", pattern: "/zones", usedBy: "workers" },
  { method: "GET", pattern: "/zones/:zone_id/workers/routes", usedBy: "workers" },
  {
    method: "GET",
    pattern: "/accounts/:account_id/workers/scripts/:script_name/subdomain",
    usedBy: "workers",
  },
  {
    method: "GET",
    pattern: "/accounts/:account_id/workers/scripts/:script_name/deployments",
    usedBy: "workers",
  },
  {
    method: "GET",
    pattern: "/accounts/:account_id/workers/scripts/:script_name/versions",
    usedBy: "workers",
  },
  {
    method: "GET",
    pattern: "/accounts/:account_id/workers/scripts/:script_name/versions/:version_id",
    usedBy: "workers",
  },
  { method: "GET", pattern: "/accounts/:account_id/workers/workers", usedBy: "workers" },
  {
    method: "GET",
    pattern: "/accounts/:account_id/workers/durable_objects/namespaces",
    usedBy: "workers",
  },
  { method: "GET", pattern: "/accounts/:account_id/queues", usedBy: "workers" },
  // storage
  { method: "GET", pattern: "/accounts/:account_id/r2/buckets", usedBy: "storage" },
  {
    method: "GET",
    pattern: "/accounts/:account_id/r2/buckets/:bucket_name/domains/managed",
    usedBy: "storage",
  },
  {
    method: "GET",
    pattern: "/accounts/:account_id/r2/buckets/:bucket_name/domains/custom",
    usedBy: "storage",
  },
  { method: "GET", pattern: "/accounts/:account_id/d1/database", usedBy: "storage" },
  { method: "GET", pattern: "/accounts/:account_id/storage/kv/namespaces", usedBy: "storage" },
  { method: "GET", pattern: "/accounts/:account_id/queues", usedBy: "storage" },
  { method: "GET", pattern: "/accounts/:account_id/hyperdrive/configs", usedBy: "storage" },
  {
    method: "GET",
    pattern: "/accounts/:account_id/workers/durable_objects/namespaces",
    usedBy: "storage",
  },
  { method: "GET", pattern: "/accounts/:account_id/secrets_store/stores", usedBy: "storage" },
  {
    method: "GET",
    pattern: "/accounts/:account_id/secrets_store/stores/:store_id/secrets",
    usedBy: "storage",
  },
];
