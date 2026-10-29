import type { Collector } from "../types.ts";
import { dnsCollector } from "./dns.ts";
import { pagesCollector } from "./pages.ts";
import { storageCollector } from "./storage.ts";
import { workersCollector } from "./workers.ts";
import { zonesCollector } from "./zones.ts";

export { detectSecret, SECRET_PATTERNS, type SecretPattern } from "./secrets.ts";
export { dnsCollector, pagesCollector, storageCollector, workersCollector, zonesCollector };

/** zones, dns, workers, pages, storage. Owned by the platform collectors work package. */
export const PLATFORM_COLLECTORS: readonly Collector[] = [
  zonesCollector,
  dnsCollector,
  workersCollector,
  pagesCollector,
  storageCollector,
];
