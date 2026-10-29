import type { Collector } from "../types.ts";
import { dnsCollector } from "./dns.ts";
import { zonesCollector } from "./zones.ts";

export { detectSecret, SECRET_PATTERNS, type SecretPattern } from "./secrets.ts";
export { dnsCollector, zonesCollector };

/** zones, dns, workers, pages, storage. Owned by the platform collectors work package. */
export const PLATFORM_COLLECTORS: readonly Collector[] = [zonesCollector, dnsCollector];
