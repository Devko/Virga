import type { CfReader } from "@virga/cf-api";
import type { EdgeInput, InsightRow, NodeInput, SignalRow } from "@virga/graph";

/** Resource classes of phase 1. Each class has exactly one collector. */
export const RESOURCE_CLASSES = [
  "zones",
  "dns",
  "workers",
  "pages",
  "storage",
  "access",
  "tunnels",
  "tokens",
  "members",
  "insights",
  "traffic",
] as const;

export type ResourceClass = (typeof RESOURCE_CLASSES)[number];

export interface CollectorContext {
  accountId: string;
  scanId: string;
  /** Read-only API access through the broker. Throws NoPermissionError on 401/403. */
  api: CfReader;
  /** Scan start time (epoch ms); use instead of Date.now() so runs are reproducible. */
  now: number;
}

/** Bounds of `CollectorOutput.truncated`; the scan refuses a chunk that exceeds them. */
export const TRUNCATED_LIMITS = { reasons: 100, length: 1024 } as const;

/** What one chunk produces. All rows belong to the collector's resource class. */
export interface CollectorOutput {
  nodes: NodeInput[];
  edges: EdgeInput[];
  signals?: SignalRow[];
  /** Only the `insights` collector returns these; they replace the whole insights table. */
  insights?: InsightRow[];
  /**
   * One reason per unit whose resources this chunk left out, for example a
   * tunnel past its entry point cap (decision 0005). The class is then
   * `partial`: it is not swept and the rules that require it are not
   * evaluated, so nothing that was left out resolves a finding. Reasons may
   * name IDs from the scanned account, so they are untrusted text.
   */
  truncated?: string[];
}

/**
 * A collector for one resource class. The scan Workflow runs `plan` in one
 * step and `collect` in one step per chunk, so both must be deterministic
 * for a given account state and must return less than 1 MiB.
 *
 * Collectors only read. They never call Date.now(), never write anywhere,
 * and let NoPermissionError propagate: the Workflow records `no_permission`
 * for the class and dependent rules become `not evaluated`.
 */
export interface Collector<Unit = unknown> {
  resourceClass: ResourceClass;
  /** Classes whose nodes this collector's edges point to; they run first. Ordering only. */
  after?: ResourceClass[];
  /** Candidate permission group names, for onboarding hints and docs. */
  permissions: string[];
  /**
   * Splits the work into chunks of serializable units (for example zone IDs,
   * 25 per chunk). Return `[[]]` for a collector that runs as a single chunk.
   */
  plan(ctx: CollectorContext): Promise<Unit[][]>;
  collect(ctx: CollectorContext, chunk: Unit[]): Promise<CollectorOutput>;
}
