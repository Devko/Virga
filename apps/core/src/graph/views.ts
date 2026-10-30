import type { JsonRecord, Untrusted } from "../untrusted.ts";

export const FINDING_STATUSES = ["open", "resolved", "suppressed"] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const FINDING_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];

export interface NodeView {
  id: Untrusted<string>;
  type: string;
  nativeId: Untrusted<string>;
  class: string;
  name: Untrusted<string> | null;
  props: Untrusted<JsonRecord>;
  firstSeen: number;
  changedAt: number;
  deletedAt: number | null;
}

export interface EdgeView {
  id: Untrusted<string>;
  type: string;
  src: Untrusted<string>;
  dst: Untrusted<string>;
  key: Untrusted<string>;
  class: string;
  props: Untrusted<JsonRecord>;
}

export interface CoverageView {
  resourceClass: string;
  status: string;
  chunksTotal: number;
  chunksDone: number;
  detail: Untrusted<string> | null;
}

export const RULE_RUN_STATUSES = ["evaluated", "not_evaluated", "error"] as const;
export type RuleRunStatus = (typeof RULE_RUN_STATUSES)[number];

/** One rule's run in a scan (`rule_runs`). */
export interface RuleRunView {
  ruleId: string;
  status: RuleRunStatus;
  /** Decided rows; 0 unless evaluated. */
  hits: number;
  /** Rows the rule could not decide, e.g. where exposure is `unknown`; 0 unless evaluated. */
  undecided: number;
  /** Inputs without complete coverage when the rule was not evaluated. */
  missing: string[];
  /** Why the run failed, at most 500 characters. It can quote values from the scanned account. */
  error: Untrusted<string> | null;
}

export interface GraphSummary {
  /** The most recent scan in the graph, running or finished. */
  scan: {
    id: string;
    kind: string;
    status: string;
    startedAt: number;
    finishedAt: number | null;
  } | null;
  coverage: CoverageView[];
  /** Live nodes per resource class. */
  nodes: Record<string, number>;
  /** Findings per status and severity. */
  findings: Record<FindingStatus, Partial<Record<FindingSeverity, number>>>;
  /** Exposure rows per decision. */
  exposure: Record<string, number>;
  /** Rules of the latest scan per run status. */
  rules: Record<string, number>;
  /**
   * Each rule's run in the latest scan, by rule ID. A rule that is not
   * evaluated, and an undecided row, is not a pass.
   */
  ruleRuns: RuleRunView[];
}

export interface FindingFilters {
  status?: FindingStatus | FindingStatus[];
  severity?: FindingSeverity | FindingSeverity[];
  /** Default 50, at most 200. */
  limit?: number;
  /** `cursor` of the previous page. */
  cursor?: string;
}

export interface FindingView {
  fingerprint: Untrusted<string>;
  ruleId: string;
  ruleVersion: number;
  severity: FindingSeverity;
  status: FindingStatus;
  title: string;
  evidence: Untrusted<JsonRecord>;
  insightId: Untrusted<string> | null;
  firstSeen: number;
  lastSeen: number;
  resolvedAt: number | null;
  suppressedUntil: number | null;
}

export interface FindingPage {
  findings: FindingView[];
  /** Pass as `cursor` for the next page; null on the last page. */
  cursor: string | null;
}

export interface FindingDetail extends FindingView {
  suppressedBy: Untrusted<string> | null;
  suppressReason: Untrusted<string> | null;
  /** The nodes the finding is about, with their role (finding_nodes). */
  subjects: { nodeId: Untrusted<string>; role: string }[];
  /** The subject nodes that exist in the graph, including tombstoned ones. */
  nodes: NodeView[];
}

export interface Neighborhood {
  root: Untrusted<string>;
  depth: number;
  /** Live nodes within `depth` hops, the root included. */
  nodes: NodeView[];
  /** Live edges between those nodes and the IDs in `missing`. */
  edges: EdgeView[];
  /** IDs that live edges point to but that have no live node, e.g. a class without coverage. */
  missing: Untrusted<string>[];
  /** True when `limit` cut the result short. */
  truncated: boolean;
}
