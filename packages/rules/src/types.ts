import type { SqlValue } from "@virga/graph";

export const RULE_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type RuleSeverity = (typeof RULE_SEVERITIES)[number];

export const RULE_KINDS = ["posture", "toxic", "detection"] as const;
export type RuleKind = (typeof RULE_KINDS)[number];

/** Front matter of a rule file. */
export interface RuleMeta {
  id: string;
  version: number;
  title: string;
  severity: RuleSeverity;
  kind: RuleKind;
  /** Resource classes and derived tables the rule needs. */
  requires: string[];
  /** Parameter defaults, by name. */
  params: Record<string, number | string>;
  /** Security Insight type that the rule enriches, if any. */
  enriches: string | null;
}

/** A rule ready to run: positional SQL plus the order of its parameters. */
export interface CompiledRule extends RuleMeta {
  sql: string;
  paramOrder: string[];
}

/** One row a rule returns. Columns besides these are evidence. */
export interface RuleHit {
  rule_id: string;
  fingerprint: string;
  severity: RuleSeverity;
  [column: string]: SqlValue;
}

export type VulnSeverity = "none" | "low" | "medium" | "high" | "critical";

/** A self-contained graph scenario with the hits a rule must return for it. */
export interface RuleFixture {
  rule: string;
  name: string;
  description?: string;
  params?: Record<string, number | string>;
  nodes: {
    type: string;
    id: string;
    name?: string;
    props?: Record<string, unknown>;
  }[];
  edges: {
    type: string;
    src: string;
    dst: string;
    key?: string;
    props?: Record<string, unknown>;
    deleted?: boolean;
  }[];
  exposure?: {
    entry: string;
    path?: string;
    decision: string;
    confidence: number;
  }[];
  vulns?: {
    package: string;
    id: string;
    severity: VulnSeverity;
    kev?: boolean;
    status?: "open" | "fixed" | "ignored";
  }[];
  signals?: { node: string; name: string; value: number | string }[];
  expect: { fingerprint: string; severity?: RuleSeverity }[];
}
