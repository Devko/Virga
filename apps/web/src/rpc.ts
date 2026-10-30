/**
 * The RPC surface this Worker calls, mirrored from its sources because the
 * service bindings are typed only as `Service`:
 * - `GraphReader` and `Admin`: apps/core/src (graph-reader.ts, admin.ts, graph/views.ts, index-db.ts)
 * - `TokenIntake`: apps/broker/src/token-intake.ts
 * Pure types plus three casts, so the SPA can import the view types too.
 */

/** A value from a scanned account. Render it as text, never as markup or instructions. */
export type Untrusted<T> = T & { readonly __untrusted: true };

export type Json = string | number | boolean | null | object;
export type JsonRecord = { [key: string]: Json };

export const PROFILES = ["inventory", "workload"] as const;
export type Profile = (typeof PROFILES)[number];

export interface AccountRow {
  id: string;
  /** Display name chosen at onboarding. */
  name: Untrusted<string>;
  status: "active" | "paused";
  cadenceHours: number;
  profile: Profile;
  createdAt: number;
  lastScanAt: number | null;
}

export interface ScanRunRow {
  id: string;
  accountId: string;
  startedAt: number;
  finishedAt: number | null;
  status: "running" | "complete" | "partial" | "failed";
  /** The scan's summary (core ScanSummary); `detail` fields quote API errors. */
  summary: Untrusted<JsonRecord> | null;
}

export interface NewAccount {
  id: string;
  name: string;
  cadenceHours?: number;
  profile?: Profile;
}

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

export type RuleRunStatus = "evaluated" | "not_evaluated" | "error";

/** One rule's run in the latest scan. Not evaluated and undecided are not passes. */
export interface RuleRunView {
  ruleId: string;
  status: RuleRunStatus;
  /** Decided rows. */
  hits: number;
  /** Rows the rule could not decide, e.g. where exposure is `unknown`. */
  undecided: number;
  /** Inputs without complete coverage when the rule was not evaluated. */
  missing: string[];
  /** Why the run failed; can quote values from the scanned account. */
  error: Untrusted<string> | null;
}

export interface GraphSummary {
  scan: {
    id: string;
    kind: string;
    status: string;
    startedAt: number;
    finishedAt: number | null;
  } | null;
  coverage: CoverageView[];
  nodes: Record<string, number>;
  findings: Record<FindingStatus, Partial<Record<FindingSeverity, number>>>;
  exposure: Record<string, number>;
  /** Rules of the latest scan per run status. */
  rules: Record<string, number>;
  /** Each rule's run in the latest scan, by rule ID. */
  ruleRuns: RuleRunView[];
}

export interface ScanSummaryView {
  account: AccountRow;
  lastRun: ScanRunRow | null;
  graph: GraphSummary;
}

export interface FindingFilters {
  status?: FindingStatus | FindingStatus[];
  severity?: FindingSeverity | FindingSeverity[];
  /** Default 50, at most 200. */
  limit?: number;
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
  cursor: string | null;
}

export interface FindingDetail extends FindingView {
  suppressedBy: Untrusted<string> | null;
  suppressReason: Untrusted<string> | null;
  subjects: { nodeId: Untrusted<string>; role: string }[];
  nodes: NodeView[];
}

export interface Neighborhood {
  root: Untrusted<string>;
  depth: number;
  nodes: NodeView[];
  edges: EdgeView[];
  missing: Untrusted<string>[];
  truncated: boolean;
}

export type TriggerResult =
  | { started: true; id: string }
  | { started: false; reason: "unknown_account" | "running" | "exists"; id: string | null };

export interface CheckIssue {
  code: string;
  message: string;
}

/** Outcome of TokenIntake.store. Never contains the token. */
export interface IntakeResult {
  ok: boolean;
  accountId: string;
  tokenId: string | null;
  expiresOn: string | null;
  permissionGroups: string[];
  reasons: CheckIssue[];
  warnings: CheckIssue[];
  stored: boolean;
  removed: boolean;
  retryable: boolean;
}

/** Every method but `listAccounts` answers null for an account that is not in the index. */
export interface GraphReaderRpc {
  /** Every account in the index, by name, then ID; at most 1,000. */
  listAccounts(): Promise<AccountRow[]>;
  getScanSummary(accountId: string): Promise<ScanSummaryView | null>;
  listFindings(accountId: string, filters?: FindingFilters): Promise<FindingPage | null>;
  getFinding(accountId: string, fingerprint: string): Promise<FindingDetail | null>;
  getNeighborhood(
    accountId: string,
    nodeId: string,
    options?: { depth?: number; limit?: number },
  ): Promise<Neighborhood | null>;
}

/** `removed`: Admin, the account was in the index; TokenIntake, a token was stored. */
export interface RemoveResult {
  removed: boolean;
}

export interface AdminRpc {
  addAccount(input: NewAccount): Promise<AccountRow>;
  triggerScan(accountId: string): Promise<TriggerResult>;
  /** Deletes the index rows, then the account's graph. Idempotent. */
  removeAccount(accountId: string): Promise<RemoveResult>;
}

export interface TokenIntakeRpc {
  store(accountId: string, token: string, profile: Profile): Promise<IntakeResult>;
  /** Deletes the stored token, then clears the account's rate budget. Idempotent. */
  remove(accountId: string): Promise<RemoveResult>;
}

/** Cloudflare account IDs, as core and the broker accept them. */
export const ACCOUNT_ID = /^[0-9a-f]{32}$/;
export const isAccountId = (value: unknown): value is string =>
  typeof value === "string" && ACCOUNT_ID.test(value);

interface Bindings {
  CORE_READ: unknown;
  CORE_ADMIN: unknown;
  BROKER_INTAKE: unknown;
}

export const graphReader = (env: Bindings) => env.CORE_READ as GraphReaderRpc;
export const coreAdmin = (env: Bindings) => env.CORE_ADMIN as AdminRpc;
export const tokenIntake = (env: Bindings) => env.BROKER_INTAKE as TokenIntakeRpc;
