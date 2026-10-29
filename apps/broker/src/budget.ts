/**
 * Rate budget of one account (S-02). The Cloudflare API allows 1,200 REST
 * requests per 5 minutes per token and blocks the token for 5 minutes when
 * that is exceeded. GraphQL has its own quota of 300 queries per 5 minutes on
 * top of the REST limit, and sends no `Ratelimit` header.
 *
 * The ledger counts its own grants in a sliding window and also trusts the
 * last `Ratelimit` header until its reset time, since the quota is shared with
 * the dashboard and other clients of the same token. It keeps a safety margin,
 * paces the last quarter of the quota over the time until it refills, and
 * blocks after a 429 until `retry-after`.
 */

export const BUDGET_KINDS = ["rest", "graphql"] as const;
export type BudgetKind = (typeof BUDGET_KINDS)[number];

export interface BudgetLimit {
  quota: number;
  windowMs: number;
  /** Requests left unused, for other clients of the token and requests in flight. */
  margin: number;
}

export const LIMITS: Record<BudgetKind, BudgetLimit> = {
  rest: { quota: 1200, windowMs: 300_000, margin: 120 },
  graphql: { quota: 300, windowMs: 300_000, margin: 30 },
};

const PACE_BELOW = 0.25;
const DEFAULT_BLOCK_SECONDS = 300;

export type BudgetDecision =
  | { ok: true }
  | { ok: false; reason: "blocked" | "exhausted" | "pacing"; waitMs: number };

/** What one response said about the budget. */
export interface BudgetReport {
  status: number;
  /** `r` of the `Ratelimit` header; applies to the REST budget. */
  remaining?: number;
  /** `t` of the `Ratelimit` header, in seconds. */
  reset?: number;
  /** `retry-after` in seconds, on a 429. */
  retryAfter?: number;
}

interface State {
  [key: string]: SqlStorageValue;
  remaining: number | null;
  reset_at: number;
  reported_at: number;
  blocked_until: number;
  last_grant: number;
}

export const isBudgetKind = (value: unknown): value is BudgetKind =>
  BUDGET_KINDS.includes(value as BudgetKind);

/** Budget bookkeeping over Durable Object SQLite. Time is passed in for tests. */
export class BudgetLedger {
  readonly sql: SqlStorage;

  constructor(sql: SqlStorage) {
    this.sql = sql;
    sql.exec("CREATE TABLE IF NOT EXISTS grants (kind TEXT NOT NULL, at INTEGER NOT NULL)");
    sql.exec("CREATE INDEX IF NOT EXISTS grants_kind_at ON grants (kind, at)");
    sql.exec(
      `CREATE TABLE IF NOT EXISTS budget (
        kind TEXT PRIMARY KEY,
        remaining INTEGER,
        reset_at INTEGER NOT NULL DEFAULT 0,
        reported_at INTEGER NOT NULL DEFAULT 0,
        blocked_until INTEGER NOT NULL DEFAULT 0,
        last_grant INTEGER NOT NULL DEFAULT 0
      )`,
    );
  }

  /** Grants one request or says how long to wait. A GraphQL query also uses REST quota. */
  acquire(kind: BudgetKind, now: number): BudgetDecision {
    const kinds: BudgetKind[] = kind === "graphql" ? ["rest", "graphql"] : ["rest"];
    let decision: BudgetDecision = { ok: true };
    for (const k of kinds) {
      const d = this.decide(k, now);
      if (!d.ok && (decision.ok || d.waitMs > decision.waitMs)) decision = d;
    }
    if (!decision.ok) return decision;
    for (const k of kinds) {
      this.sql.exec("INSERT INTO grants (kind, at) VALUES (?, ?)", k, now);
      this.update(k, { last_grant: now });
    }
    return decision;
  }

  report(kind: BudgetKind, report: BudgetReport, now: number): void {
    if (report.status === 429) {
      this.blockUntil(kind, now + (report.retryAfter ?? DEFAULT_BLOCK_SECONDS) * 1000);
    }
    if (report.remaining !== undefined) {
      this.update("rest", {
        remaining: report.remaining,
        reset_at: now + (report.reset ?? 0) * 1000,
        reported_at: now,
      });
    }
  }

  blockUntil(kind: BudgetKind, until: number): void {
    if (until > this.state(kind).blocked_until) this.update(kind, { blocked_until: until });
  }

  state(kind: BudgetKind): State {
    const rows = this.sql.exec<State>("SELECT * FROM budget WHERE kind = ?", kind).toArray();
    return (
      rows[0] ?? { remaining: null, reset_at: 0, reported_at: 0, blocked_until: 0, last_grant: 0 }
    );
  }

  private decide(kind: BudgetKind, now: number): BudgetDecision {
    const limit = LIMITS[kind];
    const state = this.state(kind);
    if (state.blocked_until > now) {
      return { ok: false, reason: "blocked", waitMs: state.blocked_until - now };
    }
    this.sql.exec("DELETE FROM grants WHERE kind = ? AND at <= ?", kind, now - limit.windowMs);
    const local = this.sql
      .exec<{ n: number; oldest: number | null }>(
        "SELECT count(*) AS n, min(at) AS oldest FROM grants WHERE kind = ?",
        kind,
      )
      .one();
    let remaining = limit.quota - local.n;
    let refillAt = (local.oldest ?? now) + limit.windowMs;
    if (state.remaining !== null && state.reset_at > now) {
      const after = this.sql
        .exec<{ n: number }>(
          "SELECT count(*) AS n FROM grants WHERE kind = ? AND at >= ?",
          kind,
          state.reported_at,
        )
        .one().n;
      if (state.remaining - after < remaining) {
        remaining = state.remaining - after;
        refillAt = state.reset_at;
      }
    }
    const usable = remaining - limit.margin;
    if (usable <= 0) {
      return { ok: false, reason: "exhausted", waitMs: Math.max(1, refillAt - now) };
    }
    if (usable < limit.quota * PACE_BELOW && state.last_grant > 0) {
      const next = state.last_grant + (refillAt - now) / usable;
      if (next > now) return { ok: false, reason: "pacing", waitMs: Math.ceil(next - now) };
    }
    return { ok: true };
  }

  private update(kind: BudgetKind, values: Partial<Omit<State, "kind">>): void {
    const next = { ...this.state(kind), ...values };
    this.sql.exec(
      `INSERT INTO budget (kind, remaining, reset_at, reported_at, blocked_until, last_grant)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (kind) DO UPDATE SET remaining = excluded.remaining,
         reset_at = excluded.reset_at, reported_at = excluded.reported_at,
         blocked_until = excluded.blocked_until, last_grant = excluded.last_grant`,
      kind,
      next.remaining,
      next.reset_at,
      next.reported_at,
      next.blocked_until,
      next.last_grant,
    );
  }
}
