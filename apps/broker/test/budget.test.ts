import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { type BudgetKind, type BudgetLedger, LIMITS } from "../src/budget.ts";
import { parseRatelimit, parseRetryAfter } from "../src/headers.ts";
import type { RateBudget } from "../src/rate-budget.ts";

const T0 = 1_800_000_000_000;

/** Runs `fn` against the ledger of a fresh budget object. */
const withLedger = <R>(fn: (ledger: BudgetLedger) => R) =>
  runInDurableObject(env.RATE_BUDGET.get(env.RATE_BUDGET.newUniqueId()), (instance: RateBudget) =>
    fn(instance.ledger),
  );

/** Acquires until refused at one instant; returns the grants and the refusal. */
function burst(ledger: BudgetLedger, kind: BudgetKind, now: number) {
  let granted = 0;
  for (;;) {
    const decision = ledger.acquire(kind, now);
    if (!decision.ok) return { granted, decision };
    granted++;
  }
}

/** Tries one request every `step` ms in [from, to); returns the grant times. */
function sendOver(ledger: BudgetLedger, kind: BudgetKind, from: number, to: number, step: number) {
  const sent: number[] = [];
  for (let now = from; now < to; now += step) {
    if (ledger.acquire(kind, now).ok) sent.push(now);
  }
  return sent;
}

const paced = (kind: BudgetKind) => LIMITS[kind].quota * 0.25;

describe("Ratelimit headers", () => {
  it("parses the documented format", () => {
    expect(parseRatelimit('"default";r=1199;t=1')).toEqual({ remaining: 1199, reset: 1 });
    expect(parseRatelimit('"default";r=50;t=30, "burst";r=7;t=2')).toEqual({
      remaining: 7,
      reset: 2,
    });
    expect(parseRatelimit(null)).toBeUndefined();
    expect(parseRatelimit("garbage")).toBeUndefined();
  });

  it("parses retry-after as seconds or a date", () => {
    expect(parseRetryAfter("300", T0)).toBe(300);
    expect(parseRetryAfter(new Date(T0 + 61_000).toUTCString(), T0)).toBe(61);
    expect(parseRetryAfter("soon", T0)).toBeUndefined();
  });
});

describe("rate budget", () => {
  it("allows a burst of three quarters of the quota, then paces", async () => {
    const { granted, decision } = await withLedger((l) => burst(l, "rest", T0));
    expect(granted).toBe(LIMITS.rest.quota - LIMITS.rest.margin - paced("rest") + 1);
    expect(decision).toMatchObject({ ok: false, reason: "pacing" });
  });

  it("never uses the safety margin within a window when no header is seen", async () => {
    const sent = await withLedger((l) => sendOver(l, "rest", T0, T0 + 300_000, 50));
    expect(sent.length).toBe(LIMITS.rest.quota - LIMITS.rest.margin);
    const late = sent.filter((t) => t >= T0 + 150_000).length;
    expect(late).toBeGreaterThan(50);
  });

  it("frees quota as the window slides", async () => {
    const result = await withLedger((l) => {
      sendOver(l, "rest", T0, T0 + 300_000, 50);
      return {
        exhausted: l.acquire("rest", T0 + 299_999),
        next: burst(l, "rest", T0 + 300_000 + 300_000).granted,
      };
    });
    expect(result.exhausted).toMatchObject({ ok: false, reason: "exhausted" });
    expect(result.next).toBe(LIMITS.rest.quota - LIMITS.rest.margin - paced("rest") + 1);
  });

  it("pauses before the quota reported by Cloudflare runs out", async () => {
    // Another client of the token used most of the quota: r=200 with 100 s left.
    const result = await withLedger((l) => {
      l.report("rest", { status: 200, remaining: 200, reset: 100 }, T0);
      const sent = sendOver(l, "rest", T0, T0 + 100_000, 100);
      return { sent, last: l.acquire("rest", T0 + 99_999) };
    });
    expect(result.sent).toHaveLength(200 - LIMITS.rest.margin);
    // The 80 usable requests are spread over the 100 s, not sent at once.
    expect(result.sent.filter((t) => t < T0 + 10_000).length).toBeLessThan(20);
    expect(result.last).toMatchObject({ ok: false, reason: "exhausted" });
  });

  it("counts requests sent after the last header", async () => {
    const result = await withLedger((l) => {
      l.report("rest", { status: 200, remaining: 125, reset: 200 }, T0);
      const sent = sendOver(l, "rest", T0, T0 + 200_000, 1000);
      return { sent, next: l.acquire("rest", T0 + 199_999) };
    });
    expect(result.sent).toHaveLength(5);
    expect(result.next).toEqual({ ok: false, reason: "exhausted", waitMs: 1 });
  });

  it("blocks after a 429 until retry-after", async () => {
    const result = await withLedger((l) => {
      l.report("rest", { status: 429, retryAfter: 120 }, T0);
      return {
        during: l.acquire("rest", T0 + 119_999),
        graphql: l.acquire("graphql", T0 + 1_000),
        after: l.acquire("rest", T0 + 120_000),
      };
    });
    expect(result.during).toEqual({ ok: false, reason: "blocked", waitMs: 1 });
    expect(result.graphql).toMatchObject({ ok: false, reason: "blocked" });
    expect(result.after.ok).toBe(true);
  });

  it("blocks for 5 minutes after a 429 without retry-after", async () => {
    const decision = await withLedger((l) => {
      l.report("graphql", { status: 429 }, T0);
      return l.acquire("graphql", T0 + 1);
    });
    expect(decision).toEqual({ ok: false, reason: "blocked", waitMs: 299_999 });
  });

  it("keeps a separate GraphQL budget that also uses REST quota", async () => {
    const result = await withLedger((l) => {
      const graphql = sendOver(l, "graphql", T0, T0 + 300_000, 100);
      return { graphql, rest: burst(l, "rest", T0 + 300_000 - 1).granted };
    });
    expect(result.graphql).toHaveLength(LIMITS.graphql.quota - LIMITS.graphql.margin);
    // The REST budget lost what the GraphQL queries used.
    expect(result.rest).toBeLessThanOrEqual(
      LIMITS.rest.quota - LIMITS.rest.margin - result.graphql.length,
    );
  });

  it("keeps its state in Durable Object storage", async () => {
    const stub = env.RATE_BUDGET.get(env.RATE_BUDGET.idFromName("persisted"));
    await stub.report("rest", { status: 429, retryAfter: 60 });
    expect(await stub.acquire("rest")).toMatchObject({ ok: false, reason: "blocked" });
    const rows = await runInDurableObject(stub, (_: RateBudget, state) =>
      state.storage.sql.exec("SELECT kind, blocked_until FROM budget").toArray(),
    );
    expect(rows).toHaveLength(1);
  });

  it("clear deletes the stored budget and starts again like a new account", async () => {
    const stub = env.RATE_BUDGET.get(env.RATE_BUDGET.newUniqueId());
    await stub.acquire("graphql");
    await stub.report("rest", { status: 429, retryAfter: 300 });
    expect(await stub.acquire("rest")).toMatchObject({ ok: false, reason: "blocked" });

    await stub.clear();
    expect(await storedRows(stub)).toEqual({});
    expect(await stub.acquire("rest")).toEqual({ ok: true });
    expect(await storedRows(stub)).toEqual({ budget: 1, grants: 1 });
  });
});

/** Rows per table of a budget object, leaving out empty tables. */
function storedRows(stub: DurableObjectStub<RateBudget>) {
  return runInDurableObject(stub, (_: RateBudget, state) => {
    const counts: Record<string, number> = {};
    const tables = state.storage.sql
      .exec<{ name: string }>(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'",
      )
      .toArray();
    for (const { name } of tables) {
      const n = state.storage.sql
        .exec<{ n: number }>(`SELECT count(*) AS n FROM "${name}"`)
        .one().n;
      if (n > 0) counts[name] = n;
    }
    return counts;
  });
}
