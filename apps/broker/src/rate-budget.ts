import { DurableObject } from "cloudflare:workers";
import {
  type BudgetDecision,
  type BudgetKind,
  BudgetLedger,
  type BudgetReport,
  isBudgetKind,
} from "./budget.ts";
import type { BrokerEnv } from "./env.ts";

/** Rate budget Durable Object, one per account (named by account ID). */
export class RateBudget extends DurableObject<BrokerEnv> {
  readonly ledger: BudgetLedger;

  constructor(ctx: DurableObjectState, env: BrokerEnv) {
    super(ctx, env);
    this.ledger = new BudgetLedger(ctx.storage.sql);
  }

  acquire(kind: BudgetKind): BudgetDecision {
    if (!isBudgetKind(kind)) throw new TypeError("unknown budget kind");
    return this.ledger.acquire(kind, Date.now());
  }

  report(kind: BudgetKind, report: BudgetReport): void {
    if (!isBudgetKind(kind)) throw new TypeError("unknown budget kind");
    this.ledger.report(kind, report, Date.now());
  }
}
