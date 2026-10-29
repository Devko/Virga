import type { SqlRunner, SqlValue } from "@virga/graph";
import type { CompiledRule, RuleHit } from "./types.ts";

/** Runs a compiled rule. `overrides` replace parameter defaults by name. */
export function runRule(
  db: SqlRunner,
  rule: CompiledRule,
  overrides: Record<string, number | string> = {},
): RuleHit[] {
  const params: Record<string, number | string> = { ...rule.params, ...overrides };
  const bindings: SqlValue[] = rule.paramOrder.map((name) => {
    const value = params[name];
    if (value === undefined) throw new Error(`${rule.id}: missing parameter ${name}`);
    return value;
  });
  return db.query<RuleHit>(rule.sql, ...bindings);
}
