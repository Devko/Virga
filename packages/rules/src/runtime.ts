import type { SqlRunner, SqlValue } from "@virga/graph";
import type { CompiledRule, RuleHit } from "./types.ts";

/**
 * Runs a compiled rule. `overrides` replace parameter defaults by name. The
 * rule only reads: a statement that writes, which Durable Object SQL would
 * run even after the compiled one, throws and is rolled back (R6-02).
 */
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
  return db.queryReadOnly<RuleHit>(rule.sql, ...bindings);
}
