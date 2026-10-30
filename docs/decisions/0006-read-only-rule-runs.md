# 0006: A rule run only reads, checked at run time

- Status: accepted
- Date: 2026-10-30
- Changes: "Scan semantics" in the graph contract (a rule run only reads)
- Source: R6-02 in the [round 6 verification](../reviews/2026-10-30-verification-round-6.md), run-time half
- Corrected: 2026-10-30, after the [round 8 verification](../reviews/2026-10-30-verification-round-8.md): `case_sensitive_like` and `defer_foreign_keys`, and two gaps of the guard

## Context

The rule compiler checks a rule's statement in Node SQLite: `EXPLAIN` refuses writes, and since round 8 a statement tail is refused too. Node SQLite compiles only the first statement of a string. Durable Object SQL runs every statement of a query and returns the cursor of the last one. A tail the compiler misses therefore runs in production, unchecked: it can write `meta.current_scan` or `findings`, and an empty last cursor resolves every open finding of the rule.

Checked in workerd 1.20261012.1 (the vitest pool) on 2026-10-30:

- `cursor.rowsWritten` counts only the last statement. `UPDATE meta ...; SELECT ...` reports 0 although the update ran.
- `total_changes()` counts the rows of every `INSERT`, `UPDATE` and `DELETE` on the connection, whatever its position, but no schema change.
- `PRAGMA query_only` and `PRAGMA schema_version` are not authorized. `sqlite_schema` can be read.
- `BEGIN`, `COMMIT`, `SAVEPOINT`, `RELEASE`, `ROLLBACK`, `ATTACH` and temporary tables are refused inside `sql.exec`. `VACUUM` fails inside a transaction.
- A throw inside `transactionSync` rolls back rows and schema. Nested `transactionSync` calls use savepoints.
- These connection settings can be changed by a statement and keep their value after a rollback: `ignore_check_constraints`, `recursive_triggers`, `reverse_unordered_selects`, `legacy_alter_table`, and `case_sensitive_like`, which changes `LIKE` in workerd as in Node SQLite (`'a' LIKE 'A'` goes from 1 to 0). `foreign_keys` is a no-op inside a transaction. `defer_foreign_keys` keeps its value too; the schema declares no foreign keys, so it changes nothing today.
- SQLite applies such flag pragmas when the statement is prepared, not when it runs.

## Decision

Rules run through `SqlRunner.queryReadOnly`, in their own transaction:

- Before and after the query, it reads `total_changes()`, the schema as text, and the settings above (`case_sensitive_like` through what `'a' LIKE 'A'` returns).
- If rows changed (or the last statement's `rowsWritten` is above 0), the schema changed, or a setting changed, the settings are set back, the call throws `ReadOnlyError`, and the transaction rolls back. A failing query sets the settings back too.
- `evaluateRules` turns the throw into a run with status `error`, so no finding opens or resolves.
- The snapshot comes before the query is prepared, so a flag pragma cannot act before it.
- Node SQLite, which would skip a tail, refuses a query with more than one statement.

## Consequences

- The guard catches writes, not reads. A tail that only reads (for example `exposure` without `requires: [access, exposure]`, R4-04) still needs the compiler's tail check.
- The guard does not catch every write either. `total_changes()` does not count `DROP TABLE`, and the schema is compared as text. So a tail that drops a table and creates it again with the same statement passes and leaves the table empty. And the settings are read through `pragma_*` table functions: a view with such a name makes that read fail or lie, and a changed setting stays. Both were reproduced in workerd 1.20261012.1 with the compiler bypassed. Today only the compiler's tail refusal stops them; the round 8 verification lists the fixes as hardening.
- `ANALYZE` and `REINDEX` change no rows, schema or setting the guard reads, so they pass. They change query plans, not results.
- Two extra queries per rule run. A scan runs 11 rules.
- A later platform change can add settings or ways to write. Re-check the list on a workerd upgrade with the probe in `apps/core/test/rules-runtime.test.ts`.
