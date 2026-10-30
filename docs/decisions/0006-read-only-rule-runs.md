# 0006: A rule run only reads, checked at run time

- Status: accepted
- Date: 2026-10-30
- Changes: "Scan semantics" in the graph contract (a rule run only reads)
- Source: R6-02 in the [round 6 verification](../reviews/2026-10-30-verification-round-6.md), run-time half
- Corrected: 2026-10-30, after the [round 8 verification](../reviews/2026-10-30-verification-round-8.md): `case_sensitive_like` and `defer_foreign_keys`, and two gaps of the guard
- Corrected: 2026-10-30, after the [round 9 verification](../reviews/2026-10-30-verification-round-9.md) (H-4): a comment after the `;` is not allowed on Durable Object SQL; workerd refuses the query
- Hardened: 2026-10-30, round 9 (work package `rules-6`), from the round 8 hardening list: a run-time tail refusal, tables that hold rows in the guard state, settings read with `PRAGMA` and always set back, `defer_foreign_keys` among the settings, and placeholders the compiler does not rewrite
- Hardened: 2026-10-30, round 10 (work package `core-6`), from the [round 9 verification](../reviews/2026-10-30-verification-round-9.md) hardening list: settings compared with fixed defaults instead of the values before the run (H-3)

## Context

The rule compiler checks a rule's statement in Node SQLite: `EXPLAIN` refuses writes, and since round 8 a statement tail is refused too. Node SQLite compiles only the first statement of a string. Durable Object SQL runs every statement of a query and returns the cursor of the last one. A tail the compiler misses therefore runs in production, unchecked: it can write `meta.current_scan` or `findings`, and an empty last cursor resolves every open finding of the rule.

Checked in workerd 1.20261012.1 (the vitest pool) on 2026-10-30:

- `cursor.rowsWritten` counts only the last statement. `UPDATE meta ...; SELECT ...` reports 0 although the update ran.
- `total_changes()` counts the rows of every `INSERT`, `UPDATE` and `DELETE` on the connection, whatever its position, but no schema change. `INSERT INTO t SELECT * FROM u` counts too.
- `PRAGMA query_only`, `PRAGMA schema_version`, `auto_vacuum`, `page_count` and `freelist_count` are not authorized. `sqlite_schema` can be read. So can `sqlite_sequence`; `_cf_KV`, which `sqlite_schema` lists once the storage API wrote a key, cannot.
- `BEGIN`, `COMMIT`, `SAVEPOINT`, `RELEASE`, `ROLLBACK`, `ATTACH` and temporary tables are refused inside `sql.exec`. `VACUUM` fails inside a transaction.
- A throw inside `transactionSync` rolls back rows and schema. Nested `transactionSync` calls use savepoints.
- These connection settings can be changed by a statement and keep their value after a rollback: `ignore_check_constraints`, `recursive_triggers`, `reverse_unordered_selects`, `legacy_alter_table`, `defer_foreign_keys`, and `case_sensitive_like`, which changes `LIKE` in workerd as in Node SQLite (`'a' LIKE 'A'` goes from 1 to 0). `foreign_keys` is a no-op inside a transaction. The schema declares no foreign keys, so `defer_foreign_keys` changes nothing today.
- SQLite applies such flag pragmas when the statement is prepared, not when it runs. `PRAGMA case_sensitive_like = 1` has no effect while another statement of the connection has an open cursor, and none later: it must be run again.
- `PRAGMA <name>` reads each of the five flag settings. `case_sensitive_like` has no read. A view named `pragma_legacy_alter_table` shadows the table function: `SELECT legacy_alter_table FROM pragma_legacy_alter_table` fails ("no such column") or returns what the view says. `PRAGMA legacy_alter_table` still returns the connection's value.
- `DROP TABLE` followed by the identical `CREATE TABLE` (round 9 probe, every table of the graph schema, empty and with 500 rows): `total_changes()` counts neither, nor the `sqlite_sequence` row the drop removes. The schema text and every root page in `sqlite_schema` stay the same, because the freed page is reused. The `sqlite_schema` rowid of a re-created object changes, but only because rowids grow: re-creating the objects with the highest rowids in the same order gives the same rowids. `CREATE TABLE ... AS SELECT` is not counted either; its schema text is SQLite's own (`CREATE TABLE ctas(a)`), and a renamed table's name is quoted (`CREATE TABLE "renamed" (a TEXT)`).
- workerd refuses bindings in any statement but the last ("only the last statement can have parameters"). It binds `@name`, `#name` and `:name` by position. A query with `;;`, or with a NUL, fails with "SQL code did not contain a statement". So does a comment after the last `;`, a line comment or a block comment (`SELECT 1; -- c`, `SELECT 1; /* c */`; round 9 verification, H-4). Whitespace after it runs.
- A compound `SELECT` of 8 terms is refused ("too many terms in compound SELECT"); one of 5 runs.

## Decision

Rules run through `SqlRunner.queryReadOnly`:

- Before anything runs, `assertOneStatement` refuses a query that SQLite could read as more than one statement, with `ReadOnlyError` (round 9). It does not rely on the compiler. It skips `'...'`, `"..."` and `` `...` `` (a doubled quote escapes), `[...]` (ends at the first `]`), `--` comments to a newline and block comments, and refuses anything after the first top-level `;` other than SQLite's whitespace (space, tab, newline, form feed, carriage return) and comments. Only whitespace may follow the `;` on Durable Object SQL, though: workerd refuses a query with a comment there ("SQL code did not contain a statement", see Context), so such a rule ends `error` on every run, which fails closed. Node SQLite runs it, so the fixture runs do not catch it; no committed rule ends with a `;`. Where its reading could differ from SQLite's tokenizer, it refuses: `$`, `@`, `#` and `:` outside quotes and comments (SQLite reads `$name(...)` up to the next whitespace or `)`, quotes included; the compiler turns every `:name` into `?`, and all 11 compiled rules pass), a NUL anywhere, and an unterminated quote, identifier or comment. A trigger body's `;` counts as the end of the statement, so a trigger is refused here.
- Both adapters run that check, so the fixture runs in Node catch a compiled rule it would refuse. Node SQLite, which would skip a tail, also refuses a query that SQLite's own statement boundary (`sourceSQL`) ends early.
- The query then runs in its own transaction. Before and after, the guard reads `total_changes()`, the schema as text and which tables hold a row, and it compares the settings above with fixed values: their SQLite defaults, all 0, so `'a' LIKE 'A'` is 1 (round 10, H-3). Settings are read with `PRAGMA <name>`, which a view cannot shadow, and `case_sensitive_like` through what `'a' LIKE 'A'` returns. The tables are all tables but the `_cf_` ones and SQLite's own, except `sqlite_sequence`; one statement with an `EXISTS` column per table reads them.
- A setting that is not at its default before the query, or that cannot be read, makes the call throw `ReadOnlyError` before the query runs; the guard sets the settings to their defaults first. Until round 10 the guard took the values before the run as its baseline, so a setting that stuck on the connection became the baseline of every later run, and each run set it back to the stuck value.
- On every exit (success, a failing query, a failing settings read), all six settings are set to their defaults, whatever a read says, and read again. A setting that does not hold its value makes the call throw `ReadOnlyError`.
- If rows changed (or the last statement's `rowsWritten` is above 0), the schema changed, a table that held rows holds none, a setting changed, or the settings could not be read after the query, the call throws `ReadOnlyError`, and the transaction rolls back.
- `evaluateRules` turns the throw into a run with status `error`, so no finding opens or resolves.
- The snapshot comes before the query is prepared, so a flag pragma cannot act before it.
- The compiler refuses every placeholder it does not rewrite: `@name`, `$name`, `#name`, a `:` without a name or with one that starts with a digit, and a `:name` that SQLite would read on (identifier characters, `(...)`, `::`). The error names the rule. Node SQLite binds such a variable NULL, so the rule would pass its fixtures, and Durable Object SQL refuses the bindings on every run.

## Consequences

- At run time a rule is one statement, whatever the compiler did. A tail that only reads (for example `exposure` without `requires: [access, exposure]`, R4-04), which the guard would not see, is refused before it runs. The guard is the second layer for writes, and the third with the compiler.
- What the guard state now catches: a table that held rows and is dropped and created again with the identical statement, alone or with others. It is empty afterwards, and filling it again counts in `total_changes()`. That includes the `sqlite_sequence` row of an `AUTOINCREMENT` table, which the drop removes.
- What it still does not catch: a table without rows dropped and created again identically, which loses nothing, and an index or trigger re-created identically. Neither the root page nor the `sqlite_schema` rowid is a reliable signal of a drop (see Context). A single statement cannot drop and create, so the tail refusal keeps these out too.
- The settings cannot stay changed through a shadowed read, a read that fails, or a query that fails after it changed one. A setting the guard cannot set back, for example `case_sensitive_like` while another cursor is open, ends the run `error` and stays on the connection. Every later run then ends `error` before its query runs, and sets it back once it can (H-3): a stuck setting fails closed instead of becoming the baseline.
- As the only statement, `ANALYZE` and `REINDEX` end `error`: the guard sees changed rows, and the first `ANALYZE` creates `sqlite_stat1`. As a tail they passed before round 9; the tail refusal now stops them. The compiler refuses them anyway.
- Setting `case_sensitive_like` back replaces SQLite's `LIKE` function on every run, which expires the connection's prepared statements; they are prepared again on their next use.
- 28 small extra statements per rule run: the state and the tables that hold rows twice each, the six settings read three times and set once. A scan runs 11 rules. The tables are one `EXISTS` column each, so SQLite's column limit bounds their number, far above today's 16.
- A later platform change can add settings or ways to write. Re-check the list on a workerd upgrade with the probes in `apps/core/test/rules-runtime.test.ts`.
