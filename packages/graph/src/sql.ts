/** Values that can be bound to a statement or returned in a row. */
export type SqlValue = string | number | null | ArrayBuffer;

export type Row = Record<string, SqlValue>;

/**
 * Minimal synchronous SQL interface shared by Durable Object storage and
 * Node's built-in SQLite. Statements use positional `?` parameters only,
 * because that is all Durable Object SQL documents.
 */
export interface SqlRunner {
  /** Runs one statement and returns all rows. */
  query<T extends Row = Row>(sql: string, ...params: SqlValue[]): T[];
  /**
   * Runs one statement that may only read, in its own transaction, and
   * returns all rows. A statement that changed rows, the schema or a
   * connection setting throws {@link ReadOnlyError}; its changes are rolled
   * back and the setting is set back (R6-02).
   */
  queryReadOnly<T extends Row = Row>(sql: string, ...params: SqlValue[]): T[];
  /** Runs one statement and discards rows. */
  run(sql: string, ...params: SqlValue[]): void;
  /** Runs several statements without parameters, for DDL. */
  script(sql: string): void;
  /** Runs `fn` atomically. */
  transaction<T>(fn: () => T): T;
}

/** A read-only query changed the database or the connection; nothing of it was kept. */
export class ReadOnlyError extends Error {}

/** A statement's rows, and the rows its last statement wrote where the runtime counts them. */
export interface Executed {
  rows: Row[];
  rowsWritten: number;
}

/**
 * Connection settings a statement can change for the statements after it.
 * A rollback keeps them. `case_sensitive_like` cannot be read, so its value
 * is what LIKE does.
 */
const SETTINGS = `json_object(
  'ignore_check_constraints', (SELECT ignore_check_constraints FROM pragma_ignore_check_constraints),
  'recursive_triggers', (SELECT recursive_triggers FROM pragma_recursive_triggers),
  'reverse_unordered_selects', (SELECT reverse_unordered_selects FROM pragma_reverse_unordered_selects),
  'legacy_alter_table', (SELECT legacy_alter_table FROM pragma_legacy_alter_table),
  'case_sensitive_like', NOT ('a' LIKE 'A'))`;

/**
 * What a read must leave as it was. total_changes() counts the rows of every
 * INSERT, UPDATE and DELETE on the connection, in any position of a query
 * and inside triggers; schema changes do not count there, so the schema is
 * compared as text.
 */
const STATE = `SELECT total_changes() AS changes,
  (SELECT group_concat(type || ' ' || name || ' ' || ifnull(sql, ''), char(10))
   FROM (SELECT type, name, sql FROM sqlite_schema ORDER BY type, name)) AS schema,
  ${SETTINGS} AS settings`;

interface State extends Row {
  changes: number;
  schema: string | null;
  settings: string;
}

/** Sets back every setting that differs from `before`, and returns their names. */
function restoreSettings(db: Pick<SqlRunner, "query" | "run">, before: State): string[] {
  const was = JSON.parse(before.settings) as Record<string, number>;
  const now = JSON.parse(
    db.query<{ settings: string }>(`SELECT ${SETTINGS} AS settings`)[0]?.settings ?? "{}",
  ) as Record<string, number>;
  const changed = Object.keys(was).filter((name) => now[name] !== was[name]);
  // Names come from SETTINGS, values are 0 or 1.
  for (const name of changed) db.run(`PRAGMA ${name} = ${was[name] ? 1 : 0}`);
  return changed;
}

/**
 * Runs `exec` as {@link SqlRunner.queryReadOnly} does: in a transaction of
 * `db`, comparing the database's row changes, schema and connection
 * settings before and after. For the adapters.
 */
export function guardRead(
  db: Pick<SqlRunner, "query" | "run" | "transaction">,
  exec: () => Executed,
): Row[] {
  return db.transaction(() => {
    const before = db.query<State>(STATE)[0] as State;
    let executed: Executed;
    try {
      executed = exec();
    } catch (error) {
      // A setting changed before the failing statement survives the rollback.
      restoreSettings(db, before);
      throw error;
    }
    const settings = restoreSettings(db, before);
    const after = db.query<State>(STATE)[0] as State;
    const changed = [
      ...(executed.rowsWritten > 0 || after.changes !== before.changes ? ["rows"] : []),
      ...(after.schema !== before.schema ? ["the schema"] : []),
      ...settings.map((name) => `the setting ${name}`),
    ];
    if (changed.length > 0) {
      throw new ReadOnlyError(
        `a read-only query changed ${changed.join(", ")}; the change was rolled back`,
      );
    }
    return executed.rows;
  });
}

/** Structural subset of `DurableObjectStorage` used by the adapter. */
export interface DurableObjectStorageLike {
  sql: {
    exec(
      query: string,
      ...bindings: unknown[]
    ): { toArray(): unknown[]; readonly rowsWritten: number };
  };
  transactionSync<T>(closure: () => T): T;
}

/** Adapts Durable Object storage to {@link SqlRunner}. */
export function fromDurableObjectStorage(storage: DurableObjectStorageLike): SqlRunner {
  const db: SqlRunner = {
    query: <T extends Row>(sql: string, ...params: SqlValue[]) =>
      storage.sql.exec(sql, ...params).toArray() as T[],
    // Durable Object SQL runs every statement of `sql` and returns the cursor
    // of the last one, whose rowsWritten counts only that statement.
    queryReadOnly: <T extends Row>(sql: string, ...params: SqlValue[]) =>
      guardRead(db, () => {
        const cursor = storage.sql.exec(sql, ...params);
        const rows = cursor.toArray() as Row[];
        return { rows, rowsWritten: cursor.rowsWritten };
      }) as T[],
    run: (sql, ...params) => {
      storage.sql.exec(sql, ...params);
    },
    script: (sql) => {
      storage.sql.exec(sql);
    },
    transaction: (fn) => storage.transactionSync(fn),
  };
  return db;
}
