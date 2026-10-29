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
  /** Runs one statement and discards rows. */
  run(sql: string, ...params: SqlValue[]): void;
  /** Runs several statements without parameters, for DDL. */
  script(sql: string): void;
  /** Runs `fn` atomically. */
  transaction<T>(fn: () => T): T;
}

/** Structural subset of `DurableObjectStorage` used by the adapter. */
export interface DurableObjectStorageLike {
  sql: {
    exec(query: string, ...bindings: unknown[]): { toArray(): unknown[] };
  };
  transactionSync<T>(closure: () => T): T;
}

/** Adapts Durable Object storage to {@link SqlRunner}. */
export function fromDurableObjectStorage(storage: DurableObjectStorageLike): SqlRunner {
  return {
    query: <T extends Row>(sql: string, ...params: SqlValue[]) =>
      storage.sql.exec(sql, ...params).toArray() as T[],
    run: (sql, ...params) => {
      storage.sql.exec(sql, ...params);
    },
    script: (sql) => {
      storage.sql.exec(sql);
    },
    transaction: (fn) => storage.transactionSync(fn),
  };
}
