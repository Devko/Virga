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

/**
 * A read-only query was refused before it ran, or changed the database or
 * the connection; nothing of it was kept.
 */
export class ReadOnlyError extends Error {}

/** SQLite's whitespace: its tokenizer skips nothing else, not even a vertical tab. */
const BLANK = new Set([" ", "\t", "\n", "\f", "\r"]);

/** Signs that start a named variable in SQLite. */
const VARIABLE = new Set(["$", "@", "#", ":"]);

/**
 * Refuses, with {@link ReadOnlyError}, a query that SQLite could read as more
 * than one statement. Durable Object SQL runs every statement of a query, so
 * a read is checked before anything runs, independently of the rule
 * compiler (R6-02, round 9).
 *
 * It skips '...', "..." and `...` (a doubled quote escapes), [...] (ends at
 * the first ]), -- comments to a newline and block comments. Anything after
 * the first `;` other than SQLite's whitespace and comments is a tail. Where
 * its reading could differ from SQLite's, it refuses:
 * - `$`, `@`, `#` and `:` outside quotes and comments. SQLite reads
 *   `$name(...)` up to the next whitespace or `)`, quotes included. The
 *   compiler turns every `:name` into `?`, so a compiled rule holds none.
 * - A NUL anywhere, where SQLite stops reading.
 * - An unterminated quote, identifier or comment.
 */
export function assertOneStatement(sql: string): void {
  const refuse = (what: string): never => {
    throw new ReadOnlyError(`a read-only query holds ${what}; it was not run`);
  };
  if (sql.includes("\0")) refuse("a NUL");
  let ended = false;
  let i = 0;
  while (i < sql.length) {
    const c = sql[i] as string;
    let end = -1;
    if (c === "-" && sql[i + 1] === "-") {
      const newline = sql.indexOf("\n", i + 2);
      end = newline === -1 ? sql.length : newline;
    } else if (c === "/" && sql[i + 1] === "*") {
      const close = sql.indexOf("*/", i + 2);
      if (close === -1) refuse("an unterminated comment");
      end = close + 2;
    } else if (ended && !BLANK.has(c)) {
      refuse("text after its first statement");
    } else if (c === "'" || c === '"' || c === "`") {
      end = quoteEnd(sql, i, c);
      if (end === -1) refuse(`an unterminated ${c} quote`);
    } else if (c === "[") {
      const close = sql.indexOf("]", i + 1);
      if (close === -1) refuse("an unterminated [ identifier");
      end = close + 1;
    } else if (VARIABLE.has(c)) {
      refuse(`a named variable (${c})`);
    } else {
      if (c === ";") ended = true;
      end = i + 1;
    }
    i = end;
  }
}

/** The index after the quote that closes the one at `start`, or -1. */
function quoteEnd(sql: string, start: number, quote: string): number {
  let i = start + 1;
  while (i < sql.length) {
    if (sql[i] === quote) {
      if (sql[i + 1] !== quote) return i + 1;
      i++;
    }
    i++;
  }
  return -1;
}

/** A statement's rows, and the rows its last statement wrote where the runtime counts them. */
export interface Executed {
  rows: Row[];
  rowsWritten: number;
}

/**
 * Connection settings a statement can change for the statements after it. A
 * rollback keeps them, `defer_foreign_keys` too (workerd 1.20261012.1). Each
 * is read with its PRAGMA statement: a view named like the table function
 * pragma_<name> makes a read through the function fail or lie, but not this.
 */
const FLAGS = [
  "ignore_check_constraints",
  "recursive_triggers",
  "reverse_unordered_selects",
  "legacy_alter_table",
  "defer_foreign_keys",
] as const;

/** Setting names and their values, 0 or 1. */
type Settings = Record<string, number>;

/**
 * Reads the settings. `case_sensitive_like` has no read, so its value is
 * what LIKE does. Throws if a value is not 0 or 1.
 */
function readSettings(db: Pick<SqlRunner, "query">): Settings {
  const settings: Settings = {};
  for (const name of FLAGS) settings[name] = db.query(`PRAGMA ${name}`)[0]?.[name] as number;
  const like = db.query("SELECT 'a' LIKE 'A' AS ci")[0]?.ci;
  settings.case_sensitive_like = like === 0 ? 1 : like === 1 ? 0 : Number.NaN;
  for (const [name, value] of Object.entries(settings)) {
    if (value !== 0 && value !== 1) throw new Error(`the setting ${name} reads ${String(value)}`);
  }
  return settings;
}

/** The names of the settings that differ from `before`, all of them if they cannot be read. */
function changedSettings(db: Pick<SqlRunner, "query">, before: Settings): string[] {
  let now: Settings;
  try {
    now = readSettings(db);
  } catch {
    return Object.keys(before);
  }
  return Object.keys(before).filter((name) => now[name] !== before[name]);
}

/**
 * Sets every setting to its value in `before`, whatever a read says, and
 * checks that it holds. Throws {@link ReadOnlyError} naming each setting
 * that could not be set back.
 */
function setBack(db: Pick<SqlRunner, "query" | "run">, before: Settings): void {
  for (const [name, value] of Object.entries(before)) {
    try {
      // Names come from FLAGS and case_sensitive_like, values are 0 or 1.
      db.run(`PRAGMA ${name} = ${value ? 1 : 0}`);
    } catch {
      // The check below names it.
    }
  }
  const stuck = changedSettings(db, before);
  if (stuck.length > 0) {
    const names = stuck.map((name) => `the setting ${name}`).join(", ");
    throw new ReadOnlyError(`a read-only query changed ${names}, which could not be set back`);
  }
}

/**
 * Tables whose rows a read must keep: all but the platform's `_cf_` tables,
 * which cannot be read, and SQLite's own, except sqlite_sequence.
 */
const TABLES = `SELECT name FROM sqlite_schema WHERE type = 'table'
  AND substr(name, 1, 4) <> '_cf_'
  AND (substr(name, 1, 7) <> 'sqlite_' OR name = 'sqlite_sequence')
  ORDER BY name`;

/**
 * What a read must leave as it was. total_changes() counts the rows of every
 * INSERT, UPDATE and DELETE on the connection, in any position of a query
 * and inside triggers; schema changes do not count there, so the schema is
 * compared as text.
 *
 * Neither sees a table dropped and created again by the same statement: the
 * drop is not counted, and the text, root page and all stay the same
 * (workerd 1.20261012.1). The table is empty afterwards, and filling it
 * again counts, so the guard also compares which tables hold rows.
 */
const STATE = `SELECT total_changes() AS changes,
  (SELECT group_concat(type || ' ' || name || ' ' || ifnull(sql, ''), char(10))
   FROM (SELECT type, name, sql FROM sqlite_schema ORDER BY type, name)) AS schema,
  (SELECT json_group_array(name) FROM (${TABLES})) AS tables`;

interface State extends Row {
  changes: number;
  schema: string | null;
  tables: string;
}

/**
 * The tables of `names` that hold a row, in one statement with a column per
 * table: Durable Object SQL refuses a UNION ALL of 16 terms.
 */
function filled(db: Pick<SqlRunner, "query">, names: readonly string[]): string[] {
  if (names.length === 0) return [];
  const columns = names.map(
    (name, i) => `EXISTS (SELECT 1 FROM "${name.replaceAll('"', '""')}") AS t${i}`,
  );
  const row = db.query(`SELECT ${columns.join(", ")}`)[0] ?? {};
  return names.filter((_, i) => row[`t${i}`] === 1);
}

/**
 * Runs `exec` as {@link SqlRunner.queryReadOnly} does: in a transaction of
 * `db`, comparing the database's row changes, schema, tables that hold rows
 * and connection settings before and after, and setting every setting back.
 * For the adapters, which refuse a statement tail before they call it.
 */
export function guardRead(
  db: Pick<SqlRunner, "query" | "run" | "transaction">,
  exec: () => Executed,
): Row[] {
  return db.transaction(() => {
    const before = db.query<State>(STATE)[0] as State;
    const held = filled(db, JSON.parse(before.tables) as string[]);
    const settings = readSettings(db);
    let executed: Executed;
    let changedNames: string[];
    try {
      executed = exec();
      changedNames = changedSettings(db, settings);
    } finally {
      // On every exit, whatever a read said: a rollback keeps a setting, a
      // statement can change one before a later one fails, and a read can
      // fail or, through a shadowed pragma_ function, lie.
      setBack(db, settings);
    }
    const after = db.query<State>(STATE)[0] as State;
    const schemaChanged = after.schema !== before.schema;
    const changed = [
      ...(executed.rowsWritten > 0 || after.changes !== before.changes ? ["rows"] : []),
      ...(schemaChanged ? ["the schema"] : []),
      ...changedNames.map((name) => `the setting ${name}`),
    ];
    // With the schema as it was, every table of `held` can still be read.
    const kept = schemaChanged ? held : filled(db, held);
    const emptied = held.filter((name) => !kept.includes(name));
    const what = [
      ...(changed.length > 0 ? [`changed ${changed.join(", ")}`] : []),
      ...(emptied.length > 0 ? [`emptied ${emptied.join(", ")}`] : []),
    ];
    if (what.length > 0) {
      throw new ReadOnlyError(
        `a read-only query ${what.join(" and ")}; the change was rolled back`,
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
    // of the last one, whose rowsWritten counts only that statement. So a
    // tail is refused before anything runs, and the guard checks the rest.
    queryReadOnly: <T extends Row>(sql: string, ...params: SqlValue[]) => {
      assertOneStatement(sql);
      return guardRead(db, () => {
        const cursor = storage.sql.exec(sql, ...params);
        const rows = cursor.toArray() as Row[];
        return { rows, rowsWritten: cursor.rowsWritten };
      }) as T[];
    },
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
