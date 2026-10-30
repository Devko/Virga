import { DatabaseSync } from "node:sqlite";
import type { Row, SqlRunner, SqlValue } from "./sql.ts";

export interface NodeSqlRunner extends SqlRunner {
  /** Output column names of a statement, without running it. */
  columns(sql: string): string[];
  /**
   * What follows the first statement of `sql`, from the first character that
   * is not whitespace or a comment; empty when nothing else follows that
   * statement and its `;`. Node SQLite compiles only the first statement,
   * while Durable Object SQL runs every one (R6-02).
   */
  tail(sql: string): string;
  close(): void;
}

/**
 * Whitespace and comments as SQLite's tokenizer skips them. Stricter where
 * that is simpler: an unterminated block comment or a NUL is left as tail.
 */
const BLANK = /^(?:[ \t\n\f\r]+|--[^\n\0]*|\/\*[^\0]*?\*\/)*/;

/** Opens a Node SQLite database as a {@link SqlRunner}. For tests and the rule compiler. */
export function openNodeDatabase(path = ":memory:"): NodeSqlRunner {
  const db = new DatabaseSync(path);
  let depth = 0;
  const tail = (sql: string) => {
    // sourceSQL is the input up to the end of the first statement, its `;` included.
    const first = db.prepare(sql).sourceSQL;
    if (!sql.startsWith(first)) return sql;
    const rest = sql.slice(first.length);
    return rest.slice(BLANK.exec(rest)?.[0].length ?? 0);
  };
  return {
    query: <T extends Row>(sql: string, ...params: SqlValue[]) =>
      db.prepare(sql).all(...(params as never[])) as T[],
    run: (sql, ...params) => {
      db.prepare(sql).run(...(params as never[]));
    },
    script: (sql) => db.exec(sql),
    transaction: (fn) => {
      if (depth > 0) return fn();
      depth++;
      db.exec("BEGIN");
      try {
        const result = fn();
        db.exec("COMMIT");
        return result;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      } finally {
        depth--;
      }
    },
    columns: (sql) =>
      db
        .prepare(sql)
        .columns()
        .map((c) => c.name),
    tail,
    close: () => db.close(),
  };
}
