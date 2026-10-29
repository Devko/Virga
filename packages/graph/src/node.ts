import { DatabaseSync } from "node:sqlite";
import type { Row, SqlRunner, SqlValue } from "./sql.ts";

export interface NodeSqlRunner extends SqlRunner {
  /** Output column names of a statement, without running it. */
  columns(sql: string): string[];
  close(): void;
}

/** Opens a Node SQLite database as a {@link SqlRunner}. For tests and the rule compiler. */
export function openNodeDatabase(path = ":memory:"): NodeSqlRunner {
  const db = new DatabaseSync(path);
  let depth = 0;
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
    close: () => db.close(),
  };
}
