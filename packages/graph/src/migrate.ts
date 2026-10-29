import { MIGRATIONS, type Migration } from "./schema.ts";
import type { SqlRunner } from "./sql.ts";

/** Returns the schema version of the database, 0 for an empty one. */
export function schemaVersion(db: SqlRunner): number {
  const table = db.query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'");
  if (table.length === 0) return 0;
  const row = db.query<{ value: string }>("SELECT value FROM meta WHERE key = 'schema_version'")[0];
  return row ? Number(row.value) : 0;
}

/** Applies all pending migrations, each in its own transaction. Returns the new version. */
export function migrate(db: SqlRunner, migrations: readonly Migration[] = MIGRATIONS): number {
  let version = schemaVersion(db);
  for (const migration of migrations) {
    if (migration.version <= version) continue;
    db.transaction(() => {
      db.script(migration.sql);
      db.run(
        `INSERT INTO meta (key, value) VALUES ('schema_version', ?)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
        String(migration.version),
      );
    });
    version = migration.version;
  }
  return version;
}
