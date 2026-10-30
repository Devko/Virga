import { assertAccountId } from "./scan/ids.ts";
import { STALE_SCAN_MS } from "./scan/policy.ts";
import type { ScanIndex, ScanRunEnd, ScanRunStart, ScanSummary } from "./scan/types.ts";
import { type Untrusted, untrusted } from "./untrusted.ts";

/** Access to the account index D1 database (migrations/). */

const HOUR_MS = 60 * 60 * 1000;

export const PROFILES = ["inventory", "workload"] as const;
export type Profile = (typeof PROFILES)[number];

export interface AccountRow {
  id: string;
  /** Display name chosen at onboarding. */
  name: Untrusted<string>;
  /**
   * `removing`: a removal began and has not finished, for example because
   * the graph could not be deleted yet. The account stays listed until
   * Admin.removeAccount finishes, and no scan of it begins (R5-08).
   */
  status: "active" | "paused" | "removing";
  cadenceHours: number;
  profile: Profile;
  createdAt: number;
  lastScanAt: number | null;
}

export interface ScanRunRow {
  id: string;
  accountId: string;
  startedAt: number;
  finishedAt: number | null;
  status: "running" | "complete" | "partial" | "failed";
  /** Written when the scan finishes. `detail` fields quote API errors. */
  summary: Untrusted<ScanSummary> | null;
}

interface AccountRecord {
  id: string;
  name: string;
  status: "active" | "paused";
  cadence_hours: number;
  profile: Profile;
  created_at: number;
  last_scan_at: number | null;
  removing_at: number | null;
}

interface ScanRunRecord {
  id: string;
  account_id: string;
  started_at: number;
  finished_at: number | null;
  status: ScanRunRow["status"];
  summary: string | null;
}

const accountRow = (r: AccountRecord): AccountRow => ({
  id: r.id,
  name: untrusted(r.name),
  status: r.removing_at === null ? r.status : "removing",
  cadenceHours: r.cadence_hours,
  profile: r.profile,
  createdAt: r.created_at,
  lastScanAt: r.last_scan_at,
});

const scanRunRow = (r: ScanRunRecord): ScanRunRow => ({
  id: r.id,
  accountId: r.account_id,
  startedAt: r.started_at,
  finishedAt: r.finished_at,
  status: r.status,
  summary: r.summary === null ? null : untrusted(JSON.parse(r.summary)),
});

export function d1ScanIndex(db: D1Database): ScanIndex {
  return {
    async hasAccount(accountId: string) {
      const row = await db
        .prepare("SELECT 1 FROM accounts WHERE id = ? AND removing_at IS NULL")
        .bind(accountId)
        .first();
      return row !== null;
    },

    async beginRun(run: ScanRunStart) {
      // A scan that began while its account was being removed gets no row (R4-03, R5-08).
      await db
        .prepare(
          `INSERT INTO scan_runs (id, account_id, started_at, status)
           SELECT ?, ?, ?, 'running'
           WHERE EXISTS (SELECT 1 FROM accounts WHERE id = ? AND removing_at IS NULL)
           ON CONFLICT (id) DO NOTHING`,
        )
        .bind(run.id, run.accountId, run.startedAt, run.accountId)
        .run();
    },

    async finishRun(run: ScanRunEnd) {
      await db.batch([
        // Only a running row, which beginRun wrote: a scan instance that runs
        // again after it ended (R2-07) keeps the first result, and a removed
        // account gets no row back.
        db
          .prepare(
            `UPDATE scan_runs SET finished_at = ?, status = ?, summary = ?
             WHERE id = ? AND account_id = ? AND status = 'running'`,
          )
          .bind(run.finishedAt, run.status, JSON.stringify(run.summary), run.id, run.accountId),
        // Never move last_scan_at back, e.g. when an older instance finishes late.
        db
          .prepare(
            `UPDATE accounts SET last_scan_at = ?
             WHERE id = ? AND (last_scan_at IS NULL OR last_scan_at < ?)`,
          )
          .bind(run.startedAt, run.accountId, run.startedAt),
      ]);
    },
  };
}

/**
 * Active accounts whose next scan is due at `at`, in ID order after `after`.
 * Due means at least `cadence_hours` full hours since the start of the last
 * finished scan, counted in UTC hour slots so an hourly account is not
 * skipped when its scan ends later in the hour. Accounts with a scan still
 * running (and not stale), and accounts being removed, are left out.
 */
export async function dueAccounts(
  db: D1Database,
  at: number,
  options: { after?: string; limit: number },
): Promise<string[]> {
  const hour = Math.floor(at / HOUR_MS);
  const { results } = await db
    .prepare(
      `SELECT a.id FROM accounts a
       WHERE a.status = 'active' AND a.removing_at IS NULL AND a.id > ?
         AND (a.last_scan_at IS NULL OR ? - a.last_scan_at / ${HOUR_MS} >= a.cadence_hours)
         AND NOT EXISTS (
           SELECT 1 FROM scan_runs r
           WHERE r.account_id = a.id AND r.status = 'running' AND r.started_at > ?)
       ORDER BY a.id LIMIT ?`,
    )
    .bind(options.after ?? "", hour, at - STALE_SCAN_MS, options.limit)
    .all<{ id: string }>();
  return results.map((r) => r.id);
}

/** Accounts one list returns at most. */
export const MAX_ACCOUNTS = 1000;

/** Every account in the index, by name, then ID; at most MAX_ACCOUNTS. */
export async function listAccounts(db: D1Database): Promise<AccountRow[]> {
  const { results } = await db
    .prepare("SELECT * FROM accounts ORDER BY name, id LIMIT ?")
    .bind(MAX_ACCOUNTS)
    .all<AccountRecord>();
  return results.map(accountRow);
}

export async function getAccount(db: D1Database, id: string): Promise<AccountRow | null> {
  const row = await db
    .prepare("SELECT * FROM accounts WHERE id = ?")
    .bind(id)
    .first<AccountRecord>();
  return row ? accountRow(row) : null;
}

export async function latestRun(db: D1Database, accountId: string): Promise<ScanRunRow | null> {
  const row = await db
    .prepare(
      "SELECT * FROM scan_runs WHERE account_id = ? ORDER BY started_at DESC, id DESC LIMIT 1",
    )
    .bind(accountId)
    .first<ScanRunRecord>();
  return row ? scanRunRow(row) : null;
}

/** The running scan of an account, if one is running and not stale. */
export async function runningScan(
  db: D1Database,
  accountId: string,
  at: number,
): Promise<string | null> {
  const row = await db
    .prepare(
      `SELECT id FROM scan_runs WHERE account_id = ? AND status = 'running' AND started_at > ?
       ORDER BY started_at DESC LIMIT 1`,
    )
    .bind(accountId, at - STALE_SCAN_MS)
    .first<{ id: string }>();
  return row?.id ?? null;
}

export interface NewAccount {
  id: string;
  name: string;
  /** Default 24 (D-09). */
  cadenceHours?: number;
  /** Default `inventory`. Must match the profile of the token stored in the broker. */
  profile?: Profile;
}

const MAX_NAME = 200;
// Control characters, including line breaks, have no place in a display name.
const hasControl = (s: string) =>
  [...s].some((c) => {
    const code = c.codePointAt(0) ?? 0;
    return code < 0x20 || (code >= 0x7f && code <= 0x9f);
  });

function checkNewAccount(input: NewAccount): Required<NewAccount> {
  assertAccountId(input?.id);
  const name = typeof input.name === "string" ? input.name.trim() : "";
  if (name === "" || name.length > MAX_NAME || hasControl(name)) {
    throw new TypeError(`name must be 1 to ${MAX_NAME} printable characters`);
  }
  const cadenceHours = input.cadenceHours ?? 24;
  if (!Number.isInteger(cadenceHours) || cadenceHours < 1 || cadenceHours > 720) {
    throw new RangeError("cadenceHours must be an integer from 1 to 720");
  }
  const profile = input.profile ?? "inventory";
  if (!PROFILES.includes(profile)) throw new TypeError("invalid profile");
  return { id: input.id, name, cadenceHours, profile };
}

/**
 * Marks the account as being removed, the first step of Admin.removeAccount.
 * A repeat keeps the first time. Returns whether the account is in the index.
 */
export async function markRemoving(db: D1Database, id: string, at: number): Promise<boolean> {
  assertAccountId(id);
  const row = await db
    .prepare("UPDATE accounts SET removing_at = coalesce(removing_at, ?) WHERE id = ? RETURNING id")
    .bind(at, id)
    .first();
  return row !== null;
}

/**
 * Deletes an account and its scan runs, the last step of Admin.removeAccount.
 * Returns whether the account was in the index.
 */
export async function deleteAccount(db: D1Database, id: string): Promise<boolean> {
  assertAccountId(id);
  const [, account] = await db.batch([
    db.prepare("DELETE FROM scan_runs WHERE account_id = ?").bind(id),
    db.prepare("DELETE FROM accounts WHERE id = ?").bind(id),
  ]);
  return (account?.meta.changes ?? 0) > 0;
}

/**
 * Adds an account, or updates name, cadence and profile of an existing one.
 * An account being removed stays `removing`.
 */
export async function upsertAccount(
  db: D1Database,
  input: NewAccount,
  at: number,
): Promise<AccountRow> {
  const a = checkNewAccount(input);
  const row = await db
    .prepare(
      `INSERT INTO accounts (id, name, status, cadence_hours, profile, created_at)
       VALUES (?, ?, 'active', ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET name = excluded.name,
         cadence_hours = excluded.cadence_hours, profile = excluded.profile
       RETURNING *`,
    )
    .bind(a.id, a.name, a.cadenceHours, a.profile, at)
    .first<AccountRecord>();
  if (!row) throw new Error("account upsert returned no row");
  return accountRow(row);
}
