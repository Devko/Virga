import {
  type MasterKey,
  openToken,
  rewrapToken,
  type SealedToken,
  sealToken,
  VaultError,
} from "./crypto.ts";

export const TOKEN_PROFILES = ["inventory", "workload"] as const;
export type TokenProfile = (typeof TOKEN_PROFILES)[number];

/** Vault metadata of one account. Never contains the token. */
export interface VaultEntry {
  accountId: string;
  tokenId: string;
  profile: TokenProfile;
  keyVersion: number;
  expiresOn: string | null;
  /** When the token last passed the write check, at onboarding or a recheck. */
  checkedAt: number;
  /** A call runs a recheck of the token until this time (TM-04), or null. */
  recheckUntil: number | null;
  createdAt: number;
  updatedAt: number;
  /**
   * The token's ciphertext, which tells this stored token apart from any
   * other. Every store seals the token with a fresh data key and IV, so a
   * token stored again, even the same secret under the same token ID, gets
   * another ciphertext; a master key rotation rewraps only the data key and
   * keeps it. A recheck matches the row on it (`SeenToken`).
   */
  ciphertext: Uint8Array<ArrayBuffer>;
}

/**
 * The token a recheck read: its ID and its ciphertext. `claimRecheck`,
 * `markChecked` and `deleteToken` act on the row only while it still holds
 * this token, so a token stored meanwhile, even under the same token ID, is
 * neither claimed, marked as checked nor deleted for the old one.
 */
export type SeenToken = Pick<VaultEntry, "tokenId" | "ciphertext">;

interface Row {
  account_id: string;
  token_id: string;
  profile: TokenProfile;
  key_version: number;
  key_iv: number[];
  wrapped_key: number[];
  token_iv: number[];
  token_ciphertext: number[];
  expires_on: string | null;
  checked_at: number;
  recheck_until: number | null;
  created_at: number;
  updated_at: number;
}

const entryOf = (row: Row): VaultEntry => ({
  accountId: row.account_id,
  tokenId: row.token_id,
  profile: row.profile,
  keyVersion: row.key_version,
  expiresOn: row.expires_on,
  checkedAt: row.checked_at,
  recheckUntil: row.recheck_until ?? null,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  ciphertext: new Uint8Array(row.token_ciphertext),
});

// D1 returns BLOB columns as arrays of numbers.
const sealedOf = (row: Row): SealedToken => ({
  keyVersion: row.key_version,
  keyIv: new Uint8Array(row.key_iv),
  wrappedKey: new Uint8Array(row.wrapped_key),
  tokenIv: new Uint8Array(row.token_iv),
  tokenCiphertext: new Uint8Array(row.token_ciphertext),
});

export interface PutToken {
  accountId: string;
  tokenId: string;
  profile: TokenProfile;
  token: string;
  expiresOn: string | null;
  now: number;
}

/** Stores the token of an account, replacing an earlier one with a fresh data key. */
export async function putToken(db: D1Database, master: MasterKey, entry: PutToken): Promise<void> {
  const sealed = await sealToken(master, entry.accountId, entry.tokenId, entry.token);
  await db
    .prepare(
      `INSERT INTO vault_tokens (account_id, token_id, profile, key_version, key_iv, wrapped_key,
         token_iv, token_ciphertext, expires_on, checked_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (account_id) DO UPDATE SET
         token_id = excluded.token_id, profile = excluded.profile,
         key_version = excluded.key_version, key_iv = excluded.key_iv,
         wrapped_key = excluded.wrapped_key, token_iv = excluded.token_iv,
         token_ciphertext = excluded.token_ciphertext, expires_on = excluded.expires_on,
         checked_at = excluded.checked_at, recheck_until = NULL,
         updated_at = excluded.updated_at`,
    )
    .bind(
      entry.accountId,
      entry.tokenId,
      entry.profile,
      sealed.keyVersion,
      sealed.keyIv,
      sealed.wrappedKey,
      sealed.tokenIv,
      sealed.tokenCiphertext,
      entry.expiresOn,
      entry.now,
      entry.now,
      entry.now,
    )
    .run();
}

export async function getEntry(db: D1Database, accountId: string): Promise<VaultEntry | null> {
  const row = await db
    .prepare("SELECT * FROM vault_tokens WHERE account_id = ?")
    .bind(accountId)
    .first<Row>();
  return row ? entryOf(row) : null;
}

/** Decrypts the token of an account, or returns null if none is stored. */
export async function getToken(
  db: D1Database,
  master: MasterKey,
  accountId: string,
): Promise<{ entry: VaultEntry; token: string } | null> {
  const row = await db
    .prepare("SELECT * FROM vault_tokens WHERE account_id = ?")
    .bind(accountId)
    .first<Row>();
  if (!row) return null;
  if (row.account_id !== accountId) throw new VaultError("vault row does not match the account");
  const token = await openToken(master, row.account_id, row.token_id, sealedOf(row));
  return { entry: entryOf(row), token };
}

/**
 * Claims the recheck of a token for one call (TM-04). It succeeds only while
 * the row still holds the token (`SeenToken`) and check time the caller saw,
 * and no other claim runs. A claim lapses at `until`, so a call that dies does
 * not block the account.
 */
export async function claimRecheck(
  db: D1Database,
  seen: VaultEntry,
  now: number,
  until: number,
): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE vault_tokens SET recheck_until = ?
       WHERE account_id = ? AND token_id = ? AND token_ciphertext = ? AND checked_at = ?
         AND (recheck_until IS NULL OR recheck_until <= ?)`,
    )
    .bind(until, seen.accountId, seen.tokenId, seen.ciphertext, seen.checkedAt, now)
    .run();
  return result.meta.changes > 0;
}

/** Ends a claim from claimRecheck. A newer claim is left alone. */
export async function releaseRecheck(
  db: D1Database,
  accountId: string,
  until: number,
): Promise<void> {
  await db
    .prepare(
      "UPDATE vault_tokens SET recheck_until = NULL WHERE account_id = ? AND recheck_until = ?",
    )
    .bind(accountId, until)
    .run();
}

/**
 * Records a passed recheck of the token `seen`, and ends any claim. Only
 * while the row still holds that token: one stored meanwhile keeps its own
 * check time and expiry. Returns whether the row was updated.
 */
export async function markChecked(
  db: D1Database,
  accountId: string,
  seen: SeenToken,
  expiresOn: string | null,
  now: number,
): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE vault_tokens SET expires_on = ?, checked_at = ?, recheck_until = NULL, updated_at = ?
       WHERE account_id = ? AND token_id = ? AND token_ciphertext = ?`,
    )
    .bind(expiresOn, now, now, accountId, seen.tokenId, seen.ciphertext)
    .run();
  return result.meta.changes > 0;
}

/**
 * Deletes the token of an account. With `seen`, only while the row still
 * holds that token, so a failed recheck does not delete a token stored
 * meanwhile, even under the same token ID.
 */
export async function deleteToken(
  db: D1Database,
  accountId: string,
  seen?: SeenToken,
): Promise<boolean> {
  const statement =
    seen === undefined
      ? db.prepare("DELETE FROM vault_tokens WHERE account_id = ?").bind(accountId)
      : db
          .prepare(
            "DELETE FROM vault_tokens WHERE account_id = ? AND token_id = ? AND token_ciphertext = ?",
          )
          .bind(accountId, seen.tokenId, seen.ciphertext);
  const result = await statement.run();
  return result.meta.changes > 0;
}

const ROTATE_CHUNK = 50;

/**
 * Rewraps every data key wrapped with `from` under `to`. All rows are
 * unwrapped before anything is written, so a wrong `from` key changes
 * nothing. Updates are guarded by the old wrapped key, so a token replaced
 * meanwhile is not overwritten. Safe to run again after an interruption.
 */
export async function rotateMasterKey(
  db: D1Database,
  from: MasterKey,
  to: MasterKey,
): Promise<{ rotated: number }> {
  if (from.version === to.version) {
    throw new VaultError("the new master key needs a new version");
  }
  const { results } = await db
    .prepare("SELECT * FROM vault_tokens WHERE key_version = ? ORDER BY account_id")
    .bind(from.version)
    .all<Row>();
  const updates: D1PreparedStatement[] = [];
  for (const row of results) {
    const old = sealedOf(row);
    const next = await rewrapToken(from, to, row.account_id, row.token_id, old);
    updates.push(
      db
        .prepare(
          `UPDATE vault_tokens SET key_version = ?, key_iv = ?, wrapped_key = ?
           WHERE account_id = ? AND key_version = ? AND wrapped_key = ?`,
        )
        .bind(
          next.keyVersion,
          next.keyIv,
          next.wrappedKey,
          row.account_id,
          from.version,
          old.wrappedKey,
        ),
    );
  }
  let rotated = 0;
  for (let i = 0; i < updates.length; i += ROTATE_CHUNK) {
    const done = await db.batch(updates.slice(i, i + ROTATE_CHUNK));
    rotated += done.reduce((n, r) => n + r.meta.changes, 0);
  }
  return { rotated };
}
