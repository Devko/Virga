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
  checkedAt: number;
  createdAt: number;
  updatedAt: number;
}

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
  createdAt: row.created_at,
  updatedAt: row.updated_at,
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
         checked_at = excluded.checked_at, updated_at = excluded.updated_at`,
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

/** Records a passed recheck. */
export async function markChecked(
  db: D1Database,
  accountId: string,
  expiresOn: string | null,
  now: number,
): Promise<void> {
  await db
    .prepare(
      "UPDATE vault_tokens SET expires_on = ?, checked_at = ?, updated_at = ? WHERE account_id = ?",
    )
    .bind(expiresOn, now, now, accountId)
    .run();
}

export async function deleteToken(db: D1Database, accountId: string): Promise<boolean> {
  const result = await db
    .prepare("DELETE FROM vault_tokens WHERE account_id = ?")
    .bind(accountId)
    .run();
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
