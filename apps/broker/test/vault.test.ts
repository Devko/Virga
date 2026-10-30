import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import { importMasterKey, openToken, rewrapToken, sealToken, VaultError } from "../src/crypto.ts";
import { loadMasterKey } from "../src/master-key.ts";
import {
  claimRecheck,
  deleteToken,
  getEntry,
  getToken,
  markChecked,
  putToken,
  releaseRecheck,
  rotateMasterKey,
} from "../src/vault.ts";
import { ACCOUNT_ID, OTHER_ACCOUNT_ID, TOKEN_ID } from "./fixtures/tokens.ts";
import { NEXT_MASTER_KEY, TEST_MASTER_KEY, TEST_TOKEN } from "./helpers.ts";

const contains = (haystack: Uint8Array, needle: Uint8Array) => {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
};

describe("envelope encryption", () => {
  it("round-trips a token", async () => {
    const master = await importMasterKey(TEST_MASTER_KEY, 1);
    const sealed = await sealToken(master, ACCOUNT_ID, TOKEN_ID, TEST_TOKEN);
    expect(await openToken(master, ACCOUNT_ID, TOKEN_ID, sealed)).toBe(TEST_TOKEN);
    expect(contains(sealed.tokenCiphertext, new TextEncoder().encode(TEST_TOKEN))).toBe(false);
  });

  it("uses a fresh data key and IVs per token", async () => {
    const master = await importMasterKey(TEST_MASTER_KEY, 1);
    const a = await sealToken(master, ACCOUNT_ID, TOKEN_ID, TEST_TOKEN);
    const b = await sealToken(master, ACCOUNT_ID, TOKEN_ID, TEST_TOKEN);
    expect(a.wrappedKey).not.toEqual(b.wrappedKey);
    expect(a.tokenCiphertext).not.toEqual(b.tokenCiphertext);
    expect(a.keyIv).not.toEqual(b.keyIv);
  });

  it("binds the ciphertext to account, token ID and key version", async () => {
    const master = await importMasterKey(TEST_MASTER_KEY, 1);
    const sealed = await sealToken(master, ACCOUNT_ID, TOKEN_ID, TEST_TOKEN);
    await expect(openToken(master, OTHER_ACCOUNT_ID, TOKEN_ID, sealed)).rejects.toThrow(VaultError);
    await expect(openToken(master, ACCOUNT_ID, "0".repeat(32), sealed)).rejects.toThrow(VaultError);
    const relabelled = await importMasterKey(TEST_MASTER_KEY, 2);
    await expect(
      openToken(relabelled, ACCOUNT_ID, TOKEN_ID, { ...sealed, keyVersion: 2 }),
    ).rejects.toThrow(VaultError);
    const other = await importMasterKey(NEXT_MASTER_KEY, 1);
    await expect(openToken(other, ACCOUNT_ID, TOKEN_ID, sealed)).rejects.toThrow(VaultError);
  });

  it("rewraps the data key without touching the token ciphertext", async () => {
    const v1 = await importMasterKey(TEST_MASTER_KEY, 1);
    const v2 = await importMasterKey(NEXT_MASTER_KEY, 2);
    const sealed = await sealToken(v1, ACCOUNT_ID, TOKEN_ID, TEST_TOKEN);
    const rewrapped = await rewrapToken(v1, v2, ACCOUNT_ID, TOKEN_ID, sealed);
    expect(rewrapped.keyVersion).toBe(2);
    expect(rewrapped.tokenCiphertext).toEqual(sealed.tokenCiphertext);
    expect(await openToken(v2, ACCOUNT_ID, TOKEN_ID, rewrapped)).toBe(TEST_TOKEN);
    await expect(openToken(v1, ACCOUNT_ID, TOKEN_ID, rewrapped)).rejects.toThrow(VaultError);
  });

  it("accepts only 32-byte base64 master keys and never echoes them", async () => {
    const short = btoa("too short");
    for (const bad of [short, "not base64!", ""]) {
      const error = await importMasterKey(bad, 1).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(VaultError);
      expect(String(error)).not.toContain(bad || "\u0000");
    }
    await expect(importMasterKey(TEST_MASTER_KEY, 0)).rejects.toThrow(VaultError);
  });
});

describe("master key source (D-15)", () => {
  it("uses the Secrets Store binding", async () => {
    const master = await loadMasterKey(env);
    const sealed = await sealToken(master, ACCOUNT_ID, TOKEN_ID, TEST_TOKEN);
    const expected = await importMasterKey(TEST_MASTER_KEY, 1);
    expect(await openToken(expected, ACCOUNT_ID, TOKEN_ID, sealed)).toBe(TEST_TOKEN);
  });

  it("falls back to MASTER_KEY only when the store is not bound", async () => {
    const fallback = await loadMasterKey({ MASTER_KEY: NEXT_MASTER_KEY, MASTER_KEY_VERSION: "3" });
    expect(fallback.version).toBe(3);
    const failing = {
      MASTER_KEY_STORE: { get: () => Promise.reject(new Error("store down")) },
      MASTER_KEY: NEXT_MASTER_KEY,
    };
    await expect(loadMasterKey(failing)).rejects.toThrow("not readable from Secrets Store");
    await expect(loadMasterKey({})).rejects.toThrow("no master key configured");
  });
});

describe("vault in D1", () => {
  beforeEach(async () => {
    await env.VAULT.exec("DELETE FROM vault_tokens");
  });

  const store = async (accountId: string, key = TEST_MASTER_KEY, version = 1) =>
    putToken(env.VAULT, await importMasterKey(key, version), {
      accountId,
      tokenId: TOKEN_ID,
      profile: "inventory",
      token: `${TEST_TOKEN}${accountId.slice(0, 4)}`,
      expiresOn: "2026-12-01T00:00:00Z",
      now: 1_000,
    });

  it("keeps one row per account and stores no plaintext", async () => {
    await store(ACCOUNT_ID);
    await store(ACCOUNT_ID);
    const { results } = await env.VAULT.prepare("SELECT * FROM vault_tokens").all();
    expect(results).toHaveLength(1);
    expect(JSON.stringify(results)).not.toContain(TEST_TOKEN);
    const row = results[0] as { token_ciphertext: number[] };
    const plain = new TextEncoder().encode(TEST_TOKEN);
    expect(contains(new Uint8Array(row.token_ciphertext), plain)).toBe(false);
    const entry = await getEntry(env.VAULT, ACCOUNT_ID);
    expect(entry).toMatchObject({ accountId: ACCOUNT_ID, tokenId: TOKEN_ID, keyVersion: 1 });
    expect(JSON.stringify(entry)).not.toContain(TEST_TOKEN);
  });

  it("does not decrypt a row moved to another account", async () => {
    await store(ACCOUNT_ID);
    await env.VAULT.prepare("UPDATE vault_tokens SET account_id = ?").bind(OTHER_ACCOUNT_ID).run();
    const master = await importMasterKey(TEST_MASTER_KEY, 1);
    await expect(getToken(env.VAULT, master, OTHER_ACCOUNT_ID)).rejects.toThrow(VaultError);
  });

  it("deletes a token", async () => {
    await store(ACCOUNT_ID);
    expect(await deleteToken(env.VAULT, ACCOUNT_ID)).toBe(true);
    expect(await deleteToken(env.VAULT, ACCOUNT_ID)).toBe(false);
    expect(await getEntry(env.VAULT, ACCOUNT_ID)).toBeNull();
  });

  const entryOf = async (accountId: string) => {
    const entry = await getEntry(env.VAULT, accountId);
    if (!entry) throw new Error(`no entry for ${accountId}`);
    return entry;
  };

  it("TM-04: gives the recheck claim to one caller until it lapses", async () => {
    await store(ACCOUNT_ID);
    const seen = await entryOf(ACCOUNT_ID);
    expect(seen.recheckUntil).toBeNull();
    expect(await claimRecheck(env.VAULT, seen, 2_000, 5_000)).toBe(true);
    expect(await claimRecheck(env.VAULT, seen, 2_000, 5_000)).toBe(false);
    expect(await claimRecheck(env.VAULT, seen, 4_999, 9_000)).toBe(false);
    expect((await entryOf(ACCOUNT_ID)).recheckUntil).toBe(5_000);
    // The claim lapses, so a call that died does not block the account.
    expect(await claimRecheck(env.VAULT, seen, 5_000, 9_000)).toBe(true);
    // The first caller's release leaves the second claim alone.
    await releaseRecheck(env.VAULT, ACCOUNT_ID, 5_000);
    expect((await entryOf(ACCOUNT_ID)).recheckUntil).toBe(9_000);
    await releaseRecheck(env.VAULT, ACCOUNT_ID, 9_000);
    expect((await entryOf(ACCOUNT_ID)).recheckUntil).toBeNull();
  });

  it("TM-04: does not claim a token that was checked again or replaced", async () => {
    await store(ACCOUNT_ID);
    const seen = await entryOf(ACCOUNT_ID);
    await markChecked(env.VAULT, ACCOUNT_ID, seen, "2026-12-15T00:00:00Z", 3_000);
    expect(await claimRecheck(env.VAULT, seen, 4_000, 9_000)).toBe(false);
    const checked = await entryOf(ACCOUNT_ID);
    expect(checked).toMatchObject({ checkedAt: 3_000, expiresOn: "2026-12-15T00:00:00Z" });
    const replaced = { ...checked, tokenId: "0".repeat(32) };
    expect(await claimRecheck(env.VAULT, replaced, 4_000, 9_000)).toBe(false);
    expect(await claimRecheck(env.VAULT, checked, 4_000, 9_000)).toBe(true);
    // A passed check clears the claim, and so does storing a token.
    await markChecked(env.VAULT, ACCOUNT_ID, checked, null, 6_000);
    expect((await entryOf(ACCOUNT_ID)).recheckUntil).toBeNull();
    expect(await claimRecheck(env.VAULT, await entryOf(ACCOUNT_ID), 7_000, 9_000)).toBe(true);
    await store(ACCOUNT_ID);
    expect((await entryOf(ACCOUNT_ID)).recheckUntil).toBeNull();
  });

  it("TM-04: leaves a replaced token alone when given the old token ID", async () => {
    await store(ACCOUNT_ID);
    const seen = await entryOf(ACCOUNT_ID);
    const other = { ...seen, tokenId: "0".repeat(32) };
    expect(await markChecked(env.VAULT, ACCOUNT_ID, other, null, 5_000)).toBe(false);
    expect((await entryOf(ACCOUNT_ID)).checkedAt).toBe(1_000);
    expect(await deleteToken(env.VAULT, ACCOUNT_ID, other)).toBe(false);
    expect(await getEntry(env.VAULT, ACCOUNT_ID)).not.toBeNull();
    expect(await deleteToken(env.VAULT, ACCOUNT_ID, seen)).toBe(true);
    expect(await getEntry(env.VAULT, ACCOUNT_ID)).toBeNull();
  });

  it("R10 hardening: broker same token ID: a token stored again is not claimed, marked or deleted for the old one", async () => {
    await store(ACCOUNT_ID);
    const seen = await entryOf(ACCOUNT_ID);
    // Stored again under the same token ID, here even with the same check time.
    await store(ACCOUNT_ID);
    const again = await entryOf(ACCOUNT_ID);
    expect(again).toMatchObject({ tokenId: seen.tokenId, checkedAt: seen.checkedAt });
    expect(again.ciphertext).not.toEqual(seen.ciphertext);
    expect(await claimRecheck(env.VAULT, seen, 2_000, 5_000)).toBe(false);
    expect(await markChecked(env.VAULT, ACCOUNT_ID, seen, null, 3_000)).toBe(false);
    expect(await deleteToken(env.VAULT, ACCOUNT_ID, seen)).toBe(false);
    expect(await entryOf(ACCOUNT_ID)).toEqual(again);
    // The token that is stored is matched.
    expect(await claimRecheck(env.VAULT, again, 2_000, 5_000)).toBe(true);
    expect(await markChecked(env.VAULT, ACCOUNT_ID, again, null, 3_000)).toBe(true);
    expect(await entryOf(ACCOUNT_ID)).toMatchObject({ checkedAt: 3_000, recheckUntil: null });
    expect(await deleteToken(env.VAULT, ACCOUNT_ID, again)).toBe(true);
  });

  it("R10 hardening: broker same token ID: a master key rotation keeps the match", async () => {
    await store(ACCOUNT_ID);
    const seen = await entryOf(ACCOUNT_ID);
    const v1 = await importMasterKey(TEST_MASTER_KEY, 1);
    const v2 = await importMasterKey(NEXT_MASTER_KEY, 2);
    expect(await rotateMasterKey(env.VAULT, v1, v2)).toEqual({ rotated: 1 });
    // A recheck that read the row before the rotation still acts on its token.
    expect(await claimRecheck(env.VAULT, seen, 2_000, 5_000)).toBe(true);
    expect(await markChecked(env.VAULT, ACCOUNT_ID, seen, null, 3_000)).toBe(true);
    expect(await deleteToken(env.VAULT, ACCOUNT_ID, seen)).toBe(true);
  });

  it("rotates the master key for every row", async () => {
    const accounts = [ACCOUNT_ID, OTHER_ACCOUNT_ID, "f".repeat(32)];
    for (const account of accounts) await store(account);
    const v1 = await importMasterKey(TEST_MASTER_KEY, 1);
    const v2 = await importMasterKey(NEXT_MASTER_KEY, 2);
    const before = await env.VAULT.prepare(
      "SELECT account_id, token_ciphertext FROM vault_tokens ORDER BY account_id",
    ).all();

    expect(await rotateMasterKey(env.VAULT, v1, v2)).toEqual({ rotated: 3 });

    for (const account of accounts) {
      const found = await getToken(env.VAULT, v2, account);
      expect(found?.token).toBe(`${TEST_TOKEN}${account.slice(0, 4)}`);
      expect(found?.entry.keyVersion).toBe(2);
      await expect(getToken(env.VAULT, v1, account)).rejects.toThrow(VaultError);
    }
    const after = await env.VAULT.prepare(
      "SELECT account_id, token_ciphertext FROM vault_tokens ORDER BY account_id",
    ).all();
    expect(after.results).toEqual(before.results);
    expect(await rotateMasterKey(env.VAULT, v1, v2)).toEqual({ rotated: 0 });
  });

  it("changes nothing when the old key is wrong", async () => {
    await store(ACCOUNT_ID);
    const wrong = await importMasterKey(NEXT_MASTER_KEY, 1);
    const v2 = await importMasterKey(NEXT_MASTER_KEY, 2);
    await expect(rotateMasterKey(env.VAULT, wrong, v2)).rejects.toThrow(VaultError);
    const v1 = await importMasterKey(TEST_MASTER_KEY, 1);
    expect((await getToken(env.VAULT, v1, ACCOUNT_ID))?.entry.keyVersion).toBe(1);
    await expect(rotateMasterKey(env.VAULT, v1, v1)).rejects.toThrow("new version");
  });
});
