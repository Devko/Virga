/**
 * Envelope encryption for the vault. Each token gets a random AES-256-GCM
 * data key; the data key is wrapped (AES-256-GCM) with the master key.
 * Associated data binds both ciphertexts to the account and token ID, and the
 * wrapped key also to the master key version, so a row copied to another
 * account or relabelled with another key version does not decrypt.
 */

const LABEL = "virga-vault-v1";
const IV_BYTES = 12;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export interface MasterKey {
  version: number;
  key: CryptoKey;
}

export interface SealedToken {
  keyVersion: number;
  keyIv: Uint8Array<ArrayBuffer>;
  wrappedKey: Uint8Array<ArrayBuffer>;
  tokenIv: Uint8Array<ArrayBuffer>;
  tokenCiphertext: Uint8Array<ArrayBuffer>;
}

/** A vault failure. Messages are fixed strings and never contain key or token material. */
export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultError";
  }
}

const tokenAad = (accountId: string, tokenId: string) =>
  encoder.encode(JSON.stringify([LABEL, "token", accountId, tokenId]));

const keyAad = (accountId: string, tokenId: string, keyVersion: number) =>
  encoder.encode(JSON.stringify([LABEL, "data-key", accountId, tokenId, keyVersion]));

const randomIv = () => crypto.getRandomValues(new Uint8Array(IV_BYTES));

function decodeBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Imports a master key given as 32 random bytes in base64. */
export async function importMasterKey(base64: string, version: number): Promise<MasterKey> {
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new VaultError("master key version must be a positive integer");
  }
  let raw: Uint8Array<ArrayBuffer>;
  try {
    raw = decodeBase64(base64.trim());
  } catch {
    throw new VaultError("master key is not valid base64");
  }
  if (raw.length !== 32) throw new VaultError("master key must be 32 bytes");
  const key = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
    "wrapKey",
    "unwrapKey",
  ]);
  raw.fill(0);
  return { version, key };
}

export async function sealToken(
  master: MasterKey,
  accountId: string,
  tokenId: string,
  token: string,
): Promise<SealedToken> {
  const dataKey = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ])) as CryptoKey;
  const tokenIv = randomIv();
  const tokenCiphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: tokenIv, additionalData: tokenAad(accountId, tokenId) },
      dataKey,
      encoder.encode(token),
    ),
  );
  const keyIv = randomIv();
  const wrappedKey = new Uint8Array(
    await crypto.subtle.wrapKey("raw", dataKey, master.key, {
      name: "AES-GCM",
      iv: keyIv,
      additionalData: keyAad(accountId, tokenId, master.version),
    }),
  );
  return { keyVersion: master.version, keyIv, wrappedKey, tokenIv, tokenCiphertext };
}

async function unwrapDataKey(
  master: MasterKey,
  accountId: string,
  tokenId: string,
  sealed: SealedToken,
  extractable: boolean,
): Promise<CryptoKey> {
  if (sealed.keyVersion !== master.version) {
    throw new VaultError(
      `data key is wrapped with master key version ${sealed.keyVersion}, not ${master.version}`,
    );
  }
  try {
    return await crypto.subtle.unwrapKey(
      "raw",
      sealed.wrappedKey,
      master.key,
      {
        name: "AES-GCM",
        iv: sealed.keyIv,
        additionalData: keyAad(accountId, tokenId, sealed.keyVersion),
      },
      { name: "AES-GCM" },
      extractable,
      ["encrypt", "decrypt"],
    );
  } catch {
    throw new VaultError("data key does not unwrap: wrong master key or tampered row");
  }
}

export async function openToken(
  master: MasterKey,
  accountId: string,
  tokenId: string,
  sealed: SealedToken,
): Promise<string> {
  const dataKey = await unwrapDataKey(master, accountId, tokenId, sealed, false);
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: sealed.tokenIv, additionalData: tokenAad(accountId, tokenId) },
      dataKey,
      sealed.tokenCiphertext,
    );
    return decoder.decode(plain);
  } catch {
    throw new VaultError("token does not decrypt: tampered row");
  }
}

/** Wraps the data key with another master key. The token ciphertext stays as it is. */
export async function rewrapToken(
  from: MasterKey,
  to: MasterKey,
  accountId: string,
  tokenId: string,
  sealed: SealedToken,
): Promise<SealedToken> {
  const dataKey = await unwrapDataKey(from, accountId, tokenId, sealed, true);
  const keyIv = randomIv();
  const wrappedKey = new Uint8Array(
    await crypto.subtle.wrapKey("raw", dataKey, to.key, {
      name: "AES-GCM",
      iv: keyIv,
      additionalData: keyAad(accountId, tokenId, to.version),
    }),
  );
  return { ...sealed, keyVersion: to.version, keyIv, wrappedKey };
}
