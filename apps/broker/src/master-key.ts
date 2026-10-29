import { importMasterKey, type MasterKey, VaultError } from "./crypto.ts";

export interface MasterKeySource {
  MASTER_KEY_STORE?: { get(): Promise<string> };
  MASTER_KEY?: string;
  MASTER_KEY_VERSION?: string;
}

const cache = new WeakMap<object, Promise<MasterKey>>();

/**
 * Loads the master key (D-15). The Secrets Store binding wins whenever it is
 * bound, and its errors propagate: falling back on a store failure could
 * silently wrap new data keys with a different key. MASTER_KEY is read only
 * when the binding is absent.
 */
export function loadMasterKey(env: MasterKeySource): Promise<MasterKey> {
  let pending = cache.get(env);
  if (!pending) {
    pending = readMasterKey(env);
    pending.catch(() => cache.delete(env));
    cache.set(env, pending);
  }
  return pending;
}

async function readMasterKey(env: MasterKeySource): Promise<MasterKey> {
  const version = Number(env.MASTER_KEY_VERSION ?? "1");
  if (env.MASTER_KEY_STORE) {
    let value: string;
    try {
      value = await env.MASTER_KEY_STORE.get();
    } catch {
      throw new VaultError("master key is not readable from Secrets Store");
    }
    return importMasterKey(value, version);
  }
  if (env.MASTER_KEY) return importMasterKey(env.MASTER_KEY, version);
  throw new VaultError("no master key configured: bind MASTER_KEY_STORE or set MASTER_KEY");
}
