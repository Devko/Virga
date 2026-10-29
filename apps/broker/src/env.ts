/**
 * Bindings of the broker. `wrangler types` sees only what wrangler.jsonc
 * declares; the fallback secret MASTER_KEY (D-15) is set with
 * `wrangler secret put` and only when the Secrets Store binding is removed.
 */
export interface BrokerEnv extends Omit<Env, "MASTER_KEY_STORE" | "MASTER_KEY_VERSION"> {
  MASTER_KEY_STORE?: SecretsStoreSecret;
  MASTER_KEY?: string;
  MASTER_KEY_VERSION?: string;
}
