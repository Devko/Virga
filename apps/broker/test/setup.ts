import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, vi } from "vitest";
import { TEST_MASTER_KEY } from "./helpers.ts";

await applyD1Migrations(env.VAULT, env.TEST_MIGRATIONS);

// The local Secrets Store starts empty in every test file. Miniflare's secret
// binding has the admin API that `wrangler secrets-store secret create` uses
// locally; a deployed binding has no such method.
type LocalSecret = {
  "SecretsStoreSecret::admin_api"(): { create(value: string): Promise<string> };
};
const secret = env.MASTER_KEY_STORE as unknown as LocalSecret;
await secret["SecretsStoreSecret::admin_api"]().create(TEST_MASTER_KEY);

afterEach(() => {
  vi.restoreAllMocks();
});
