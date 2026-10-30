# @virga/broker

The credential broker: the only Worker that holds Cloudflare API tokens. It has no routes, `workers.dev` and preview URLs are off, and the default `fetch` handler answers 404. Other Workers reach it through service bindings to two entrypoints.

## Entrypoints

`ApiCaller` implements `BrokerApi` from `@virga/cf-api` and is bound to the core Worker:

- `get(accountId, path, query)` sends `GET https://api.cloudflare.com/client/v4<path>` with the account's token.
- `graphql(accountId, query, variables)` sends `POST /graphql`.

It refuses, without calling Cloudflare, every call that is not on the read allowlist (`isAllowedRead`), a path scoped to another account (`accountOfPath`), an invalid account ID or query parameter, and a GraphQL document that contains a mutation or subscription. API errors come back as `CfResponse` values, not exceptions, so the status survives the RPC boundary. Callers type the binding as `BrokerApi` and wrap it with `brokerTransport`.

`TokenIntake` is bound to the web Worker:

- `store(accountId, token, profile)` runs the write check and stores the token if it passes.
- `recheck(accountId)` runs the write check on the stored token. A token that fails is deleted; one whose check could not finish (429, 5xx) is kept.
- `remove(accountId)` deletes the token, then clears the account's rate budget (`RateBudget.clear()`, which deletes the object's storage). It returns `{ removed }`, true when a token was stored; it is idempotent and throws on failure, so a retry finishes the job.

Results list the reasons and warnings and never contain the token.

| Code | Status | Meaning |
| --- | --- | --- |
| 99001 (`NOT_ALLOWED_CODE`) | 400 | Refused by the allowlist or an input check |
| 99002 | 429 | Rate budget exhausted; not sent to Cloudflare. `retryAfter` is set |
| 99003 | 401 | No token stored for the account |
| 99004 | 500, 502 | Broker error, Cloudflare unreachable, or a response that is not a v4 envelope |

## Write check

Both calls go through the same path as every other read (allowlist, account check, rate budget):

1. `GET /accounts/{account_id}/tokens/verify`: the status must be `active`; it returns the token ID.
2. `GET /accounts/{account_id}/tokens/{token_id}`: the policies. The token needs Account API Tokens Read for this.

A token is rejected if any permission group of an allow policy is not a read group, if it has no expiry or expires more than 90 days ahead, if it is expired, disabled or not yet valid, if no allow policy names `com.cloudflare.api.account.<account_id>`, or if a policy names any resource other than this account or a single zone. Read groups are names ending in ` Read`, `Read-Only` or ` Metadata Read`, plus the two Security Center Insights groups. Names containing Write, Edit, Admin, Editor, Revoke or Purge, and every other name, are rejected (fail closed). Deny policies are ignored. For the inventory profile, groups that read code or data (D-14) produce a warning.

Global API Keys (`cfk_`), user tokens (`cfut_`) and Wrangler OAuth tokens (`cfoat_`) are refused before any call.

## Vault

The D1 database `virga-vault` is bound only to this Worker (D-08) and holds one row per account. Each token gets a random AES-256-GCM data key, and the data key is wrapped with the master key (AES-256-GCM, Web Crypto). Associated data binds the token ciphertext to the account and token ID, and the wrapped key also to the master key version, so a row moved to another account or relabelled with another version does not decrypt.

## Master key (D-15)

The key is 32 random bytes, base64 (`openssl rand -base64 32`).

- Default: Secrets Store. Create the secret with `wrangler secrets-store secret create <STORE_ID> --name virga-master-key --scopes workers --remote` and set `store_id` in `wrangler.jsonc`.
- Fallback: remove the `secrets_store_secrets` entry and run `wrangler secret put MASTER_KEY`.

When the Secrets Store binding exists, it is the only source, and its errors fail the call. A fallback on failure could wrap new data keys with a different key.

`MASTER_KEY_VERSION` names the version of the configured key. To rotate, run `rotateMasterKey(db, old, new)` from `src/vault.ts` with both keys, then deploy the new key with the new version. It unwraps every row before it writes anything, leaves token ciphertexts unchanged, and can run again after an interruption. Rows are readable only with the key of their version, so calls fail between the rewrap and the deploy. No entrypoint runs a rotation yet.

## Rate budget

`RateBudget` is a Durable Object per account (S-02). REST: 1,200 requests per 300 s, 120 kept as margin. GraphQL: 300 queries per 300 s, 30 kept as margin, and each query also uses REST quota. The budget counts its own requests in a sliding window and also trusts the last `Ratelimit` header (`"default";r=1199;t=1`) until its reset. It paces the last quarter of the quota over the time until it refills, and after a 429 it blocks until `retry-after` (300 s if missing). `ApiCaller` waits out pauses of up to 5 s and answers longer ones with a 429 `CfResponse` that carries `retryAfter`.

`clear()` is for offboarding (`TokenIntake.remove`). It deletes the object's storage and starts an empty ledger, so a request still in flight, or the account onboarded again, starts like a new account.

## Tests

`pnpm --filter @virga/broker test` runs the tests in workerd with `@cloudflare/vitest-plugin`. The main Worker shares the test isolate, so tests replace the global `fetch` with a mock that serves fixtures built from the API reference. Nothing goes to the network. Setup applies the D1 migrations and seeds the local Secrets Store.
