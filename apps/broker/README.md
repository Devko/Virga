# @virga/broker

The credential broker: the only Worker that holds Cloudflare API tokens. It has no routes, `workers.dev` and preview URLs are off, and the default `fetch` handler answers 404. Other Workers reach it through service bindings to two entrypoints.

## Entrypoints

`ApiCaller` implements `BrokerApi` from `@virga/cf-api` and is bound to the core Worker:

- `get(accountId, path, query)` sends `GET https://api.cloudflare.com/client/v4<path>` with the account's token.
- `graphql(accountId, query, variables)` sends `POST /graphql`.

Before it uses a token whose last passed write check is 24 hours old, it runs the check again ([below](#recheck-before-use-tm-04)). It refuses, without calling Cloudflare, every call that is not on the read allowlist (`isAllowedRead`), a path scoped to another account (`accountOfPath`), an invalid account ID or query parameter, and a GraphQL document that contains a mutation or subscription. API errors come back as `CfResponse` values, not exceptions, so the status survives the RPC boundary. Callers type the binding as `BrokerApi` and wrap it with `brokerTransport`.

`TokenIntake` is bound to the web Worker:

- `store(accountId, token, profile)` runs the write check and stores the token if it passes.
- `recheck(accountId)` runs the write check on the stored token, as `ApiCaller` does before use. A token that fails is deleted; one whose check got no answer (429, 5xx, no connection, no v4 envelope) is kept. Nothing calls it yet.
- `remove(accountId)` deletes the token, then clears the account's rate budget (`RateBudget.clear()`, which deletes the object's storage). It returns `{ removed }`, true when a token was stored; it is idempotent and throws on failure, so a retry finishes the job.

Results list the reasons and warnings and never contain the token.

| Code | Status | Meaning |
| --- | --- | --- |
| 99001 (`NOT_ALLOWED_CODE`) | 400 | Refused by the allowlist or an input check |
| 99002 | 429 | Rate budget exhausted; not sent to Cloudflare. `retryAfter` is set |
| 99003 | 401 | No token stored for the account |
| 99004 | 500, 502 | Broker error, Cloudflare unreachable, or a response that is not a v4 envelope |
| 99005 | 401 | The stored token failed its recheck before use and was deleted (TM-04) |
| 99006 | 503, 429 | The recheck before use got no answer, or another call's recheck is still running; the token is kept and the call was not sent. `retryAfter` is set on 429 |

## Write check

It runs at onboarding (`store`), on request (`recheck`) and before use ([below](#recheck-before-use-tm-04)), in `src/token-check.ts`. Both calls go through the same path as every other read (allowlist, account check, rate budget):

1. `GET /accounts/{account_id}/tokens/verify`: the status must be `active`; it returns the token ID.
2. `GET /accounts/{account_id}/tokens/{token_id}`: the policies. The token needs Account API Tokens Read for this.

A token is rejected if any permission group of an allow policy is not a read group, if it has no expiry or expires more than 90 days ahead, if it is expired, disabled or not yet valid, if no allow policy names `com.cloudflare.api.account.<account_id>`, or if a policy names any resource other than this account or a single zone. Read groups are names ending in ` Read`, `Read-Only` or ` Metadata Read`, plus the two Security Center Insights groups. Names containing Write, Edit, Admin, Editor, Revoke or Purge, and every other name, are rejected (fail closed). Deny policies are ignored. For the inventory profile, groups that read code or data (D-14) produce a warning.

Global API Keys (`cfk_`), user tokens (`cfut_`) and Wrangler OAuth tokens (`cfoat_`) are refused before any call.

## Recheck before use (TM-04)

A token's policies can be widened after onboarding. `ApiCaller` therefore runs the write check again before it uses a token whose last passed check is old (`usableToken` in `src/token-check.ts`).

- **When.** `checked_at` is set when `store` or a recheck passes. A call rechecks the token first when `now - checked_at >= 24 h`, or when `checked_at` lies more than a minute ahead of the clock (a bad row or clock fails safe). A token in daily use is rechecked once a day; one idle for longer is rechecked at its next use.
- **One at a time.** The call that finds the token due claims the vault row (`recheck_until`, migration `0002_recheck_claim.sql`) with a conditional update, which succeeds only while the row holds the token (see **Which token**) and check time that call read and no other claim runs. Other calls of the account read the row again every 200 ms for up to 10 s: they are served once the check passed, answer 401 (99003) once the token is gone, and fail closed with 503 (99006) if the recheck still runs. A claim lapses after 30 s, so a call that dies does not block the account.
- **Same calls.** The recheck is the onboarding check: the same two reads through the same path, so the allowlist, the account check and the rate budget apply to them. It costs two REST requests per account and day.
- **Passed:** the check time and the expiry are recorded, only while the row still holds the token that was checked, the claim ends, and the call is served.
- **Failed**, for any reason onboarding refuses (a write or unknown group, no expiry or one more than 90 days ahead, expired, disabled or revoked, without Account API Tokens Read, a resource of another account, another token ID): the token is deleted, only while the row still holds that token, so a token stored meanwhile stays, under the same token ID too. The call answers 401 with 99005 and up to three reasons; the reader turns it into `NoPermissionError`, which core records as `no_permission` without retries, so the class is not complete and its rules stay `not evaluated`. Later calls answer 401 with 99003 until the account is onboarded again. The broker logs the account ID and the reason codes.
- **Which token.** The claim, the record of a pass and the deletion match the row on the account, the token ID and the token's ciphertext as the recheck read them (`SeenToken` in `src/vault.ts`). A rolled token keeps its ID, so the ID alone would let the old secret's recheck delete the new token, or record its pass and expiry on it. Every store seals the token with a fresh data key and IV, so a token stored again gets another ciphertext, even the same secret under the same ID; a master key rotation rewraps only the data key, so a recheck that runs across a rotation still acts on its token. The check time is not enough: `TokenIntake.recheck` takes no claim, so a pass recorded meanwhile changes it and a failed recheck would leave the failing token stored with a fresh check time; and two stores in one millisecond get the same one. No migration is needed.
- **No answer** (no connection, a 5xx, a 429 from Cloudflare or from the rate budget, a body that is not a v4 envelope): the token, its check time and its expiry stay as they were, and the call fails closed with 99006 without being sent: 429 with `retryAfter` after a rate limit, 503 otherwise. The next call tries again.

**Why an unanswered check fails closed.** The broker cannot tell core "served, but the token is unchecked", so serving would let a class end `complete` while the token's permissions are unknown. Failing keeps unknown a result: core retries the step (after `retryAfter` on a 429, with backoff otherwise) and then records `error`, so the class is not complete and its rules stay `not evaluated`. Serving would also let a token whose check never gets an answer be used, unchecked, until it expires. The cost is small: the check reads the same API as the scan, so an outage that stops the check mostly stops the scan too, and a rate limit refuses the call anyway. The token stays stored, so the next scan recovers without the operator.

**Limits.** A token is rechecked only when a call uses it; there is no scheduled recheck. An idle token stays in the vault unchecked until its next use or its expiry (90 days at most). Between two rechecks a widened token is used for up to 24 hours. Both are bounded by the allowlist, which sends only reads.

## Vault

The D1 database `virga-vault` is bound only to this Worker (D-08) and holds one row per account: the sealed token, its token ID, profile and expiry, the time of its last passed check, and the claim of a running recheck. Each token gets a random AES-256-GCM data key, and the data key is wrapped with the master key (AES-256-GCM, Web Crypto). Associated data binds the token ciphertext to the account and token ID, and the wrapped key also to the master key version, so a row moved to another account or relabelled with another version does not decrypt.

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

`pnpm --filter @virga/broker test` runs the tests in workerd with `@cloudflare/vitest-plugin`. The main Worker shares the test isolate, so tests replace the global `fetch` with a mock that serves fixtures built from the API reference. Nothing goes to the network. Setup applies the D1 migrations and seeds the local Secrets Store. `test/recheck.test.ts` covers the recheck before use (TM-04).
