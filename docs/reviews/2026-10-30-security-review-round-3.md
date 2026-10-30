# Security review, round 3

- Date: 2026-10-30
- Scope: what round 2 added (`apps/web`, `scripts/`, the `access-v2` and `undecided` changes), at commit d8480b1
- Status: all findings fixed in round 4 of the [work packages](../team/work-packages.md) by `fix-tunnels`, `fix-deploy` and `fix-lifecycle`; `review-4` verifies them in round 5

| Finding | Fixed by | Test |
| --- | --- | --- |
| R3-01 | `fix-tunnels` | `packages/collectors/test/identity/tunnels.test.ts` (two R3-01 tests); end to end: the R3-01 cases in `apps/core/test/e2e/account.ts`, run by `apps/core/test/e2e/scan.test.ts` |
| R3-02 | `fix-tunnels` | `packages/collectors/test/identity/tunnels.test.ts` (four R3-02 tests); `packages/exposure/test/evaluate.test.ts` (three R3-02 cases); end to end: `apps/core/test/e2e/scan.test.ts` (R3-02) and the R3-02 cases in `apps/core/test/e2e/account.ts` |
| R3-03 | `fix-deploy` | R3-03 tests in `scripts/test/config.test.ts` (configs next to and above the app), `run.test.ts` (`--config`, no named environment), `deploy.test.ts` (`CLOUDFLARE_ENV`, no `--env`), `topology.test.ts` (no `env` blocks) and `steps.test.ts` (the checked config in every Wrangler call) |
| R3-04 | `fix-deploy` | `scripts/test/steps.test.ts` (three R3-04 tests), `scripts/test/topology.test.ts` (credentials in `secrets.required`) |
| R3-05 | `fix-deploy` | `scripts/test/run.test.ts` (R3-05: builds run without any `CLOUDFLARE_` or `CF_` variable) |
| R3-06 | `fix-deploy` | `scripts/test/topology.test.ts` (one owner per `database_id`), `scripts/test/steps.test.ts` (three R3-06 tests) |
| R3-07 | `fix-lifecycle` | `packages/rules/test/evaluate.test.ts` (R3-07: an undecided row ends an expired suppression) |

Related changes:

- The last part of the R3-01 fix, which keeps a Service Auth policy for every address `public` behind `access_required`, came in round 3 with `fix-exposure` (`packages/exposure/test/evaluate.test.ts`). The [verification review](2026-10-30-verification-round-4.md) found a variant of it (R4-01).
- `fix-lifecycle` also stops a sweep from moving `current_scan` (`packages/graph/test/write.test.ts`) and caps evidence strings inside list items (`packages/rules/test/evaluate.test.ts`).

## Summary

Read-only review of the round 2 additions on branch ccr-fb16682f-xtuagp (HEAD d8480b1). No tracked files were changed. The existing suites pass: exposure 162, rules 244, collectors 178, scripts 70, web 49 (workerd and SPA).

**Main problem: the new `access_required` path in access-v2.** It gives two new kinds of false "protected" result for tunnel hostnames, and CF-004 then reports nothing:
- **F1 (high):** the collector takes the flag from the top-level `originRequest`, but cloudflared only enforces a rule's own `access` block.
- **F2 (medium):** the collector drops ingress rules that have no hostname, and requests that fall through to them reach the origin without any check.

Both were checked against cloudflared's source (`ingress/ingress.go`, `rule.go`, `config.go`, `proxy/proxy.go`) and with scratch scripts, not kept in the repository, that run the real collector, graph write path, evaluator and CF-004.

**Deploy script:** the topology checks can be bypassed because Wrangler deploys a config file the script never read (F3). There are also three low guardrail gaps (F4–F6).

**Undecided rows:** they keep an expired suppression in force for as long as the exposure stays unknown (F7).

**Checked and found sound:**
- **Access JWT check:**
  - Only RS256 and RSA keys are accepted, with `alg`/`use` filtered; `iss` is compared exactly, `aud` may be a list, and `exp`/`nbf` have 30 s skew.
  - `type` must be `app`.
  - The certs fetch uses `redirect: manual`, a 64 KiB cap and a 5 s timeout.
  - Keys are cached for 1 h, with a 30 s refetch floor; stale keys are used only when a fetch fails, and never past 24 h.
  - `ctx.access` is optional; if present, its aud must match.
- **Routing:** with `run_worker_first`, every route (assets, `/api`, `/mcp`, 404 fallback) goes through `authenticate`. Refusals are JSON 403s with the security headers.
- **Admin routes:** both admin routes check the Origin and the JSON content type (CSRF) first, then the admin email. Service tokens are never admin.
- **Headers:** CSP and the other security headers are on every response.
- **Onboarding:** the token is not logged, echoed or kept, and errors are logged by name only. Broker output is rebuilt field by field and scrubbed of the token.
- **SPA:**
  - Untrusted strings are rendered as React text only, with no `dangerouslySetInnerHTML`.
  - Links are built by the app and encoded.
  - Graph labels are canvas text.
  - The build has no inline scripts.
- **MCP:**
  - Tools are read-only, the Origin is pinned to the Worker's host, and no CORS headers are sent.
  - Output carries the notice and an `<untrusted-data>` block; `<`, `>` and `&` are escaped and the text is capped at 100k characters.
- **RPC types:** they are types plus casts only.
- **Deploy commands:** `spawn` runs without a shell and takes argument arrays, the dry run strips credentials, all output is redacted, and the secrets file is mode 0600 inside `mkdtemp` and removed afterwards.
- **Evaluator overrides:** they fail closed (non-array, missing fields, more than 100 entries or a path over 512 characters becomes `other`, which ends in `unknown`).
- **Paths:** they are kept as configured.
- **`all_workers` tiers:** they match the contract.
- **Undecided lifecycle:** findings that are open stay open, and each of the six converted rules computes `decided` per subject.

**Not re-reported:**
- R2-01 to R2-10.
- Items already planned for round 3: the `rule_runs.undecided` column (fix-core); `all_workers` and `/*` handling in CF-010, CF-011 and CF-002 (fix-rules).


## Findings

### R3-01 [high] access_required inherited from the top-level originRequest, which cloudflared does not enforce, so a tunnel hostname with no Access check is decided 'access'

Location: `packages/collectors/src/identity/tunnels.ts:89`

**Scenario**

**Input:** a remotely managed tunnel config:
- `originRequest: {access: {required: true, teamName: 'acme', audTag: ['aud1']}}`
- `ingress: [{hostname: 'ssh.example.com', service: 'ssh://localhost:22'}, {service: 'http_status:404'}]`
- no Access app on ssh.example.com

**What the code does:**
- `accessRequired()` falls back to the top-level block and stores `access_required: true`.
- `withOriginAccess` (packages/exposure/src/evaluate.ts:520) turns the decision into `/` access, confidence 1, reason "cloudflared requires an Access token".
- CF-004 is evaluated with 0 hits.

**What cloudflared does:**
- `validateIngress` builds the JWT validator only from the rule's own `r.OriginRequest.Access` (ingress.go, `if access := r.OriginRequest.Access; access != nil`).
- The top-level defaults only reach `Rule.Config`, which is used for path normalization; `proxy.applyIngressMiddleware` runs only `rule.Handlers`.
- So anyone on the internet reaches the SSH origin.

This is a false "protected" result for a critical CF-004 case. The test tunnels.test.ts:153-159 (wiki and legacy hostnames) and graph-contract.md:233 assert the same behaviour.

**Fix**

- Read `access_required` only from the rule's own `originRequest.access.required` and drop the fallback to `config.originRequest`.
- Update graph-contract.md:233 (contract first) and the collector test that asserts inheritance.
- Add an end-to-end case: top-level access only, no Access app, so CF-004 hits.
- Also limit `withOriginAccess` to `public` results where Access issues no token: no app, Bypass, or a public override. Under decision 0003, a Service Auth policy with include 0.0.0.0/0 becomes `public`, Access does issue a token for it, and the conversion would make that a false "access" too.

**How it was verified**

- **cloudflared source:** downloaded master (ingress/ingress.go, rule.go, config.go, proxy/proxy.go, orchestration/config.go) and read `validateIngress`, `RemoteConfig.UnmarshalJSON` (the top-level originRequest is passed as defaults) and `applyIngressMiddleware`.
- **End-to-end run:** scratch script tunnel-toplevel.ts runs the real tunnels collector, prepareBatch/applyBatch, evaluateExposure and evaluateRules(CF-004). It prints:
  - node access_required: true
  - exposure: `[tunnel_hostname:…:ssh.example.com, '/', 'access', 1, 'cloudflared requires an Access token…']`
  - CF-004: `{status: evaluated, hits: 0, undecided: 0}`

### R3-02 [medium] Ingress rules without a hostname are dropped, so traffic that falls through to them is counted as covered by the hostname rule's access_required

Location: `packages/collectors/src/identity/tunnels.ts:151`

**Scenario**

cloudflared uses the first matching rule, and a rule with `hostname == ""` matches every hostname (rule.go `Matches`). The collector skips every rule without a hostname, including the catch-all and non-last path-only rules.

**Case A:**
- `ingress: [{path: '^/debug', service: 'http://localhost:6060'}, {hostname: 'app.example.com', service: 'http://localhost:8080', originRequest: {access: {required: true, teamName: 'acme', audTag: ['aud1']}}}, {service: 'http_status:404'}]`
- Result: one node with access_required true and exposure `['/', 'access', 1]`; CF-004 has 0 hits.
- Reality: https://app.example.com/debug/… reaches localhost:6060 without any JWT check.

**Case B:**
- `[{hostname: 'app.example.com', path: '^/admin', service: X, access required}, {service: 'http://localhost:8080'}]`
- Result: only `/admin*` is evaluated, as access; CF-004 has 0 hits.
- Reality: every other path of app.example.com reaches the catch-all origin with no check.

Without `access_required` (the round 1 behaviour), the same host is `public` and CF-004 hits. `access_required` is what turns these into false "protected" results.

**Fix**

In `collectIngress`, keep track of rules without a hostname whose service is not `http_status:`.
- **Earlier rules:** for every hostname rule after such a rule (one with a path), set `access_required` to false, or emit the hostname-less rule as its own entry point so that it evaluates to `unknown`.
- **Catch-all:** when a hostname rule has a path and the catch-all serves an origin, emit a fall-through entry for that hostname, keyed `<tid>:<host>`, with the catch-all's service and its own access flag.
- **Contract:** add both cases to the contract's known limits until they are modelled.

**How it was verified**

- **cloudflared source:** read `Rule.Matches` (`hostMatch := r.Hostname == "" || r.Hostname == "*" || …`), `FindMatchingRule` (first match, then the last rule) and `validateHostname` (only the last rule may be a full catch-all; earlier rules may be path-only).
- **End-to-end run:** scratch script tunnel-catchall.ts runs the real collector, evaluator and CF-004.
  - Case A: node `…:app.example.com access_required=true`, exposure `['/', 'access', 1]`, CF-004 hits 0.
  - Case B: exposure `['/admin*', 'access', 1]` only, CF-004 hits 0.
  - Control (same as A without access): `['/', 'public', 2]`.

### R3-03 [medium] Deploy checks one Wrangler config, but Wrangler deploys whichever config it finds itself (parent or sibling wrangler.json, CLOUDFLARE_ENV)

Location: `scripts/lib/steps.ts:318`

**Scenario**

`checkTopology` reads `apps/<app>/wrangler.jsonc`; config.ts:60 tries wrangler.jsonc first and looks nowhere else. Every wrangler call runs with `cwd` set to the app directory and without `--config`. Wrangler 4.151.0 looks for `wrangler.json` in every directory up the tree first, then `wrangler.jsonc`, then `wrangler.toml` (cli.js:3540, `file()` walks up). It also selects a named environment from `CLOUDFLARE_ENV`, which the runner passes through; topology.ts:128 only warns when a config has `env` blocks.

**Concrete case:**
- A stray `wrangler.json` in the repo root, `apps/` or `~` contains `{name: 'virga-web', workers_dev: true, services: [{binding: 'API', service: 'virga-broker', entrypoint: 'ApiCaller'}]}`.
- `checkTopology` passes with no issues; `wrangler deploy` in apps/web uploads `env.API (virga-broker#ApiCaller)` with workers.dev on.
- That gives the internet-facing Worker the token-using entrypoint (D-06, D-08).

The same happens with a sibling `apps/web/wrangler.json`, and with an `env.prod` block plus `CLOUDFLARE_ENV=prod` set in the operator's shell.

**Fix**

- Pass `--config <absolute configPath>` to every wrangler invocation: deploy, d1 list/create/migrations, secret list, secrets-store. With `--config`, Wrangler uses that file and skips the `.wrangler/deploy` redirect.
- Remove `CLOUDFLARE_ENV` from the child environment, or pass an explicit empty `--env`.
- Make `env` blocks an error.
- Make `findConfigFile` refuse when both wrangler.json and wrangler.jsonc exist.

**How it was verified**

- **Parent wrangler.json:** built scratch script wcfg (copies of the real broker, core and web configs, plus a root wrangler.json).
  - scratch script topo.ts runs `readWorkerConfig` + `checkTopology` and prints `issues: []` and "web config checked: apps/web/wrangler.jsonc".
  - `wrangler deploy --dry-run` (apps/web/node_modules/.bin/wrangler, 4.151.0) in wcfg/apps/web prints `env.API (virga-broker#ApiCaller)`.
- **CLOUDFLARE_ENV:** in scratch script wenv, `CLOUDFLARE_ENV=prod wrangler deploy --dry-run` prints the env.prod binding to ApiCaller.
- **Wrangler code:** read `findWranglerConfig`, `file()` and `getCloudflareEnv` in wrangler-dist/cli.js.

### R3-04 [low] Deploy uploads any environment variable named in web's secrets.required, including the deploy token itself

Location: `scripts/lib/steps.ts:257`

**Scenario**

`planWebSettings` loops over `WEB_SETTINGS` plus `web.requiredSecrets` and copies each name's value from `process.env` into `plan.upload`. deploy.ts then writes that into `--secrets-file` for virga-web.

**Concrete case:**
- `"secrets": {"required": ["CLOUDFLARE_API_TOKEN"]}` is added to apps/web/wrangler.jsonc, by mistake or in a change a reviewer misses.
- A real deploy then installs the tool account's deploy token (Workers write, D1, Secrets Store read) as `env.CLOUDFLARE_API_TOKEN` in the internet-facing web Worker.
- No check or warning fires.

**Fix**

Upload only names in `WEB_SETTINGS`. For other `secrets.required` names, only check that they already exist. In any case, refuse names in `CREDENTIAL_VARS` or with a `CLOUDFLARE_`/`CF_` prefix.

**How it was verified**

scratch script plan.ts calls `parseWorkerConfig` with `secrets.required: ['CLOUDFLARE_API_TOKEN']`, then `planWebSettings(web, {CLOUDFLARE_API_TOKEN: 'cfat_…'})`. It prints `upload names: [ 'CLOUDFLARE_API_TOKEN' ]`. deploy.ts:117-118 passes `webPlan.upload` to `withSecretsFile` on a real deploy.

### R3-05 [low] Deploy token is passed to the SPA build and its whole dependency tree

Location: `scripts/lib/run.ts:74`

**Scenario**

With `credentials: 'token'` (every real deploy), `processRunner` keeps `CLOUDFLARE_API_TOKEN` for every child, including `bin: 'pnpm'`. `build()` (steps.ts:309) runs `pnpm run build`, which is `vite build` for apps/web. Any build-time package (vite, rolldown or oxc, or a future plugin) can read the token, which can redeploy the broker. The build does not need it.

**Fix**

Make credentials a per-command property. Strip all `CREDENTIAL_VARS` for `bin: 'pnpm'`, and keep the token only for the wrangler calls that reach the API.

**How it was verified**

scratch script buildenv.ts uses the real `processRunner({credentials: 'token'})` to run `pnpm exec node -e …` in apps/web. The child prints "build step sees token: 47 chars".

### R3-06 [low] D1 ownership check uses database_name, so a binding that names one database and points at the vault's UUID passes

Location: `scripts/lib/topology.ts:136`

**Scenario**

`checkTopology` decides who owns a database by `databaseName ?? databaseId`. `ensureDatabases` (steps.ts:90-95) only checks that a `database_id` exists in `d1 list`, never that its listed name matches `database_name`. Wrangler binds by `database_id`.

**Concrete case:**
- Core's `INDEX` has `{database_name: 'virga-index', database_id: <UUID of virga-vault>}`.
- `checkTopology` returns `[]`, and ensureDatabases accepts the UUID.
- `d1 migrations apply virga-index --remote` from apps/core applies the index migrations to the vault.
- Core is deployed with the vault bound, breaking D-08 (vault bound only to the broker).

**Fix**

In `ensureDatabases`, look up the listed entry for each `database_id` and require its name to equal `database_name`. Then check one owner per database by UUID.

**How it was verified**

scratch script d1.ts loads the real configs, sets core's d1 binding to that name/UUID pair, and runs `checkTopology`, which prints `issues: []`. Read steps.ts:76-120 to confirm the UUID is never compared to the name.

### R3-07 [low] An undecided row keeps an expired suppression in force indefinitely, hiding the finding from the default view

Location: `packages/rules/src/evaluate.ts:335`

**Scenario**

`applyHits` only updates decided rows; undecided fingerprints are added to `returned` and left alone. The read path (apps/core/src/graph/read.ts) does not recompute status. The SPA's findings list shows `status=open` by default.

**Concrete case:**
- An open CF-004 finding on tunnel_hostname t1:ssh.example.com is suppressed until t=1000 ("adding Access this week").
- The owner adds an Access app whose override has `path_pattern: '/api/*/health'`.
- Exposure becomes `/` access plus `/api/*` unknown, and CF-004 returns an undecided row.
- At t=5,000,000 the finding is still `suppressed` with `suppressed_until` 1000.
- It stays that way, out of the open list and counted as suppressed in the summary, until a decided row appears.
- This contradicts data-model.md ("It expires on its own"). The undecided count is also not persisted (planned in fix-core), so nothing shows why.

**Fix**

When an undecided row meets a finding that is `suppressed` with `suppressed_until <= at`, set the status to `open` and clear the suppression fields, leaving evidence and nodes unchanged. Alternatively, have GraphReader report suppressions past their date as open. Then update the data-model text.

**How it was verified**

scratch script undecided.ts loads the real evaluator and runs CF-004 through evaluateRules on a seeded suppressed finding. It prints:
- exposure `[['/', 'access', 2], ['/api/*', 'unknown', 0]]`
- summary `{hits: 0, undecided: 1, resolved: 0}`
- rule_runs `hits 0`
- finding `{status: 'suppressed', suppressed_until: 1000, last_seen: 1}`
