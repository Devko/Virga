# Verification review, round 5

- Date: 2026-10-30
- Scope: (1) are the findings of the [round 3 review](2026-10-30-security-review-round-3.md) fixed? (2) review of the round 4 changes, at commit 2a5c436
- Status: R5-01 to R5-08 fixed in round 6 of the [work packages](../team/work-packages.md); not yet verified by a review. Leftovers are listed below the table

| Finding | Fixed by | Commits | Test |
| --- | --- | --- | --- |
| R5-01 | `deploy-hardening` | 83531c8 | `scripts/test/jsonc.test.ts`, `scripts/test/config.test.ts` (R5-01 tests); `scripts/test/wrangler-parse.test.ts` compares the parser with the pinned Wrangler on the review's config, the committed configs and generated texts |
| R5-02 | `deploy-hardening` | 1be6bef | `scripts/test/topology.test.ts` (R5-02 tests: `unsafe.bindings`, cross-Worker `workflows`, `build.command`, unknown keys, every allowed path exists in Wrangler's schema) |
| R5-03 | `deploy-hardening` | b7e0f6a | `scripts/test/run.test.ts`, `config.test.ts`, `deploy.test.ts` (R5-03 tests: `.env`, `.env.local`, `.dev.vars`, `--env-file`, `CLOUDFLARE_API_BASE_URL`, `CLOUDFLARE_ENV`, `WRANGLER_CI_OVERRIDE_NAME`). Also closes the rest of R3-03 |
| R5-04 | `tunnels-limits` | 8c6bb3e | `packages/collectors/test/identity/tunnels.test.ts` (R5-04 tests, including both review cases and a `:` in a hostname); e2e `apps/core/test/e2e/scan.test.ts` (R5-04) |
| R5-05 | `tunnels-limits` | b2d9336 | `tunnels.test.ts` (R5-05 tests: the review's 474-character regex, a 600-character path, an overlong hostname); e2e (R5-05) |
| R5-06 | `tunnels-limits` | 1778496 | `tunnels.test.ts` (R5-06 tests: the review's 96 KB case, the 1,000/1,001 boundary); `packages/exposure/test/evaluate.test.ts` (R5-06); e2e (R5-06) |
| R5-07 | `tunnels-limits` (Pages side) | 9df389b | `packages/collectors/test/platform/pages.test.ts` (R5-07 tests); e2e (R5-07: the open Pages finding of CF-024 stays open as undecided) |
| R5-08 | `core-offboarding` | 8d11162, 1bac065 | `apps/core/test/admin.test.ts` (graph deletion fails, index deletion fails, a scan begins in between, re-adding a `removing` account); `apps/core/test/index-db.test.ts` |

Leftovers after round 6:

- R5-03: variables in the operator's shell other than the pinned API variables still reach Wrangler (for example `HTTPS_PROXY`, `NODE_TLS_REJECT_UNAUTHORIZED`). The deploy does not build Wrangler's environment from an allowlist. `assets.directory` may point outside the app directory.
- R5-06: the cap bounds the node count, not the size of the nodes; and a truncated tunnel whose emitted nodes all answer with `http_status` gives CF-004 no row (see the contract's known limits).
- R5-07: the Worker side (a version whose `resources.bindings` is missing is still read as no bindings) needs S-05-style evidence of the API shape and a contract entry first.
- R5-08: concurrent `addAccount` and `removeAccount` calls for one account are not serialized; graphs left by the pre-round-6 removal order are not detected automatically.

## Summary

Read-only review of HEAD 2a5c436 ("Record the round 4 verification and plan round 5"). No tracked files were changed and git status is clean. Scratch scripts and a copy of HEAD (git archive) were used for the checks; they are not kept in the repository.

All existing suites pass: cf-api 6, graph 15, exposure 184, collectors 194, rules 313, broker 127, core 192, web 60, scripts 87. rules:check passes with 11 rules and 66 fixtures.

Verification of the round 3 findings:
- Fixed: R3-01, R3-04, R3-05, R3-06.
- Partly fixed:
  - R3-02: a path-only rule whose native ID is over 512 characters is still dropped, and ID collisions can drop a node.
  - R3-03: Wrangler still reads CLOUDFLARE_ENV and WRANGLER_CI_OVERRIDE_NAME from apps/<app>/.env.
  - R3-07: an expired suppression stays in force while the rule is not_evaluated, and data-model.md:116 is out of date.

New findings in the round 4 code (none of them repeat R4-01 to R4-07):
- Deploy, medium: Wrangler reads a `__proto__` member of wrangler.jsonc as the object's prototype, but the deploy check's JSON.parse does not. A web config can therefore bind the vault D1 and the master key while checkTopology reports no issues.
- Deploy, low: the check ignores three keys that Wrangler deploys: `unsafe.bindings` (can give web ApiCaller), `workflows` with `script_name` (can give web core's ScanWorkflow) and `build.command` (the custom build sees the deploy token).
- Deploy, low: Wrangler loads apps/<app>/.env and .env.local. A CLOUDFLARE_API_BASE_URL set there sent the deploy token to a local capture server during a real deploy.ts run.
- Tunnels, low (three findings):
  - native ID collisions hide a hostname;
  - native IDs over 512 characters are dropped without any signal;
  - the fall-through expansion grows quadratically: a 96 KB config produced 1,001,001 nodes.
- Lifecycle, low: when Pages env var data is missing from the API response, CF-024 treats the project as clean and resolves an open Pages finding.
- Offboarding, low: when the graph deletion fails after the index rows are deleted, the account disappears from the UI and its graph data stays.

Offboarding authorization, CSRF, token deletion and the rate budget clear were checked and found sound.

## Verification of R3-01 to R3-07

| Finding | Status |
| --- | --- |
| R3-01 | fixed |
| R3-02 | partly fixed |
| R3-03 | partly fixed |
| R3-04 | fixed |
| R3-05 | fixed |
| R3-06 | fixed |
| R3-07 | partly fixed |

### R3-01: fixed

Script (scratch script) runs the real tunnels collector, prepareBatch/applyBatch, evaluateExposure and evaluateRules(CF-004).
- R3-01 scenario (access only in the top-level originRequest): the node has access_required false, exposure is [/, public, 2] and CF-004 is evaluated with 1 hit, opened 1.
- Variant: the rule has its own originRequest without access, plus a top-level access block. access_required is false.
- Variant: required set to the string "true". access_required is false.
- Control: the rule's own access block gives access_required true, [/, access, 1] and 0 hits.
accessRequired (tunnels.ts:86-93) now reads only rule.originRequest.access.required === true.

### R3-02: partly fixed

Script (scratch script)
- Case A gives two nodes: app.example.com (access_required true) and app.example.com^/debug (via_fallthrough). Exposure: [/, access, 1] and [/debug*, public, 2]. CF-004 has 1 hit.
- Case B gives a fall-through node app.example.com at [/, public, 2] next to /admin* access. CF-004 has 1 hit.
- Hostname '*' path rules and catch-all origins work too: every listed hostname gets its own fall-through node.
- Wildcard hostname rules keep their own public node.

Remaining 1, long native ID ((scratch script)
- A path-only rule with a 474-character regex gives native ID <tid>:app.example.com<path>, 526 characters.
- Its node is dropped silently. Only app.example.com [/, access, 1] remains, and CF-004 has 0 hits.
- The same rule with a short path gives 1 hit.

Remaining 2, ID collision ((scratch script) a native ID collision drops the node of a later rule. See the findings below.

### R3-03: partly fixed

Script (scratch script) runs against a copy of HEAD made with git archive.
- A stray /wrangler.json or apps/wrangler.json now raises ConfigError ('is a Wrangler config above the app').
- A sibling apps/web/wrangler.json next to wrangler.jsonc raises ConfigError.
- configOverrides({CLOUDFLARE_ENV:'prod'}) returns ['CLOUDFLARE_ENV'], so deploy.ts exits 1.
- An env block is now a topology error.
- The real Wrangler 4.151.0 was run through processRunner with a stray root wrangler.json that binds ApiCaller. Its dry run prints only CORE_READ, CORE_ADMIN and BROKER_INTAKE, so --config works.

Remaining ((scratch script)
- Wrangler loads .env and .env.local from cwd (cli.js:366615, loadDotEnv).
- childEnv deletes CLOUDFLARE_ENV and WRANGLER_CI_OVERRIDE_NAME. Because they are then absent, the values in the file win.
- apps/web/.env with CLOUDFLARE_ENV=prod and WRANGLER_CI_OVERRIDE_NAME=virga-broker makes the dry run print:
  - 'No environment found in configuration with name "prod"'
  - 'Failed to match Worker name ... "virga-web-prod" ... expected "virga-broker". Overriding using the CI provided Worker name'
- The checked web config would therefore be deployed as virga-broker.
See the .env finding.

### R3-04: fixed

Script (scratch script)
- secrets.required ['CLOUDFLARE_API_TOKEN'] now gives the topology error 'Cloudflare credentials are never Worker secrets'.
- planWebSettings returns upload [] and expected ['CLOUDFLARE_API_TOKEN'].
- Variants:
  - GITHUB_TOKEN: not read from the environment (upload []).
  - cloudflare_api_token and Cf_Api_Key: topology error.
- withSecretsFile({CLOUDFLARE_API_TOKEN}) throws 'refusing to upload CLOUDFLARE_API_TOKEN'.
- Wrangler itself turns secrets.required into inherit bindings and does not read their values from the environment (cli.js:176339).

### R3-05: fixed

Script (scratch script) runs the real processRunner({credentials:'token'}) with `pnpm exec node -e` in apps/web. The child prints 'CLOUDFLARE_API_TOKEN: 0 CF_API_TOKEN: 0'.

A close variant needs a committed config change and is reported as a new finding: a wrangler.jsonc `build.command`. Wrangler's custom build printed 'sees CLOUDFLARE_API_TOKEN: 46'.

### R3-06: fixed

Script (scratch script)
- Core INDEX is set to {database_name virga-index, database_id = vault UUID}.
- checkTopology returns [], but checkDatabaseIds and the real ensureDatabases throw 'database_id 1111… which is virga-vault, not virga-index'.
- Only 'd1 list --json' ran; nothing was created or migrated.
- Variants:
  - vault name and vault UUID in core: topology error.
  - broker and core both bind by the same UUID: topology error 'D1 database_id … is also bound by virga-broker'.

### R3-07: partly fixed

Script (scratch script) runs the real evaluator and evaluateRules on one DB across scans.
- Scenario: scan 2 at 5e6 gives exposure [/ access 2, /api/* unknown 0] and CF-004 evaluated with 0 hits and 1 undecided. The finding becomes status 'open' with suppressed_until null.
- A suppression that has not expired stays 'suppressed' (correct).

Remaining:
- With tunnels coverage no_permission, CF-004 is not_evaluated at 5e6 and again at 9e7. The finding stays 'suppressed' with suppressed_until 1000 indefinitely.
- GraphReader returns the raw status (read.ts findingView, summary GROUP BY status), so the SPA's default open list hides it.
- docs/architecture/data-model.md:116 still says 'an expired suppression waits for the next decided row'.

Fix: treat suppressed_until <= now as open in read.ts (summary and filters), and update the doc.

## New findings

### R5-01 [medium] The deploy check and Wrangler parse wrangler.jsonc differently: a __proto__ member deploys bindings the check never sees (vault D1 and master key in virga-web)

Location: `scripts/lib/jsonc.ts:92`

**Scenario**

Add one member to apps/web/wrangler.jsonc:
`"__proto__": {"d1_databases": [{"binding":"VAULT","database_name":"virga-vault","database_id":"<vault uuid>"}], "secrets_store_secrets": [{"binding":"MASTER_KEY_STORE","store_id":"…","secret_name":"virga-master-key"}]}`

What the deploy check sees:
- parseJsonc uses JSON.parse, which makes `__proto__` an ordinary own property.
- parseWorkerConfig sees d1 [] and secretsStore [], so checkTopology returns no issues. The STATELESS and KEY_HOLDER checks pass.

What Wrangler deploys:
- Wrangler 4.151.0 parses with jsonc-parser. Its onValue does `currentParent[currentProperty] = value` (wrangler-dist/cli.js:2341), which sets the object's prototype.
- Every key under `__proto__` is therefore inherited and deployed. The dry run prints `env.VAULT (virga-vault) D1 Database` and `env.MASTER_KEY_STORE (…/virga-master-key) Secrets Store Secret`.
- That puts the vault and the master key in the internet-facing Worker, breaking D-08 and D-15.

The same works for any checked key that is absent at top level, for example `routes` on broker or core, which the INTERNAL check reads as an own property.

Precondition: a committed config change that looks harmless in review.

**Fix**

- Reject `__proto__`, `constructor` and `prototype` keys at any depth: a JSON.parse reviver that throws, or a check on the stripped text.
- Better, check the configuration Wrangler itself resolves instead of a second parser:
  - read it with the Wrangler package's config API (unstable_readConfig / experimental-config) and run checkTopology on that result; or
  - parse with the same jsonc-parser and compare the two results.
- Combine this with an allowlist of top-level keys (next finding).

**How it was verified**

Script (scratch script) on the git-archive copy of HEAD:
- runs the real readWorkerConfig and checkTopology: d1 [], secretsStore [], issues [];
- runs `wrangler deploy --dry-run` through the real processRunner with --config: exit 0, and the output lists env.VAULT and env.MASTER_KEY_STORE.

(scratch script) shows the same mechanism with `services` holding ApiCaller (`env.API (virga-broker#ApiCaller)`).

### R5-02 [low] checkTopology ignores config keys that Wrangler deploys: unsafe.bindings, cross-Worker workflows in web, and build.command, which hands the deploy token to a build

Location: `scripts/lib/config.ts:140`

**Scenario**

parseWorkerConfig reads only selected keys and ignores the rest. Each change below was made to apps/web/wrangler.jsonc on its own:
- (a) `"unsafe": {"bindings": [{"name":"API","type":"service","service":"virga-broker","entrypoint":"ApiCaller"}]}`. checkTopology returns []. The Wrangler dry run prints `env.API (service) Unsafe Metadata` with the ApiCaller metadata. That is the R3-03 consequence (web gets ApiCaller) through a reviewed config change.
- (b) `"workflows": [{"binding":"SCAN","name":"virga-scan","class_name":"ScanWorkflow","script_name":"virga-core"}]`. Result []. The dry run prints `env.SCAN (ScanWorkflow (defined in virga-core))`. Web could then start scans for any account ID without Admin's checks. STATELESS checks only D1 and Durable Objects.
- (c) `"build": {"command": "node -e …"}`. Result []. On a token deploy, Wrangler's custom build printed 'sees CLOUDFLARE_API_TOKEN: 46'. That breaks the R3-05 rule 'builds never get credentials'.

**Fix**

- In parseWorkerConfig, allow only an explicit set of top-level keys and fail on anything else (unsafe, build, tail_consumers, etc.). The set: name, main, compatibility_date, compatibility_flags, workers_dev, preview_urls, observability, vars, d1_databases, durable_objects, migrations, workflows, services, secrets_store_secrets, assets, secrets, $schema.
- Add `workflows` to the STATELESS check.
- Allow cross-Worker workflow and Durable Object bindings (`script_name` set to another Worker) only through SERVICE_GRANTS-style grants.

**How it was verified**

Scripts (scratch script) (cases a and b) and (scratch script) (case c) run against the git-archive copy:
- real readWorkerConfig and checkTopology: issues [];
- real Wrangler 4.151.0 `deploy --dry-run` through processRunner. Case (c) ran with credentials 'token' and a fake token.

### R5-03 [low] Wrangler loads apps/<app>/.env and .env.local into its environment: CLOUDFLARE_API_BASE_URL there sends the deploy token to another host, and CLOUDFLARE_ENV / WRANGLER_CI_OVERRIDE_NAME there get past configOverrides

Location: `scripts/lib/run.ts:97`

**Scenario**

How Wrangler reads these files:
- Wrangler runs `process.env = loadDotEnv(['.env', '.env.local'], {includeProcessEnv: true})` for every command (cli.js:366615).
- The paths resolve against cwd, which processRunner sets to the app directory.
- Both files are gitignored, so they never show in git status.
- Values in the process environment win, but only for names that are set. childEnv deletes CLOUDFLARE_ENV and WRANGLER_CI_OVERRIDE_NAME and passes every non-credential CLOUDFLARE_* variable through.

Token leak:
- apps/broker/.env holds `CLOUDFLARE_API_BASE_URL=http://127.0.0.1:18787/client/v4`.
- A real `node scripts/deploy.ts` run (scratch copy, fake token) made the first wrangler call, `d1 list`, send `GET /client/v4/accounts/<id>/d1/database … authorization=Bearer cfat_scratchFAKE…` to that host, then /user/tokens/verify twice with the token.
- .env.local behaves the same.

Name override:
- apps/web/.env with CLOUDFLARE_ENV=prod and WRANGLER_CI_OVERRIDE_NAME=virga-broker renames the Worker to virga-web-prod, then overrides the name to virga-broker.
- The checked web config would replace the broker. An apps/broker/.env naming virga-web would put the vault and the master key under the internet-facing name.

**Fix**

- Pass `--env-file <path of an empty file>` to every wrangler call in processRunner. That replaces the default .env and .env.local lookup.
- Refuse to deploy while any apps/<app>/.env* file exists, as configsAbove does for stray configs.
- Build Wrangler's environment from an allowlist (PATH, HOME, proxy and CA variables, CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, WRANGLER_SEND_METRICS) instead of deleting known names.
- Refuse CLOUDFLARE_API_BASE_URL and CF_API_BASE_URL in the operator's shell too.

**How it was verified**

- (scratch script) a git-archive copy with a fake store_id, ran the full deploy.ts with a fake token. The local HTTP server at (scratch script) logged the Authorization header.
- (scratch script) covers .env.local. With `--env-file` pointing to an empty file, the local server received nothing.
- (scratch script) covers the dry-run warnings for the name override.

### R5-04 [low] tunnel_hostname native IDs concatenate hostname and path, so a crafted rule takes the ID of another hostname and hides that hostname's entry point

Location: `packages/collectors/src/identity/tunnels.ts:211`

**Scenario**

The native ID is `${id}:${hostname}${rule.path}`, and a path regex may start with hostname characters. A rule whose ID is already in `taken` is skipped.

Case 1:
- ingress `[{hostname:'ssh', path:'.example.com', service:'http_status:404'}, {hostname:'ssh.example.com', service:'ssh://localhost:22'}, {service:'http_status:404'}]`.
- Both rules map to `<tid>:ssh.example.com`. Only the http_status node is emitted, CF-004 is evaluated with 0 hits, and tunnels coverage is complete.
- Without the first rule: [/, public, 2], CF-004 1 hit.

Case 2:
- `{hostname:'app.example.co', path:'m', access required}` before `{hostname:'app.example.com', service:'ssh://localhost:22'}`.
- Only node app.example.com with path 'm' remains, decided access. CF-004 has 0 hits.

In cloudflared these rules have different hostnames, so anyone reaches the SSH origin without a check. A user with tunnel edit rights in the scanned account can hide an exposed origin from Virga.

**Fix**

- Key `taken` on the pair (hostname, path), not on the native ID.
- When a native ID is already used by a different pair:
  - keep the existing ID for the first pair, so current fingerprints stay;
  - give the other pair an ID with a hash suffix of hostname and path.
  - Alternatively, refuse hostnames outside `^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*$` and use a separator such hostnames cannot contain.
- Add a collector test for both cases.

**How it was verified**

Script (scratch script) runs the real collector, write path, evaluateExposure and the compiled CF-004.

### R5-05 [low] A fall-through (or hostname) rule whose native ID exceeds 512 characters is marked taken and then dropped silently, so the hostname rule after it decides 'access'

Location: `packages/collectors/src/identity/tunnels.ts:216`

**Scenario**

Input:
- ingress `[{path:'^/debug/(p0x|p1x|…|p94x)', service:'ssh://localhost:22'}, {hostname:'app.example.com', service:'http://localhost:8080', originRequest:{access:{required:true,…}}}, {service:'http_status:404'}]`.
- The path is 474 characters, so the native ID is 526 characters, over LIMITS.nativeId 512.

What the collector does:
- taken.add and takenWhole run before the fitsId check, then `continue` drops the fall-through node with no signal.
- Only app.example.com [/, access, 1] remains. CF-004 is evaluated with 0 hits and tunnels coverage is complete.
- Control with a short path: the fall-through node is public and CF-004 has 1 hit.

In cloudflared, app.example.com/debug/p0x reaches SSH without any JWT check. This is the R3-02 effect through a long regex.

**Fix**

Never skip an entry point without a signal. Either:
- emit it under a native ID with a hash suffix and keep the full path in props (parseTunnelPath already treats long regexes as approximate, all paths); or
- throw a RangeError so the chunk ends 'error' and CF-004 is not evaluated.
Add a test with a 600-character path-only rule.

**How it was verified**

Script (scratch script) runs the real collector, write path, evaluator and CF-004.

### R5-06 [low] Fall-through expansion is quadratic and unbounded: a 96 KB ingress config yields about one million tunnel_hostname nodes

Location: `packages/collectors/src/identity/tunnels.ts:209`

**Scenario**

Every path-only rule yields one node per hostname in the ingress, and nothing caps the total.

Case 1:
- 1,000 path-only rules plus 1,000 hostname rules, a 95,834-byte config, well below the broker's 16 MiB body cap.
- Result: 1,001,001 nodes, 325 MB of node JSON and 1.2 GB of heap. This took 6.6 s in Node.
- A Worker isolate has 128 MB, so the collect step dies and is retried. Tunnels coverage ends 'error', and CF-004, CF-010 and CF-011 are not evaluated for the whole account. Any isolate it shares with other scans is lost too.

Case 2:
- 200 by 200 (36 KB) gives 40,201 nodes.
- Write path, exposure and CF-004 took 60.6 s in Node and produced 40,000 findings.

Before round 4 the output was linear in the config size. Anyone who can edit a tunnel's config can stall that account's scans.

**Fix**

- Cap tunnel_hostname nodes per tunnel and per chunk, for example 5,000. Past the cap, either:
  - throw a RangeError (settled as 'error' without retries); or
  - collapse each fall-through rule into one node with hostname '*' and via_fallthrough true, which still evaluates as public or unknown.
- Size TUNNELS_PER_CHUNK with the cap in mind.

**How it was verified**

Scripts (scratch script) and (scratch script) run the real collector, write path, evaluator and CF-004 (Node with --max-old-space-size=4096).

### R5-07 [low] CF-024 v2 reads Pages env vars that the API did not return as 'no vars', so an open Pages finding is resolved instead of going undecided

Location: `packages/collectors/src/platform/pages.ts:82`

**Scenario**

How the collector reads env vars:
- plainTextVars treats a missing deployment_configs, `env_vars: null`, or an env var without `type` as 'no variables' (lines 82 and 85).
- It emits plain_text_vars [], with no uninspected marker.

Scan 1:
- Project shop has production env var API_KEY {type: plain_text, value: <high-entropy token>}.
- CF-024 is evaluated with 1 hit and the finding opens.

Scan 2:
- The same project comes back without deployment_configs, with env_vars null, or with the var lacking `type`.
- CF-024 is evaluated with 0 hits, 0 undecided and resolved 1. The finding becomes 'resolved' although nothing shows the secret is gone.
- Control: a var whose value is omitted gives looks_secret null, CF-024 has undecided 1, and the finding stays open.

Whether Pages Metadata Read returns env vars is still open (S-05). This breaks 'Unknown is a result' for the Pages half that round 4 enabled. The Worker side has the same older pattern (workers.ts:262: bindings missing gives []).

**Fix**

- When deployment_configs, an environment's config or its env_vars is absent or not an object, record the environment as uninspected. Use a marker entry with looks_secret null or a `vars_readable: false` prop.
- Treat a var without a known type but with a value as uninspected.
- Make CF-024 return an undecided row for such projects.
- Add an undecided fixture for each case. Apply the same to version bindings on the Worker side.

**How it was verified**

Script (scratch script) runs the real pages collector with the fixture transport, the write path and the compiled CF-024, over two scans in one DB.

### R5-08 [low] Offboarding: if the graph deletion fails after the index rows are deleted, the account disappears from every list while its graph data stays

Location: `apps/core/src/admin.ts:57`

**Scenario**

Order of the steps:
- removeAccount runs deleteAccount (index) first, then deleteAll on the graph.
- The web DELETE handler calls the broker first, then this.

Scratch workerd test (apps/core config, real Admin, index and AccountGraph), with an ACCOUNT_GRAPH whose deleteAll throws 'Durable Object reset':
- removeAccount rejects;
- getAccount is null and the account is not in listAccounts;
- GraphReader.getScanSummary is null;
- the graph still holds worker_script:api.

Effect in the UI:
- The web Worker answers 502 account_not_removed.
- The SPA shows the Remove form only while summary.data exists. Once the admin leaves the page, the account can no longer be found or removed in the UI.
- The offboarded account's inventory, findings and evidence stay in its Durable Object indefinitely.

**Fix**

Delete the graph before the index rows. Or mark the index row 'removing' first, skip it in dispatchDue and triggerScan, delete the graph, and only then delete the row. List 'removing' accounts in the SPA with a retry button. Correct the doc comment.

**How it was verified**

Workerd test (scratch script) run with `npx vitest run` in the scratch copy. It asserted on the observed state:
- removeAccount: 'Error: Durable Object reset'
- indexAccount: null
- listed: false
- summary: null
- nodesLeft: [worker_script:api]
