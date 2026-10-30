# Verification review, round 6

- Date: 2026-10-30
- Scope: (1) are the findings of the [round 4 verification](2026-10-30-verification-round-4.md) (R4-01 to R4-07, fixed in round 5) and the [round 5 verification](2026-10-30-verification-round-5.md) (R5-01 to R5-08, fixed in round 6) fixed? (2) review of the round 5 and round 6 changes, at commit 3617367
- Status: new findings R6-01 to R6-07 open; fixes are planned in round 8 of the [work packages](../team/work-packages.md)

## Summary

Read-only review of 3617367 ("Give collectors-4 all of apps/core"). No tracked file was changed. Scratch scripts, scratch workerd tests and a copy of the repository were used for the checks; they are not kept in the repository.

All existing suites passed: cf-api 6, graph 15, web 60, exposure 194, collectors 258, broker 127, rules 388, core 229, scripts 137. `rules:check` passed with 11 rules and 71 fixtures, and `check:release-age` with 333 locked versions.

Not re-reported, because round 7 worked on them in parallel or they were already known: decision 0005, the per-tunnel byte budget, the Wrangler environment allowlist, `assets.directory`, the SPA's `removing` state, the Worker side of R5-07, and concurrent `addAccount` and `removeAccount`. The web removal route's authorization and CSRF checks were re-read and are unchanged.

## Verification of R4-01 to R4-07 and R5-01 to R5-08

| Finding | Status | Evidence |
| --- | --- | --- |
| R4-01 | fixed | /tmp/review-6/node/r401.ts runs the real evaluateExposure, replaceExposure and evaluateRules(CF-004) over two scans in one DB. Scan 1: Service Auth ip 0.0.0.0/0 on ssh.example.com (access_required) gives [/, public, 2] and CF-004 opened 1. Scan 2 cases: [Bypass 192.0.2.0/24, SA 0.0.0.0/0] gives public 2 and the finding stays open. [SA 0.0.0.0/0, Bypass everyone] gives public 2 and stays open. [Bypass office, SA everyone] gives unknown 0, undecided 1, still open. Variants: SA ::/0 or SA through a group holding 0.0.0.0/0 give public. SA 0.0.0.0/1 + 128.0.0.0/1, a missing policy, or an unsupported action give unknown, finding open. Control: Bypass office + Allow everyone gives access 1 and resolves, which is correct because no policy there issues a token without a login. |
| R4-02 | partly fixed | /tmp/review-6/node/r402.ts runs the real storage collector (fixture transport), the evaluator and CF-021 over two scans. Fixed cases: a custom domain whose enabled flag is omitted becomes enabled null, CF-021 has undecided 1, finding open. An r2.dev response without enabled becomes a node with enabled null, undecided 1, open. Still broken: a managed response {enabled:true} without `domain` emits no r2_public_domain, and CF-021 resolves 1. A custom response {} without `domains` emits no domain, and CF-021 resolves 1. Reported as a finding. |
| R4-03 | fixed | Scratch workerd test /tmp/review-6/copy/apps/core/test/r6-offboard.test.ts uses the real Admin, d1ScanIndex, runScan and AccountGraph. removeAccount returns {removed:true}. A runScan started afterwards returns {status: skipped, steps: [begin]}. Afterwards scan_runs is [], graph nodes [] and scans []. The existing R4-03 tests pass. |
| R4-04 | partly fixed | The review's copy of CF-004 with requires [tunnels, access] and no undecided fixture now fails compileRules with: 'reads exposure, so requires must also list exposure' and 'needs an undecided-*.yaml fixture'. Bypass: scratch rule CF-995 (/tmp/review-6/rules-hr) has requires [zones] and SQL `SELECT ... FROM (...) AS [z--]; SELECT ... FROM exposure WHERE decision = 'public'`. It compiles with errors []. In workerd DO SQL, with access coverage 'error' and a stale public exposure row, evaluateRules returned the hidden statement's row: evaluated, 1 hit, opened 1. Same root cause as R4-05, reported as a finding. |
| R4-05 | partly fixed | The review's WITH ... INSERT INTO meta ... RETURNING and WITH ... DELETE FROM findings ... RETURNING now fail with 'writes to meta/findings; a rule may only read'. Variant CF-997 (/tmp/review-6/rules-ms): `SELECT ... FROM (...) AS [z--]; UPDATE meta SET value = 'forged' WHERE key = 'current_scan'`. compileRules gives errors [], and both fixtures pass. The scratch workerd test r6-multistmt.test.ts calls evaluateRules on the DO's SqlRunner: meta current_scan went from 's1' to 'forged', and the run was evaluated with 0 hits. Reported as a finding. |
| R4-06 | fixed | /tmp/review-6/node/r406.ts runs the compiled CF-003 (loadFixture + runRule, now_ms 2026-10-29) on a never-expiring Workers Scripts Write token, both on the raw spelling and on canonicalCidr's output. These give 1 hit both ways: 0:0:0:0:0:ffff:0:0/96, ::0:ffff:0:0/96, 0::ffff:0.0.0.0/96, the zero-padded form, ::FFFF:0:0/96, ::ffff:0:0/096, ' ::ffff:0:0/96 ', ::/0 and 0.0.0.0/0. canonicalCidr turns every mapped spelling into ::ffff:0.0.0.0/96. Control: 198.51.100.0/24 alone gives 0. |
| R4-07 | partly fixed | Scratch project /tmp/review-6/age pins @types/node 26.6.6 (registry time 2026-10-28T18:36:36Z). With the lockfile as pnpm writes it, checkReleaseAge reports too_young. The same lockfile with the entry on one flow-style line, or with a comment after its key, parses to [undici-types@8.9.0] with no failures. With the packages section indented by 3 spaces it parses to [], checked 0, no failures. pnpm 10.28.0 `install --frozen-lockfile` installed @types/node 26.6.6 from each variant and left the lockfile unchanged. Also not checked: the pnpm version itself. corepack ran pnpm 10.34.9 (published 2026-10-25) from packageManager, and pnpm/action-setup at the pinned SHA reads packageManager when `version` is omitted, as ci.yml omits it. Both reported as findings. |
| R5-01 | fixed | /tmp/review-6/r5-deploy.ts runs the real readWorkerConfig and checkTopology on a copy. These all raise ConfigError 'key "__proto__" is refused': the review's __proto__ member with a VAULT D1, the escaped "__proto__", and __proto__ nested under observability. scripts/test/wrangler-parse.test.ts, which compares against Wrangler 4.151.0, passes. Wrangler's parseJSONC (cli.js:3113) throws on any jsonc-parser error, and an explicit --config skips redirected configs (cli.js:3524). The config can still change after the check: see the build-time finding. |
| R5-02 | fixed | Each of these gives a topology error: unsafe.bindings with ApiCaller, workflows with script_name virga-core (3 errors), and build.command. Variants tail_consumers and services[].props are refused too ('not supported'). The checks run once, before the builds: see the build-time finding. |
| R5-03 | fixed | apps/broker/.env holding CLOUDFLARE_API_BASE_URL makes readWorkerConfig raise ConfigError. processRunner checks again for .env files before every wrangler spawn and passes --env-file /dev/null. Wrangler 4.151.0 then loads only args['env-file'] (cli.js:366614). CLOUDFLARE_API_BASE_URL, WRANGLER_API_ENVIRONMENT and CLOUDFLARE_COMPLIANCE_REGION are pinned in childEnv. The env allowlist leftover is known. |
| R5-04 | fixed | /tmp/review-6/node/r5tun.ts runs the real tunnels collector, write path, evaluator and CF-004. Case 1 gives two nodes, `<tid>:ssh.example.com:` (ssh, public 2) and `<tid>:ssh:.example.com` (http_status), and CF-004 has 1 hit. Case 2 gives app.example.com public, 1 hit. Colon variant (hostname 'a:b' versus hostname 'a' with path 'b:'): the second pair gets `<tid>:sha256:<hash>`, public, 1 hit. |
| R5-05 | fixed | The review's 474-character regex rule gives a fall-through node `<tid>:app.example.com:sha256:<hex>` (ssh, public 2) next to app.example.com (access 1), and CF-004 has 1 hit. A 600-character hostname gets a pair-hash ID and is unknown; CF-004 has undecided 1 instead of dropping it. |
| R5-06 | fixed | 1,000 path-only rules × 1,000 hostname rules (194,811 bytes) give exactly 1,000 nodes and ingress_truncated true. Every row is unknown 0, and CF-004 is evaluated with 0 hits and 1,000 undecided. It took 152 ms in Node. The known limits (decision 0005, byte budget) are not re-reported. |
| R5-07 | partly fixed | /tmp/review-6/node/r507.ts runs the real pages collector, the write path and CF-024 over two scans; scan 1 opens the finding for API_KEY=cfat_... These scan-2 cases leave it open with 2 undecided: no deployment_configs, env_vars null, a variable without type, a value omitted. Still broken: a plain_text variable with value null, or with an object value, gives looks_secret false, and CF-024 resolves 1. Reported as a finding. The Worker side is known. |
| R5-08 | fixed | Scratch workerd test r6-offboard.test.ts, with an ACCOUNT_GRAPH whose deleteAll throws. removeAccount rejects with 'Error: Durable Object reset'. getAccount, listAccounts and getScanSummary all report 'removing', and the graph still holds worker_script:api. A runScan in between is skipped at begin. The retry returns {removed:true}, after which the index row is null and nodes are []. |

The partly fixed findings continue as new findings: R4-02 as R6-06, R4-04 and R4-05 as R6-02, R4-07 as R6-03 and R6-04, R5-07 as R6-05.

## New findings

### R6-01 [medium] Configs are checked before the builds run; a build can rewrite wrangler.jsonc (or the wrangler shim) and the Wrangler call that holds the token deploys or runs it unchecked

Area: deploy. Location: `scripts/deploy.ts:131`

**Scenario**

deploy.ts reads and checks every config (lines 97-104), then runs `pnpm run build` for each Worker (line 131, steps.ts:379) and immediately calls `wrangler deploy --config <same file>`. The config is never read again. Code that runs during apps/web's `vite build` has no CLOUDFLARE_* variable (R3-05): vite.config.ts, a Vite plugin, or a compromised build dependency. Such code can append `"unsafe": {"bindings": [{"name":"API","type":"service","service":"virga-broker","entrypoint":"ApiCaller"}]}` and `"build": {"command": "..."}` to apps/web/wrangler.jsonc. Wrangler then deploys env.API (virga-broker#ApiCaller) into the internet-facing Worker, and runs the custom build with CLOUDFLARE_API_TOKEN in its environment. A `__proto__` member or a VAULT D1 binding works the same way. The same build can instead add a line to apps/web/node_modules/.bin/wrangler, which the next Wrangler call runs while it holds the token. R5-01, R5-02 and R3-05 are each bypassed after the check.

**Fix**

Run all builds first, then read and check the configs. Before every Wrangler call, compare the config bytes with the bytes that were checked and refuse a difference (the .env check already works this way). Keep build code away from what the token-holding steps run. Either build in a separate job or sandbox that can write only dist/, or bundle with `wrangler deploy --dry-run --outdir` and deploy that output from a step in which no build code runs. Check apps/*/node_modules/.bin/wrangler and the wrangler package against the lockfile integrity before passing CLOUDFLARE_API_TOKEN. Add a test in which a build modifies the config.

**How it was verified**

Done in the scratch copy /tmp/review-6/copy, with apps/web's build script set to run /tmp/review-6/evil-build.mjs first. The real `node scripts/deploy.ts --dry-run` printed 'Configs: virga-broker, virga-core, virga-web; service bindings match', then 'evil-build: build sees CLOUDFLARE vars: none', then a web dry run listing 'env.API (service) Unsafe Metadata' and '[custom build] Running: ...'. /tmp/review-6/toctou-token.ts used the real readWorkerConfig, checkTopology (issues []), build and deploy through processRunner({credentials:'token'}) with a fake 52-character token, and printed '[custom build] custom build sees CLOUDFLARE_API_TOKEN: 52'. With /tmp/review-6/evil-build2.mjs (which edits node_modules/.bin/wrangler) it printed 'planted wrangler shim sees CLOUDFLARE_API_TOKEN: 52'.

### R6-02 [low] The rule compiler checks only the first SQL statement: a bracket identifier holding `--` hides a second statement, which Durable Object SQL runs (write, unchecked exposure read, unchecked output)

Area: rules. Location: `packages/rules/src/params.ts:25`

**Scenario**

compileParams skips quotes, comments and `;`, but it does not know SQLite's `[identifier]` quoting. In `... AS [z--]; UPDATE meta SET value = 'forged' WHERE key = 'current_scan'` it reads `--` as a comment to the end of the line. So the one-statement check passes, and the SELECT/WITH check in parse.ts passes too. node:sqlite's prepare compiles only the first statement and ignores the tail. That means EXPLAIN (compile.ts:201, the write and read checks), db.columns and the fixtures (even under query_only) all see only the SELECT. In production, the Durable Object's sql.exec runs every statement and returns the cursor of the last one. The second statement can therefore write (meta.current_scan, findings), read exposure without `requires: [access, exposure]` (R4-04), or return rows no fixture checked. An empty last cursor gives 0 hits, which resolves every open finding of the rule.

**Fix**

In compileParams, treat `[` ... `]` as a quoted identifier, like the quotes. In checkAgainstSchema, refuse a tail: compare `db.prepare(sql).sourceSQL` with the whole statement (node:sqlite returns only the first one, e.g. 'SELECT 1 AS [x--];'). At runtime, run rules through a SqlRunner method that refuses a cursor with rowsWritten > 0. Add compile tests with `[x--];` and `[a;b]`.

**How it was verified**

compileRules on /tmp/review-6/rules-ms/CF-997 returned errors [] and both fixtures passed. Scratch workerd test r6-multistmt.test.ts called evaluateRules on the DO's SqlRunner: meta current_scan went from 's1' to 'forged', with the run evaluated and 0 hits. /tmp/review-6/rules-hr/CF-995 (requires [zones], hidden `SELECT ... FROM exposure WHERE decision = 'public'`) compiled with errors []. In the DO, with access coverage 'error' and a stale public exposure row, it opened 1 high finding.

### R6-03 [low] check-release-age skips lockfile entries it does not recognise, so a two-day-old version passes while pnpm installs it

Area: supply chain. Location: `scripts/check-release-age.ts:113`

**Scenario**

parseLockfile recognises only a key line with exactly 2 spaces that ends in `:` or `: {}`, and a `    resolution: {...}` line. Every other line inside `packages:` is ignored, although the doc comment says it refuses anything else. These layouts are valid YAML that pnpm reads, and the young entry simply disappears from the check: the whole entry on one flow-style line, a comment after the key, or a packages section indented by 3 spaces (which drops every entry: checked 0). CI runs this check, then installs with `pnpm install --frozen-lockfile` from the same file.

**Fix**

Inside `packages:`, refuse any non-blank line that is neither a key line at indent 2 nor a field line at indent 4 or more. Refuse flow maps on the key line and comments. Cross-check that every `snapshots:` key (without its peer suffix) and every importer `version:` has a parsed packages entry. Alternatively, parse with a YAML parser vendored in the repository, since the CI job installs nothing. Add tests for the three layouts.

**How it was verified**

/tmp/review-6/age-check.ts ran the real checkReleaseAge (now 2026-10-30) on /tmp/review-6/age lockfiles that pin @types/node 26.6.6 (published 2026-10-28T18:36Z). The pnpm-written lockfile gave failures [@types/node@26.6.6 too_young]. The flow variant gave parsed [undici-types@8.9.0] and failures []. The comment variant gave the same. The indent variant gave parsed [], checked 0, failures []. pnpm 10.28.0 `install --frozen-lockfile` in /tmp/review-6/age-{flow,indent,comment} printed '+ @types/node 26.6.6', installed 26.6.6, and left each lockfile unchanged.

### R6-04 [low] The pnpm version that CI and operators run (packageManager) is outside the release-age check

Area: supply chain. Location: `package.json:6`

**Scenario**

check-release-age.ts reads only pnpm-lock.yaml. ci.yml runs pnpm/action-setup without `version`, and at the pinned SHA that action reads packageManager from package.json. Operators run `corepack enable && pnpm install`, which also follows packageManager. Changing `"packageManager": "pnpm@10.28.0"` to pnpm@10.34.9, published 2026-10-25 (5 days ago), leaves the lockfile untouched. The release-age job passes, and every later job and operator install runs that pnpm with full rights.

**Fix**

Have check-release-age.ts also date the pnpm version named in packageManager (and devEngines.packageManager) against registry time, with the same 14-day rule and exception list. Alternatively, set `version:` explicitly in ci.yml and check that value too.

**How it was verified**

`node scripts/check-release-age.ts` on the repository prints 'ok: all 333 locked package versions...'. The script contains no reference to package.json or packageManager (grep). In /tmp/review-6/pm, package.json packageManager pnpm@10.34.9 made `pnpm --version` print 10.34.9 through corepack. Registry time for pnpm 10.34.9 is 2026-10-25T17:54Z. The action-setup action.yml and README at ea17c68 say `version` is optional when packageManager is set.

### R6-05 [low] A Pages plain_text variable whose value is null or not a string counts as clean, so CF-024 resolves an open finding (R5-07 variant, Pages side)

Area: collectors. Location: `packages/collectors/src/platform/pages.ts:100`

**Scenario**

plainTextVars calls inspectValue(envVar.value) for type plain_text. inspectValue (secrets.ts:115) treats only `undefined` as uninspected; it walks null and objects with detectSecretIn and returns looks_secret false. Scan 1: API_KEY {type: plain_text, value: cfat_...} opens CF-024. Scan 2: the API returns the same variable with value null (for example redacted), or with an object as the value. CF-024 is then evaluated with 0 hits and resolves the finding, although nothing shows the secret is gone.

**Fix**

For Pages plain_text, a value that is not a string should get UNINSPECTED (looks_secret null). Keep detectSecretIn for Worker json bindings only. Add an undecided CF-024 fixture and a collector test for value null.

**How it was verified**

/tmp/review-6/node/r507.ts ran the real pages collector (fixture transport), the write path and CF-024 over two scans. Scan 2 with value null gave vars [{name: API_KEY, kind: plain_text, looks_secret: false}], CF-024 evaluated with 0 hits and resolved 1, finding status 'resolved'. Scan 2 with value {redacted: true} gave the same result. Control: value omitted gave looks_secret null, undecided, finding open.

### R6-06 [low] R2 domain responses that lack `domain` or `domains` count as no entry point, so CF-021 resolves an open finding (R4-02 variant)

Area: collectors. Location: `packages/collectors/src/platform/storage.ts:226`

**Scenario**

The r2.dev node is emitted only when `managed.domain` is a string (lines 226 and 230). Custom domains come from `custom?.domains ?? []` (line 240). Scan 1: bucket example-bucket with r2.dev enabled, or with custom domain files.example.com enabled, opens CF-021. Scan 2: the managed response is {enabled: true} without `domain`, or the custom response is {} without `domains`. Storage coverage is still complete and no r2_public_domain is emitted, so CF-021 is evaluated with 0 hits and resolves. This is the premise R4-02 fixed for `enabled`, applied to two more fields.

**Fix**

Managed: when `domain` is missing but `enabled` is not false, emit the node under a fallback native ID (pub-<bucketId>.r2.dev from managed.bucketId, or a per-bucket placeholder) with enabled taken from the flag, or throw so the chunk ends 'error'. Custom: when `domains` is not an array, throw instead of reading []. Add collector tests and a CF-021 undecided fixture.

**How it was verified**

/tmp/review-6/node/r402.ts ran the real storage collector, write path, evaluator and CF-021. 'variant r2.dev domain missing': domains2 [] and CF-021 evaluated with 0 hits, 0 undecided, resolved 1, status 'resolved'. 'variant custom list missing': the same. The R4-02 cases (enabled omitted) stay open as undecided.

### R6-07 [low] A scan that was running at removal ends after the account is added again and sets the new account's last_scan_at, so the dispatcher skips its first scan

Area: core. Location: `apps/core/src/index-db.ts:115`

**Scenario**

finishRun writes `UPDATE accounts SET last_scan_at = startedAt` whether or not its scan_runs row still exists. Sequence: a scan is running, the operator removes the account (for example to rotate the token) and onboards it again, and the old instance's next graph write is refused with StaleScanError. runScan's finish step then calls index.finishRun. scan_runs gets nothing back, but the re-added account, whose last_scan_at was null, gets the old scan's start time. dueAccounts then leaves it out for cadence_hours (up to 720) although its graph is empty and it was never scanned, and the index shows a last scan.

**Fix**

Update last_scan_at only for a run the index still holds. After the scan_runs UPDATE in the same batch, use `UPDATE accounts SET last_scan_at = ? WHERE id = ? AND (...) AND EXISTS (SELECT 1 FROM scan_runs WHERE id = ? AND account_id = ?)`, or require started_at >= accounts.created_at. Add a test that removes, re-adds, then finishes the old run.

**How it was verified**

Scratch workerd test /tmp/review-6/copy/apps/core/test/r6-offboard.test.ts uses the real Admin, d1ScanIndex and AccountGraph. After removeAccount and addAccount, readd_before is {lastScanAt: null, due: true}. The old scan's writeChunk throws StaleScanError. After index.finishRun for that scan, readd_after is {lastScanAt: 1793355420000 (= T1, the old scan's start), due: false at T1+2h, dueIn23h: false, runs: [], nodes: 0}.
