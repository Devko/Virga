# Verification review, round 4

- Date: 2026-10-30
- Scope: (1) are the findings of the [round 2 review](2026-10-30-security-review.md) fixed? (2) review of the round 3 changes, at commit c5f076c
- Status: new findings R4-01 to R4-07 open; fixes are planned in round 5 of the [work packages](../team/work-packages.md)

## Summary

Read-only review of HEAD c5f076c. No tracked files were changed and git status is clean. Existing suites pass: exposure 181, collectors 189, rules 296, graph 13, apps/core (workerd) 170, rules:check 11 rules / 62 fixtures.

Each R2 scenario was re-run with scratch scripts, not kept in the repository. They use the real collectors, evaluator, write path, compiled rules and AccountGraph.
- Fixed: R2-01, R2-03, R2-04, R2-05, R2-06, R2-07, R2-09 (Worker json bindings).
- Partly fixed:
  - R2-02: CF-021 still resolves a finding when a custom domain's exposure turns unknown through `enabled: null`.
  - R2-08: CF-003 misses non-canonical spellings of the IPv4-mapped any-range.
  - R2-10: minimumReleaseAge is not enforced for versions already in the lockfile, which is what CI installs from.

New findings in the round 3 code:
- Medium (fix-exposure): the Access-token exception in withOriginAccess looks only at the policy that wins the ranking. Adding a narrower Bypass next to a Service Auth policy turns an access_required tunnel hostname from public or unknown into 'access', and CF-004 resolves its finding.
- Low (fix-core): Admin.removeAccount does not stop a scan that begins after the removal. That scan refills the removed account's graph and index.
- Low (fix-rules compiler): the rule that a rule reading exposure needs an undecided fixture, and the not_evaluated gate, both depend on the rule listing `exposure` in `requires` itself. A rule that reads the exposure table without declaring it compiles and brings back the R2-02 behaviour.
- Low (older code, in scope as a compiler bypass): a `WITH … INSERT/UPDATE … RETURNING` statement passes the SELECT/WITH check and writes to the graph at scan time.

R3-01 to R3-07 are not re-reported. The CF-021 finding and the DML finding come from code before round 3 and are labelled as such.

## Verification of R2-01 to R2-10

| Finding | Status |
| --- | --- |
| R2-01 | fixed |
| R2-02 | partly fixed |
| R2-03 | fixed |
| R2-04 | fixed |
| R2-05 | fixed |
| R2-06 | fixed |
| R2-07 | fixed |
| R2-08 | partly fixed |
| R2-09 | fixed |
| R2-10 | partly fixed |

### R2-01: fixed

exp1.ts runs the real evaluator on an R2 custom domain behind one app:
- Bypass [ip 0.0.0.0/0, ::/0]: public 2, 'bypass policy needs no identity, limited by ip selectors'.
- Bypass geo: public. Bypass via an Access group holding 0.0.0.0/0: public. Bypass with an ip_list ('other') or an unknown kind: unknown 0.
- Service Auth ip 0.0.0.0/0, ::/0 or via a group: public. Service Auth office /24, 0.0.0.0/1 + 128.0.0.0/1 or ::ffff:0:0/96: unknown.

r201.ts runs the evaluator plus the compiled rules:
- CF-021 stays at 1 hit after the Bypass 0.0.0.0/0 is added.
- An open CF-004 finding stays open after a Bypass 0.0.0.0/0, and after a Service Auth 0.0.0.0/0.

The review's own scenarios are fixed. One variant still yields a false 'access': a Service Auth 0.0.0.0/0 plus a narrower Bypass on a tunnel hostname with access_required. It comes from the round 3 token handling and is reported as a new finding.

### R2-02: partly fixed

life1.ts reproduces the review scenario (real evaluator plus CF-004):
- A public tunnel hostname opens a CF-004 finding.
- An app whose target is 'other' makes the exposure unknown 0. CF-004 then reports hits 0, undecided 1, resolved 0, and the finding stays open.
- An override /api/*/health gives [/ access, /api/* unknown]. The finding stays open.

Close variant still broken (cf021.ts):
- Scan 1: R2 custom domain enabled true, no app. Exposure public, CF-021 opens a finding.
- Scan 2: the same domain with enabled null. The evaluator gives unknown 0, but CF-021 is evaluated with hits 0, undecided 0, resolved 1, and the finding is resolved.
- See the CF-021 finding.

### R2-03: fixed

exp1.ts, real evaluator:
- Route *.example.com/* plus app *.example.com (allow): [worker_route:r, /, public, 1, 'Access wildcards match one subdomain level; deeper hosts are not covered'].
- Tunnel hostname *.example.com: public 1. Tunnel hostname *.a.example.com: public 1.
- Route *example.com/* with zone example.com: public 1.
- Adding an all_workers app gives access 1, which is correct because Worker-level Access covers the deeper hosts.
- relateHost returns 'inside', not 'covers', for any-depth keys (hosts.ts:81).

### R2-04: fixed

r204.ts calls the real withoutCredentials:
- 'http://admin:s3cr@tPass@10.0.0.5:8080' becomes 'http://10.0.0.5:8080'.
- Close variants keep no part of the credential:
  - newline then '@'
  - '@' after the path ('')
  - '#a@b' ('')
  - 'rdp://DOMAIN\\admin:Pa$$w0rd!@…'
  - %40
  - uppercase scheme
  - 'http//…' ('')
- The collector test 'R2-04: drops the whole password' passes.

### R2-05: fixed

r205.ts runs the real appTargets and the evaluator:
- hostTarget('app.example.com/alpha/*') gives path '/alpha/*' (verbatim).
- A Custom Domain behind that app gives [/ public 2] and [/alpha/* access 2]. The bare /alpha falls under the public '/' row.
- 'app.example.com/alpha/' gives /alpha unknown.

### R2-06: fixed

r205.ts:
- all_workers with 21 public overrides keeps all of them: /p00 to /p20 are public 1, / is access 1.
- 101 overrides become an 'other' target and the result is unknown 0. The same happens for a worker destination and a public destination.
- A path_pattern of 513 characters becomes 'other', so the result is unknown.
- A non-public behavior makes /x unknown.

### R2-07: fixed

Every scan-scoped method calls assertCurrent synchronously after its last await: applyBatch, writeChunk, recordCoverage, sweep, computeExposure and evaluateRules (account-graph.ts:58-61, 102-201).
- finishScan returns 'failed' for a scan that is not current.
- runScan maps StaleScanError to a non-retried 'stale' result and ends the scan as failed.
- The core suite passes 170/170, including both R2-07 tests (stale, then superseded, ended or still marked running).

Variants checked: a stale instance re-running beginScan gets started:true but is still refused on write, and the sweep's write of current_scan is a no-op behind assertCurrent.

A scan that begins after Admin.removeAccount is not refused. That is a different trigger, reported as a new finding.

### R2-08: partly fixed

cf003.ts runs the compiled CF-003 on a never-expiring Workers Scripts Write token.

These allow lists now produce the hit:
- ip_condition null
- in [0.0.0.0/0, ::/0]
- in [::ffff:0.0.0.0/96]
- in [::ffff:0:0/96]
- in [0.0.0.0/1, 128.0.0.0/1]

These spellings of the same IPv4-mapped any-range produce no finding:
- 0:0:0:0:0:ffff:0:0/96
- ::0:ffff:0:0/96
- 0::ffff:0.0.0.0/96
- 0000:0000:0000:0000:0000:ffff:0000:0000/96

The GLOB '::ffff:*' at rule.sql:84 only recognises the compressed form.

### R2-09: fixed

workers.ts:250-273 routes `json` bindings through inspectValue (detectSecretIn).

r209.ts runs CF-024 on the collector's verdicts:
- json {api_key: cfat_…}: looks_secret true, CF-024:worker_script:w.
- Nested arrays and objects: hit.
- A token split across two strings: high_entropy, hit.
- The collector test R2-09 passes.

Remaining:
- A string longer than 16 KiB is checked only up to 16 KiB, as for plain_text (MAX_INPUT).
- Pages plain_text_vars are collected but CF-024 does not read them yet (planned in round 4, fix-lifecycle).
- No CF-024 fixture has kind 'json'.

### R2-10: partly fixed

pnpm-workspace.yaml:12 sets minimumReleaseAge: 20160.

r210/ test with pnpm 10.28.0 and @types/node 26.6.6, published 2026-10-28, two days ago:
- Fresh resolution with the setting fails ('published at 10/28/2026').
- With a lockfile that already holds 26.6.6, both `pnpm install --frozen-lockfile` (what ci.yml:27,48 runs) and a plain `pnpm install` install it.

So a package.json and lockfile change that brings in a fresh version passes CI, and survives the integrator's lockfile regeneration.

## New findings

### R4-01 [medium] A narrower Bypass hides a token-issuing Service Auth policy, so an access_required tunnel hostname is decided 'access' and CF-004 resolves

Location: `packages/exposure/src/policy.ts:226`

**Scenario**

Setup:
- Tunnel hostname ssh.example.com with access_required true, from the rule's own originRequest.access, which is still valid after R3-01.
- Access app 'a' on ssh.example.com.

Step 1: the app's only policy is Service Auth (non_identity) with include ip 0.0.0.0/0.
- Exposure: public 2. CF-004 opens (critical, SSH).

Step 2: the owner adds a Bypass for 192.0.2.0/24 at precedence 1.
- appVerdict ranks both policies PUBLIC (rank 1). The stable sort picks the Bypass verdict, which has no `token`.
- withOriginAccess (evaluate.ts:438-446) turns it into access 1, 'cloudflared requires an Access token'.
- CF-004 is evaluated with hits 0 and resolved 1.
- In reality, every request from outside 192.0.2.0/24 still matches the Service Auth policy. Under the contract's own model (graph-contract item 4: 'Service Auth issues the Access token'), those requests get a token and reach the origin, so the host is still public.

Same result in two other cases:
- Service Auth 0.0.0.0/0 first and Bypass everyone second. Bypass everyone has rank 0 and wins whatever the order.
- An undecided Service Auth policy (include everyone or geo, rank 2) next to a Bypass for an office range. Service Auth everyone alone is unknown; adding the narrower Bypass makes it 'access'. A policy that admits fewer requests should not make the host look more protected.

**Fix**

- In appVerdict, set `token: true` on the returned verdict whenever any of the app's policies is a Service Auth `public` verdict, not only when that policy wins the ranking.
- When a no-token public verdict wins but any Service Auth policy is undecided, or a policy is missing or has an unsupported action, carry a flag that makes withOriginAccess return `unknown` instead of `access`.
- Add tests for:
  - [bypass 192.0.2.0/24, SA 0.0.0.0/0]
  - [SA 0.0.0.0/0, bypass everyone]
  - [bypass office, SA everyone]
  Each with access_required: expect public or unknown, and CF-004 stays open.
- Reword graph-contract.md item 4 so the exception applies whenever such a policy exists in the app.

**How it was verified**

life2.ts runs the real evaluateExposure, replaceExposure and evaluateRules(CF-004), with loads through prepareBatch and applyBatch:
- Scan 1: exposure [/, public, 2], CF-004 [evaluated, 1 hit, opened 1].
- Scan 2, after adding the Bypass 192.0.2.0/24: exposure [/, access, 1], CF-004 [evaluated, 0 hits, resolved 1], finding status 'resolved'.
- The variant with SA everyone gives the same output.
- exp2.ts and exp3.ts show the other orders: SA any first plus Bypass everyone gives access 1; SA everyone alone gives unknown 0; Bypass office plus SA everyone gives access 1.

### R4-02 [low] CF-021 drops custom domains whose enabled state is unknown, so a public bucket's finding resolves when exposure turns unknown (R2-02 variant; older code)

Location: `rules/CF-021/rule.sql:25`

**Scenario**

- The evaluator decides an r2_public_domain with enabled null as unknown ('R2 public domain with unknown enabled state').
- CF-021's `domain` CTE keeps only `enabled = 1`. The domain therefore yields no row, decided or undecided.
- Scan 1: bucket customer-exports with custom domain files.example.com, enabled true, no Access app. CF-021 opens.
- Scan 2: the storage collector stores `enabled: bool(domain.enabled)`, which is null when the API omits the field or changes its type. The finding is resolved although the truth may still be public. This breaks 'Unknown is a result'.
- On the collector side, the r2.dev domain is emitted only when `managed.enabled === true` (storage.ts:228), so an unreadable flag removes the entry point altogether.

**Fix**

- In CF-021, include custom domains whose `enabled` is not exactly false, with `decided = 0` when enabled is null. This mirrors the evaluator, which makes them unknown.
- In collectBucketDomains, emit the r2.dev node with `enabled: null` when `managed.enabled` is not a boolean, instead of dropping it.
- Add an undecided-*.yaml fixture for enabled null.

**How it was verified**

cf021.ts runs the real evaluator plus CF-021:
- Scan 1: exposure [/, public, 2], CF-021 [evaluated, 1 hit, opened 1].
- Scan 2, same domain with enabled null: exposure [/, unknown, 0], CF-021 [evaluated, 0 hits, 0 undecided, resolved 1], finding 'resolved'.

### R4-03 [low] Admin.removeAccount does not stop a scan that begins after it; that scan refills the removed account's graph and index

Location: `apps/core/src/admin.ts:55`

**Scenario**

The removeAccount comment says 'The index goes first, so no new scan starts', but nothing enforces it:
- ScanWorkflow.run and runScan never check that the account is still in the index (workflows.ts:26-43, run.ts:127-131).
- AccountGraph.beginScan starts a scan on the empty, re-migrated graph after deleteAll (account-graph.ts:89-100).
- Any instance whose begin step runs after the removal therefore passes the stale-scan guard. Examples: a dispatched or triggerScan instance that is still queued, or a begin step retried after index.beginRun failed.
- It runs every collector through the broker. The token stays there until TokenIntake.remove, which removeAccount's own comment allows to come later. The scan writes the account's inventory back into the graph and adds a scan_runs row for an account that no longer exists in `accounts`.

**Fix**

- In runScan's begin step, refuse when getAccount(INDEX, accountId) is null, and return 'skipped'.
- In AccountGraph.deleteAll, leave a `removed` marker in meta. beginScan refuses while it is set; addAccount, through an explicit call, clears it.
- Optionally terminate the account's running and queued scan instances in removeAccount.
- Correct the doc comment.

**How it was verified**

Scratch workerd test coretest/removal2.test.ts runs vitest with apps/core's config and the real AccountGraph, Admin, d1ScanIndex, runScan and the fixture API:
- removeAccount returns {removed: true}.
- A runScan started afterwards (storage and dns stubs) ends 'partial'.
- getAccount is null, yet scan_runs has [{queued-…, partial}].
- The graph holds [{dns_record: 3}] nodes and scans [{queued-…, complete}].

### R4-04 [low] Compiler checks for exposure rules depend on self-declared `requires`: a rule that reads the exposure table without declaring it needs no undecided fixture and is never not_evaluated

Location: `packages/rules/src/compile.ts:76`

**Scenario**

- The undecided-fixture requirement checks only `rule.requires.includes("exposure")`. Nothing compares `requires` with the tables the SQL reads; line 42 only checks that names are known.
- The contract rule 'a rule that reads exposure must also list access' is not checked either.
- A copy of CF-004 with `requires: [tunnels, access]`, its undecided fixture deleted and the decided logic removed (`x.decision = 'public'`) compiles with errors [].
- At runtime this rule runs even when exposure coverage is error, reading the previous scan's exposure rows. When exposure turns unknown it resolves findings, which is exactly R2-02.

**Fix**

- In checkAgainstSchema, find the tables the statement reads. Either:
  - run `EXPLAIN <sql>` and map the root page of every OpenRead to sqlite_schema, or
  - scan the SQL for table names after stripping comments and strings.
- Then require `exposure` and `access` in `requires` whenever the `exposure` table is read, and likewise `vulns` and `packages`.

**How it was verified**

compile.ts calls the real compileRules on scratch rules/CF-004:
- Result: rules [[CF-004, [tunnels, access]]], fixtures 5, errors [].

life3.ts runs that compiled rule with evaluateRules and the real evaluator:
- Scan 1: [/, public], 1 hit, finding open.
- Scan 2, after an app with an 'other' target: [/, unknown], [CF-004, evaluated, 0, 0, resolved 1], finding 'resolved'.

### R4-05 [low] Rule compiler accepts `WITH … INSERT/UPDATE/DELETE … RETURNING`, so a rule can write to the graph at scan time (older parse.ts check)

Location: `packages/rules/src/parse.ts:85`

**Scenario**

- The only statement check is that the first word is SELECT or WITH.
- A CTE followed by DML with RETURNING passes that check, prepares and returns the required output columns (`db.columns`), and passes positive and negative fixtures.
- runRule executes it with db.query in the Durable Object, so it can change findings, exposure or meta.
- For example, it can rewrite meta.current_scan, which the round 3 stale-scan guard relies on.

**Fix**

- In checkAgainstSchema, run `EXPLAIN <sql>` and reject any statement with write opcodes (OpenWrite, Insert, Delete, IdxInsert, …).
- In runFixture and checkAgainstSchema, set `PRAGMA query_only = ON` so a write fails at compile time.
- Optionally reject INSERT, UPDATE, DELETE and REPLACE at the top level after the CTE.

**How it was verified**

Scratch rules2/CF-998 has:
- SQL `WITH z AS (SELECT … zone) INSERT INTO meta (key, value) SELECT 'current_scan', 'forged' FROM z … RETURNING 'CF-998' AS rule_id, …`.
- A positive and a negative fixture.

Results:
- compileRules: errors [].
- dml-run.ts calls evaluateRules on a graph with one zone: meta current_scan goes from "s1" to "forged", and the run reports evaluated with 1 hit.

### R4-06 [low] CF-003 recognises only the compressed spelling of the IPv4-mapped any-range (R2-08 variant)

Location: `rules/CF-003/rule.sql:84`

**Scenario**

- The rule documents that '::ffff:a.b.c.d/n' is read as an IPv4 range of n - 96 bits, so '::ffff:0.0.0.0/96' limits nothing.
- Its test is `address GLOB '::ffff:*'`. Equivalent spellings fall through to the IPv6 branch, where /96 lies between 32 and 128 and counts as a restriction:
  - 0:0:0:0:0:ffff:0:0/96
  - ::0:ffff:0:0/96
  - 0::ffff:0.0.0.0/96
  - fully expanded zeros
- A never-expiring Workers Scripts Write token with such an allow list is not reported, while the same token with '::ffff:0:0/96' is.
- Caveat: this depends on the rule's own assumption that Cloudflare matches IPv4 clients against mapped ranges, and on the API storing the spelling as given.

**Fix**

- Canonicalise CIDRs in the tokens collector: expand and compress IPv6, and turn IPv4-mapped entries into IPv4 with prefix n - 96.
- Or, in the rule, treat any IPv6 entry whose first 80 bits are zero and next 16 are ffff as mapped.
- Add a positive fixture with an expanded spelling.

**How it was verified**

cf003.ts uses loadFixture and runRule on the compiled CF-003 with now_ms 2026-10-29.

These allow lists produce ['CF-003:account_token:t1']:
- [::ffff:0.0.0.0/96]
- [::ffff:0:0/96]
- [0.0.0.0/0, ::/0]

These produce []:
- [0:0:0:0:0:ffff:0:0/96]
- [::0:ffff:0:0/96]
- [0::ffff:0.0.0.0/96]
- [0000:0000:0000:0000:0000:ffff:0000:0000/96]

### R4-07 [low] minimumReleaseAge is not checked for versions already in the lockfile, so CI installs a dependency released two days ago (R2-10 variant)

Location: `pnpm-workspace.yaml:12`

**Scenario**

- pnpm applies minimumReleaseAge only when it resolves versions.
- CI runs `pnpm install --frozen-lockfile` (.github/workflows/ci.yml:27, 48), which skips resolution.
- A plain `pnpm install` keeps locked entries too.
- A work package that commits package.json plus a pnpm-lock.yaml with a version published hours ago passes CI. The lockfile can come from a machine without the setting, or have `minimumReleaseAgeExclude` set and then removed. The integrator's regeneration keeps that version.

**Fix**

- Add a CI step, for example a script under scripts/, that reads every package@version in pnpm-lock.yaml. It fetches `time[version]` from the registry and fails when a version is younger than 14 days and not in an explicit exclude list.
- Or regenerate the lockfile from scratch in CI and diff it against the committed one.

**How it was verified**

Scratch project r210/ with pnpm 10.28.0 and @types/node 26.6.6, published 2026-10-28T18:36Z (registry `time`):
- Lockfile created without the setting, then `minimumReleaseAge: 20160` added.
- `pnpm install --frozen-lockfile`: '+ @types/node 26.6.6', exit 0.
- `pnpm install`: also installs it.
- Fresh resolution with no lockfile fails with '26.6.6 published at 10/28/2026'.
