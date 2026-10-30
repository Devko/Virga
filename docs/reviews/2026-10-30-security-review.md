# Security review, round 2

- Date: 2026-10-30
- Scope: all code merged up to commit 0677dde (round 1), read-only review by a reviewer agent
- Status: fixes landed in rounds 2 to 4. The [verification review](2026-10-30-verification-round-4.md) confirms seven of them and rates R2-02, R2-08 and R2-10 as partly fixed. Their follow-ups R4-02, R4-06 and R4-07 were fixed in round 5 of the [work packages](../team/work-packages.md), except the collector half of R4-02, which is planned in round 6. No review has verified the round 5 fixes yet.

| Finding | Fixed by | Test | Verification (round 4) | Follow-up |
| --- | --- | --- | --- | --- |
| R2-01 | `fix-exposure`, decision 0003 | `packages/exposure/test` (R2-01 cases) | fixed | — |
| R2-02 | `undecided` | `packages/rules/test/evaluate.test.ts`, `undecided-*` fixtures | partly fixed: CF-021 still drops custom domains whose `enabled` is `null`, so their finding resolves; follow-up R4-02 | R4-02 fixed in round 5 by `fix-rules-3`: CF-021 version 3 makes a domain with an unknown `enabled` state undecided (`packages/rules/test/cf021.test.ts`). Open: the storage collector still drops an `r2.dev` domain whose `enabled` it cannot read (round 6, `tunnels-limits`) |
| R2-03 | `fix-exposure` | `packages/exposure/test` (R2-03 cases) | fixed | — |
| R2-04 | `fix-collectors` | `packages/collectors/test/identity/tunnels.test.ts` (R2-04) | fixed | — |
| R2-05 | `access-v2` | `packages/collectors/test/identity/targets.test.ts` | fixed | — |
| R2-06 | `access-v2`; regression tests by `fix-collectors` | `packages/collectors/test/identity` (R2-06) | fixed | — |
| R2-07 | `fix-core` | `apps/core/test` (R2-07, stale and superseded scans) | fixed | — |
| R2-08 | `fix-rules` | `packages/rules/test/cf003.test.ts`, CF-003 fixtures | partly fixed: non-canonical spellings of the IPv4-mapped any-range are missed; follow-up R4-06 | R4-06 fixed in round 5 by `fix-rules-3`: canonical CIDRs from the tokens collector, and CF-003 version 3 reads every spelling (`packages/collectors/test/identity/tokens-cidr.test.ts`, `packages/rules/test/cf003.test.ts`) |
| R2-09 | `fix-collectors` (Worker `json` bindings); `fix-lifecycle` (CF-024 reads Pages env vars, round 4) | `packages/collectors/test/platform` (R2-09), `packages/rules/test/evaluate.cf024.test.ts` | fixed for Worker `json` bindings; the Pages part landed after the review | — |
| R2-10 | integrator: `minimumReleaseAge` in `pnpm-workspace.yaml` | — | partly fixed: not enforced for versions already in the lockfile; follow-up R4-07 | R4-07 fixed in round 5 by `supply-chain`: `pnpm check:release-age` in the CI job `release-age`, before any install, and a re-resolved lockfile (`scripts/test/check-release-age.test.ts`) |

## Summary

Read-only review of the current branch (0677dde). No files in the repo were changed. The package and broker test suites pass: cf-api 6, graph 8, exposure 132, collectors 175, rules 136, broker 124.

I confirmed each finding below with a concrete input, using scratch scripts that run the real sources in Node 22 (not kept in the repository).

**Main problem area: exposure and the findings lifecycle.** I found four ways to get a false "protected" result, plus one path where a finding is resolved although the truth is unknown or public:
- A Bypass or Service Auth policy whose include is an IP range, a country or an unparsed selector is decided `access` or `service_auth`, even for 0.0.0.0/0.
- A wildcard route or tunnel hostname that matches any depth is treated as fully covered by a single-label Access wildcard.
- The round 1 collector strips a trailing `/*` from Access paths.
- `bounded()` truncates the overrides of account-level Worker Access targets to 20.
- `evaluateRules` resolves findings whose exposure became `unknown`.

Two of these are already scheduled for round 2: the `undecided` package and the verbatim Access paths in `access-v2`. They are still live in the current code. The Bypass case comes from the graph contract itself (item 3, "Otherwise → access") and from the test at evaluate.test.ts:492, so fixing it needs a contract change.

**Other findings:**
- The tunnel collector keeps part of a password in the graph when the password contains `@`.
- A scan already marked failed as stale can still write chunks. A newer scan's sweep then tombstones live nodes, and the related findings resolve.
- CF-003 treats an IP allow list of 0.0.0.0/0 as a restriction.
- CF-024 never inspects `json` bindings.
- The two-week minimum dependency age is a stated rule but nothing enforces it.

**Checked and found sound:**
- **Vault:** a per-token data key, AES-GCM with fresh 12-byte IVs, associated data binding the account, token ID and key version, and rotation that unwraps every row before writing.
- **Write check:** fails closed on unknown permission group names, missing names, missing expiry, a foreign resource or a missing account resource.
- **Allowlist:** segments match `[A-Za-z0-9._~@-]`, with no `%`, `?`, `#`, `.` or `..`. Each `/accounts/:id` path must match the caller's account ID, and query keys and values are checked.
- **GraphQL check:** refuses mutation and subscription documents and fails closed on anything it cannot parse.
- **Token handling:** requests use `redirect: manual`, the token is redacted from response bodies, and logs carry only error names.
- **Rate budget:** keeps a margin, honours `retry-after` blocks and counts GraphQL against REST as well.
- **Core:**
  - GraphReader calls module functions only, validates account IDs and filters, and Durable Objects are named by a 32-hex account ID.
  - Workflow step results hold counters, plus chunk units in the plan step (at most 512 KiB); no API bodies are kept.
  - Values from scanned accounts are typed `Untrusted`.
- **Collectors:** IdP configs, SaaS and SCIM credentials, service token client IDs and plain-text values are not stored.
- **CI:** actions pinned by SHA, `contents: read`, `persist-credentials: false`, exact dependency versions and a lockfile with registry sources only.

Access, route and cloudflared wildcard semantics were taken from the sources the code cites; they were not re-checked against the live docs during the review.

## Findings

### R2-01 [high] Bypass or Service Auth policy that includes 0.0.0.0/0, a country or an unparsed selector is decided `access` / `service_auth`

Location: `packages/exposure/src/policy.ts:97`

**Scenario**

`includesEveryone` only recognises the `everyone` selector, so the second loop sets bypass = true and the app ends in `access` (line 113) with confidence 2. A Service Auth policy with an IP include ends in `service_auth` (lines 100-108).

Concrete case: an R2 custom domain files.example.com pointing at bucket customer-exports, behind an Access app whose only policy is a Bypass with include [ip 0.0.0.0/0, ip ::/0].
- Evaluator output: access, confidence 2.
- CF-021: evaluated, 0 hits. With no app it reports 1 hit.
- CF-011: 0 hits, because it does not cover r2_public_domain.

The same Bypass in front of a tunnel hostname resolves an open CF-004 finding. Further cases:
- A Bypass with include `{kind: other}` (for example an ip_list) or `geo`: `access`.
- A Service Auth policy with include ip 0.0.0.0/0: `service_auth`.

The rule is also inconsistent with itself: "include everyone, require ip 0.0.0.0/0" gives `public`, while "include ip 0.0.0.0/0" gives `access`. The two have the same effect.

**Fix**

A Bypass never requires an identity.
- Decide any Bypass policy whose include holds non-identity selectors (ip, geo, certificate, common_name, device_posture, service_token) as `public`, with a reason such as "bypass limited to networks/countries". The contract already accepts that false positive for office IP ranges.
- Decide a Bypass with an `other` or unknown selector as `unknown`.
- For `non_identity` policies, decide an include of ip, geo or `other` as `unknown` (or `public` for 0.0.0.0/0 and ::/0).
- Update graph-contract.md item 3 and the test "a bypass limited to an IP range is access" (evaluate.test.ts:492).

**How it was verified**

Read policy.ts:23-113.

exposure-check.ts output:
- bypass ip 0.0.0.0/0 and ::/0: access, confidence 2
- bypass include everyone, require ip 0.0.0.0/0: public
- bypass with an `other` (ip_list) selector: access
- bypass geo: access
- Service Auth ip 0.0.0.0/0: service_auth

r2-check.ts output:
- no app: CF-021 has 1 hit
- with the Bypass: CF-021 has 0 hits, and CF-011 has 0 hits

lifecycle-check.ts scenario B: an open CF-004 finding becomes resolved once the Bypass is added.

### R2-02 [high] Findings are resolved when exposure becomes `unknown`, even when the truth is public

Location: `packages/rules/src/evaluate.ts:296`

**Scenario**

Every open finding of an evaluated rule that the query no longer returns is resolved (lines 296-299 and 309). The rules that read exposure match only `decision = 'public'`: CF-001:23, CF-002:70, CF-004:46, CF-009:76, CF-021:32 and CF-022:24.

Concrete case (lifecycle-check.ts scenario A):
1. Tunnel hostname ssh.example.com has no Access app. Exposure is public and CF-004 opens a finding.
2. The customer adds an Access app on ssh.example.com with a destination override `{behavior: public, path_pattern: /health}`.
3. The round 1 collector emits that override as an `other` target, so the evaluator returns `unknown` for the whole host.
4. CF-004 is evaluated, because tunnels, access and exposure are all complete. The finding is resolved.

The truth is that /health is public, so a real exposure is marked fixed. This breaks the rule that unknown is a result. It is the round 2 `undecided` work package, which is not implemented yet.

**Fix**

Implement the `undecided` contract: add an optional `decided` output column. Rules that read exposure return a row with decided = 0 whenever the relevant exposure is `unknown`, and `applyHits` keeps such findings in their current state. Leave them out of `gone` and do not upsert them as open.

Until then, an interim guard: for a rule that requires `exposure`, do not resolve a finding while any `unknown` exposure row exists for an entry point linked to its subject (through `finding_nodes`).

**How it was verified**

lifecycle-check.ts scenario A, which runs the real `appTargets`, `evaluateExposure`, `evaluateRules` and the CF-004 rule.
- Step A1: CF-004 evaluated, 1 opened, finding status open.
- Step A2: exposure is unknown with confidence 0, CF-004 evaluated, 1 resolved, finding status resolved.

### R2-03 [medium] A wildcard route or tunnel hostname that matches any depth is treated as fully covered by a single-label Access wildcard

Location: `packages/exposure/src/hosts.ts:79`

**Scenario**

`relateHost` returns `covers` whenever the label lists have the same length, and ignores `key.multiLevel`. The evaluator's own model says this is wrong:
- hosts.ts:2-5: the Access pattern `*.example.com` does not cover a.b.example.com.
- evaluate.ts:155-160 and hosts.ts:10-13: the route pattern `*.example.com` and the cloudflared hostname `*.example.com` match any depth.

Concrete cases:
- Route `*.example.com/*` to Worker w, plus Access app `*.example.com` with an email-domain allow policy. The evaluator gives worker_route:r / access, confidence 1. A request to x.y.example.com, once that name has a proxied DNS record, reaches w without Access.
- The same happens for tunnel_hostname `*.example.com`.

The tests evaluate.test.ts:261-268 and the tunnel case near 359-366 assert this behaviour. The contract says all known v1 limits err toward reporting exposure; this one does not.

**Fix**

In `relateHost`, when `key.multiLevel` is true and the app pattern is not multi-level, never return `covers`. Return `inside` when the labels intersect. The key is then split: the one-level part is decided by the app, and the any-depth remainder becomes `public`. `combine` then gives public with confidence 1. Update the two tests.

**How it was verified**

Read hosts.ts:75-88 and evaluate.ts:155-176 and 434-496.

exposure-check.ts output:
- route `*.example.com/*` with app `*.example.com`: [worker_route:r, /, access, 1, access_app:a1]
- tunnel `*.example.com` with app `*.example.com`: [tunnel_hostname:*.example.com, /, access, 1, access_app:a1]

### R2-04 [medium] Tunnel service credentials are only partly removed when the password contains '@'

Location: `packages/collectors/src/identity/tunnels.ts:80`

**Scenario**

`withoutUserinfo` uses `/^([a-z][a-z0-9+.-]*:\/\/)[^/@]*@/i`, which stops at the first '@'. Go's url.Parse, which cloudflared uses, splits userinfo at the last '@'.

Concrete case: an ingress rule `{hostname: app.example.com, service: "http://admin:s3cr@tPass@10.0.0.5:8080"}`. The stored tunnel_hostname.service is `http://tPass@10.0.0.5:8080`. Part of the password is written to the graph and, from there, can reach the UI and MCP output. This contradicts "Secrets never enter the graph" and the contract line "Credentials in a service URL are removed".

**Fix**

Parse the authority explicitly, as the text from after `scheme://` up to the first '/', '?' or '#'. Drop everything up to and including its last '@'. Alternatively, when any '@' is present in the authority, store only the scheme and host, or `null`. Add a test with '@' inside the password.

**How it was verified**

collector-check.ts runs the real `tunnelsCollector.collect` with that ingress and prints: stored service "http://tPass@10.0.0.5:8080".

### R2-05 [medium] Round 1 collector strips a trailing `/*` from Access paths, so the bare path is decided `access`

Location: `packages/collectors/src/identity/targets.ts:38`

**Scenario**

`hostTarget` turns `app.example.com/alpha/*` into `{host: app.example.com, path: "/alpha"}`. The evaluator reads `/alpha` as a segment, which covers /alpha itself and everything below it.

The contract says `/alpha/*` does not cover /alpha. So the exact path /alpha of a Custom Domain for Worker w is decided access, confidence 2, while requests to /alpha reach the Worker without Access.

This is the planned round 2 `access-v2` item "verbatim Access paths". The current code still produces the false protection.

**Fix**

Keep the path exactly as configured: drop the `path.endsWith("/*")` stripping and the later rejection of '*'. The evaluator's `parseAccessPath` already maps a trailing `/*` to prefix `/alpha/`, which excludes /alpha. Add a test for the bare path.

**How it was verified**

lifecycle-check.ts scenario C prints hostTarget('app.example.com/alpha/*') = {kind: hostname, host: app.example.com, path: /alpha}, and exposure rows [/, public, 2] and [/alpha, access, 2, access_app:a].

### R2-06 [low] Overrides of account-level Worker Access are truncated to 20 by `bounded()`, so later public overrides are lost

Location: `packages/collectors/src/identity/targets.ts:79`

**Scenario**

For destination types `all_workers` and `all_preview_workers`, the collector returns `[other(dest)]`, and `other` passes the raw value through `bounded` with RAW_BOUNDS (util.ts:29: items 20, text 256). The exposure evaluator then interprets `raw.overrides` as an account-level target.

Concrete case: an app with destination `{type: all_workers, overrides: [21 × {behavior: public, path_pattern: /p00 … /p20}]}`. The collector keeps 20 overrides, so /p20 is dropped. The evaluator returns `/` access for worker_custom_domain:app.example.com, which includes /p20, a path that is public. An override path longer than 256 characters is also cut and gets a "…" appended.

**Fix**

Do not pass targets the evaluator interprets through lossy bounding. Emit structured overrides with their own higher cap and a `truncated` flag, which is round 2 work anyway, and make the evaluator return `unknown` when the list is truncated or a path was clipped.

**How it was verified**

collector-check.ts prints "overrides kept by collector: 20", then a /p19 row of public, no row for /p20, and a root row of [/, access, 1, access_app:a].

### R2-07 [low] A scan already marked failed as stale can still write chunks, and a newer scan's sweep then tombstones live nodes

Location: `apps/core/src/account-graph.ts:86`

**Scenario**

`writeChunk`, `recordCoverage`, `sweep`, `computeExposure` and `evaluateRules` never check that the scanId is the running, current scan. `sweep` in packages/graph/src/write.ts:262 even resets meta.current_scan to its own scanId.

Sequence:
1. Scan A runs for more than 12 hours.
2. The dispatcher starts scan B, and `beginScan(B)` marks A failed.
3. B writes tunnel_hostname:ssh.example.com.
4. A's still-running instance retries a chunk and writes the same node, so seen_scan becomes A.
5. B records `complete` and sweeps.

The live node is tombstoned. Its CF-004 finding is then resolved, and exposure and rules run on a graph missing real entry points.

**Fix**

Refuse writes from non-current scans. In each scan-scoped method, require `scans.status = 'running'` for that scanId and `meta.current_scan = scanId`. Otherwise throw a non-retryable error that `settle()` maps to `error`, so the stale instance ends. Do not let `sweep` move current_scan.

**How it was verified**

Read account-graph.ts:68-176 and write.ts:247-305. stale-check.ts, using the real graph write path, prints: B sweep {swept: true, nodes: 1}, node tunnel_hostname:ssh.example.com with seen_scan scan-A and deleted_at 4.

### R2-08 [low] CF-003 treats an IP allow list of 0.0.0.0/0 or ::/0 as restricted

Location: `rules/CF-003/rule.sql:55`

**Scenario**

The rule excludes every token whose `ip_condition.in` list is non-empty, so `in: [0.0.0.0/0, ::/0]` counts as an IP restriction.

Concrete case: an active token with "Workers Scripts Write", no expiry and that `in` list produces no finding. The same token with `ip_condition: null` produces CF-003:account_token:t1. A long-lived write token usable from anywhere is not reported.

**Fix**

Treat an `in` list as restricting only when it contains no /0 entry, or more strictly when every entry is narrower than a threshold such as /8 for IPv4 and /32 for IPv6. Add a positive fixture.

**How it was verified**

cf003-check.ts (loadFixture and runRule on the compiled rule): ip_condition null gives ['CF-003:account_token:t1']; in [0.0.0.0/0, ::/0] gives [].

### R2-09 [low] Secret detection skips `json` bindings, so a secret in a JSON var is never reported by CF-024

Location: `packages/collectors/src/platform/workers.ts:261`

**Scenario**

Only bindings of type `plain_text` are passed to `detectSecret`. Wrangler uploads `[vars]` entries with object values as bindings of type `json` (`{type: json, name, json: {...}}`). Those fall through to `bindingTarget`, which returns null, so they appear neither in plain_text_vars nor in any finding.

Concrete case: `vars = { CONFIG = { api_key = "cfat_<40 chars>" } }` produces no CF-024 hit, although the value is as readable as a plain-text var. Pages env vars are also not inspected; CF-024 lists that as a known gap.

**Fix**

For `json` bindings, walk the value, run `detectSecret` on every string leaf (capped as today) and record the verdict, for example in plain_text_vars with a `kind` field. Extend graph-contract.md and add CF-024 fixtures.

**How it was verified**

Read workers.ts:256-283 and bindings.ts:55-94: no `json` case exists, the default returns null, and only `plain_text` reaches detectSecret.

### R2-10 [low] The two-week minimum dependency age is not enforced

Location: `pnpm-workspace.yaml:1`

**Scenario**

CLAUDE.md and work-packages.md require dependencies released at least two weeks ago. Nothing checks this:
- pnpm-workspace.yaml sets no `minimumReleaseAge`, which pnpm 10.28 supports.
- No CI step checks it.
- scripts/ is empty.

A work package or the integrator can add a version published hours earlier, and `pnpm install --frozen-lockfile` in CI accepts it. Everything else checked out: actions are pinned by SHA, `permissions: contents: read`, `persist-credentials: false`, versions are exact, and the lockfile has only registry sources with integrity hashes.

**Fix**

Add `minimumReleaseAge: 20160` (14 days, in minutes) to pnpm-workspace.yaml, with `minimumReleaseAgeExclude` only for the workspace's own packages if needed.

**How it was verified**

Read pnpm-workspace.yaml, .npmrc, .github/workflows/ci.yml and package.json; grepped pnpm-lock.yaml for tarball, git and GitHub sources and found none; `ls scripts` is empty.
