# Completion plan

Status: proposal, 2026-11-20. This plan takes Virga from its state on 2026-10-30 (commit 70b1d1a, round 11 verified) to a first signed release. It does not replace the [implementation plan](implementation-plan.md): the phases, gates, spikes and rule rollout there still hold. This plan orders the remaining work, says who does each step, and ends the hardening rounds.

## Where things stand

- **Code.** Phase 1 is built: graph store, broker, 11 collectors, exposure evaluator v1, scan Workflow, web Worker (UI, API, MCP), deploy script, end-to-end scan test against a fake account, OCSF export, tool audit trail, test range Terraform. Phase 2 groundwork (`packages/vulns`, `packages/scanner-io`) started early under [decision 0007](decisions/0007-later-phases-before-the-phase-1-gate.md). 2,663 tests, CI green.
- **Reviews.** Eleven rounds. Round 11 left two lows (R11-01, R11-02), one broker hardening item (recheck after removal), and guard hardening ([round 11 verification](reviews/2026-10-30-verification-round-11.md)). Leads R8-06 to R8-11 wait for observed API shapes.
- **Platform.** Nothing has run on Cloudflare. No spike that needs an account has run (S-01, S-05 to S-08; the production halves of S-02 to S-04). The test range has never been through `terraform validate`.
- **Accounts.** As of 2026-11-20 the owner has one account on **Workers Paid** (confirmed). There is no second account yet.
- **Dependencies.** TM-16: body-parser 2.3.0 and fast-uri 3.1.8 have published advisories; their patched versions pass the 14-day age gate in November 2026.

## What changes in how we work

1. **Round 12 is the last hardening round.** After it, review findings no longer open a new round on their own. A finding rated high or critical is fixed before the next gate; medium and low findings go into the backlog (GitHub issues) and are picked up with the work that touches the same code. Eleven rounds have moved from design flaws (rounds 2 to 4) to supply-chain edge cases rated low (rounds 9 to 11); more rounds without platform contact have little left to find. The remaining risk is in API shapes nobody has observed, and only a real account answers that.
2. **`main` is the development branch** and the default branch (since 2026-11-20). Work goes through pull requests to `main`, with CI as the required check. The old branch `ccr-fb16682f-xtuagp` is retired.
3. **Issues track the backlog.** Each open finding, lead and gate item below becomes a GitHub issue, so the state is visible without reading the review reports.

## Accounts needed

| Role | Plan | Used for | Rules |
| --- | --- | --- | --- |
| Tool account | Workers Paid | Runs Virga: broker, core, web, D1, R2, Secrets Store, Access; S-01, S-03 production run, S-07 | Dedicated: nothing else in it, few members, all with security keys, deploys only through CI ([operator guide](operator/guide.md)). Anyone who can deploy the broker can read every stored token |
| Test range account | Free is probably enough; check with the first `terraform plan` (R2 must be enabled, which needs a payment method). Not a temporary account (see below) | Seeded misconfigurations, phase 1 gates 3 and 5, phase 2 gate 1, phase 3 gates 1 to 3 | Dedicated, with a zone that serves nothing else, ideally a domain bought for it ([test range README](../infra/test-range/README.md)). Never the tool account |
| Real account to scan | Any | Phase 1 gate 4 ("at least one other real account"); S-05, S-06 can also run here | The owner's existing account, scanned with a read-only token |

If the paid account is the owner's general account with other things in it, it should be the "real account to scan", and the tool account should be a new, empty account on Workers Paid. If it is empty, it becomes the tool account.

**Temporary accounts do not work for the test range.** `wrangler deploy --temporary` accounts ([notes](spikes/temporary-accounts.md)) are on Workers Free, are deleted after 60 minutes unless claimed, and offer no zones, R2, Access or Zero Trust, account token management, Workflows or cron triggers. The range needs a zone, a public R2 bucket, Access apps and account tokens, and a nightly scan needs it to stay up. They remain useful for quick checks of API response shapes in stage 2 (Workers API, `Ratelimit` headers). Claiming one turns it into an ordinary Free account, which is the same as creating a second account; creating one directly is simpler.

## Stages

Each stage ends with a check. "Agents" means work packages run as before; "Owner" means steps only the account owner can do (dashboard, billing, creating tokens).

### Stage 1: round 12 and dependency updates (agents, about 1 day)

| WP | Scope |
| --- | --- |
| `supply-chain-6` | R11-01: refuse a lone CR, U+0085, U+2028 and U+2029 in workflows and the guide's example (or allow printable ASCII, LF, CRLF only); refuse non-ASCII in keys and `if:` of gated jobs; require `--fresh-checkout` in the guard; Updates flow in a fresh clone or refuse git-tracked `node_modules` |
| `deploy-6` | R11-02: record and refuse `.pnp.data.json`, `.pnp.cjs`, `.pnp.js` in every case, in the app directory, each package tree and every directory above, before and after the builds and before each Wrangler call; name them in the guide and TM-27 |
| `hardening-12` | Broker: fail closed (503, retry) when `markChecked` returns false after a recheck; report the removal that actually happened; `TokenIntake.recheck` does not answer `stored: true` for a replaced secret |
| `deps-1` | TM-16: update body-parser and fast-uri once their patched versions are 14 days old; `pnpm check:release-age`; update TM-16 |
| `review-12` | Read-only verification of the four packages. Findings follow the new rule above |

**Done when:** round 12 merged to `main` by PR, CI green, review-12 report in `docs/reviews/`, and every open medium or low finding and lead filed as an issue.

### Stage 2: accounts and phase 0 spikes (owner, then agents; 1 to 2 weeks)

Owner first:

1. Confirm the plan is Workers Paid, and decide which account is the tool account (see above).
2. Create read-only API tokens for the spikes, scoped to one account, short expiry. They never go into the repository, a fixture or a log; recorded responses are sanitized before they are committed.

Then the spikes, in this order, because each unblocks the most code:

| Spike | Account | Unblocks |
| --- | --- | --- |
| S-05 permission groups | Any | Token profiles (D-14), the onboarding allowlist, CF-024's scope ([0004](decisions/0004-cf-024-scope.md)), the Worker half of R5-07 |
| R8-06 to R8-11 | Any | Observe the real shapes of tunnel configs, Worker versions and deployments, Pages projects and R2 bucket reads; fix the collectors where they guessed |
| S-04 API side | Any, with one deployed Worker | `package_dependencies`: devDependencies, transitive packages, size cap, source maps |
| S-06 Audit Logs v2 | Any | Event poller design (phase 3), cost of the tool's own `view` events |
| S-02 rest | Any | Pacing values under real load, GraphQL limit |
| S-08 Worker-level Access | Tool account, Zero Trust on | Confirms the web Worker's JWT check against a real Access app |
| S-01 Workflows | Tool account | `schedules`, duplicate instance IDs, step and CPU limits in practice |
| S-03 production run | Tool account | Row-write cost and CPU time on a 20,000-node graph in a real Durable Object |
| S-07 Containers | Tool account | Phase 2 scanner design; may run in parallel with stage 4 |

Each spike writes `docs/spikes/S-0x-*.md` and opens the follow-up work packages it implies.

**Done when:** the phase 0 gate holds: S-01 to S-06 and S-08 answered, the test range account exists. S-07 may continue.

### Stage 3: test range (owner, then agents; 2 to 4 days)

1. Owner: the dedicated account, a zone (buy a domain), `workers.dev` subdomain, Zero Trust organization, R2 enabled, a Terraform token with the permissions in the README.
2. Agents: `terraform validate`, `terraform plan`, fix and record what the docs got wrong (the README lists the known risks: IP ranges, Pages secrets, permission group names). The token only lives in the owner's shell.
3. Owner applies; the plan output and `cases.yaml` are compared.

**Done when:** the range is applied and every case in `cases.yaml` exists.

### Stage 4: first real deploy and scans, phase 1 gate (owner and agents; 1 to 2 weeks)

1. Dashboard prerequisites from the operator guide: Zero Trust, Access in front of `virga-web`, R2, a zone for the custom domain, and the master key.
2. **Secrets Store risk.** Secrets Store is still in open beta (D-15). Try it first. If store creation, the `workers` scope or the binding fails, use the documented Worker secret fallback and record the reason in a decision. Either way, write down where the master key backup lives: if it is lost, every account must be onboarded again. Key rotation has no entrypoint yet; add one before the release (stage 6).
3. `pnpm deploy` from a fresh clone, following only the guide; fix the guide where it is wrong. Gate 1.
4. Onboarding refusal test against the deployed broker with real tokens that have write, no expiry and more than 90 days to expiry. Gate 2.
5. Onboard the tool account itself (dogfooding) and the real account; full scans; missing permissions show as `not evaluated`. Gate 4.
6. Onboard and scan the test range; every phase 1 rule hits its seeded case and stays quiet on the clean one; no 429, no 5-minute block. Gates 3 and 5.
7. Exposure review: at least 50 entry points across the three accounts reviewed by hand; zero `public` on entry points marked protected. Gate 6.
8. A nightly scheduled scan of the test range with the findings compared to `cases.yaml` (testing strategy, end to end).

**Done when:** all six phase 1 gate items pass and are recorded in `docs/gates/phase-1.md` with evidence.

### Stage 5: phase 2, workload scanning (agents; 4 to 6 weeks)

Starts after the phase 1 gate. Already built: `vulns`, `scanner-io`, MCP server. Left: Worker bundles through the Versions API with `etag` change detection, package extraction by source with confidence, the scanner container (after S-07) with no internet and the advisory mirror in R2 ([0009](decisions/0009-advisory-mirror-egress.md)), container images and registry credentials, SBOMs in R2, the daily rematch, and rules CF-001 (switch on), CF-005, CF-006, CF-008. Gate: the six phase 2 items in the implementation plan, run on the test range.

### Stage 6: phase 3 and phase 4 (agents; 9 to 12 weeks)

Phase 3 (Zero Trust collectors and evaluator, change events from Audit Logs v2, pseudonymized user IDs, CF-012 to CF-020 and CF-023) and phase 4 (fix snippets, OCSF schema validation, EU mode, large-account mode, signed releases with SBOM, master key rotation entrypoint, documentation for a third-party deploy) as in the implementation plan. The first release is tagged after the phase 4 gate, which reruns the phase 1 to 3 gates on the test range from the signed release.

**Option:** if a usable product matters sooner than full coverage, tag a `0.1.0` preview after the phase 1 gate, marked as configuration-only, before phase 2. The gates do not change; the versioning policy decides whether a pre-release counts as a release.

## Rough timeline

Calendar time depends mostly on the owner's steps in stages 2 to 4.

| Stage | Effort | Earliest end if the accounts are ready in week 1 |
| --- | --- | --- |
| 1 Round 12 | 1 day | Week 1 |
| 2 Spikes | 1 to 2 weeks | Week 3 |
| 3 Test range | 2 to 4 days | Week 3 (parallel to stage 2) |
| 4 Deploy and phase 1 gate | 1 to 2 weeks | Week 5 |
| 5 Phase 2 | 4 to 6 weeks | Week 11 |
| 6 Phases 3 and 4 | 9 to 12 weeks | Week 23 |

## Risks

| Risk | Effect | Response |
| --- | --- | --- |
| API shapes differ from the docs (Workers Versions beta, permission groups, R2, tunnels) | Collectors and the allowlist need changes; leads R8-06 to R8-11 turn into findings | Stage 2 runs before the deploy; recorded, sanitized responses become fixtures |
| Secrets Store beta changes or is unavailable | The broker cannot bind the master key | Worker secret fallback is implemented and documented |
| Test range Terraform never validated | Stage 3 takes longer | Budget for fixes; the README lists the known risks |
| The paid account is the owner's general account | Tool account not dedicated; the broker would sit next to other workloads | Use a new empty account as the tool account |
| Review findings keep coming | No end to hardening | Round 12 is the last round; high and critical only block a gate |
| Free plan limits in the test range | Some seeded cases cannot be created | Upgrade the test range account to Workers Paid if `terraform plan` needs it |

## Decisions for the owner

Answered on 2026-11-20:

- The account is on Workers Paid.
- The hardening rounds end after round 12.
- The old branch `ccr-fb16682f-xtuagp` may be deleted.

Open:

1. Is the paid account empty (tool account) or the general account (scanned account)?
2. A second, Free account and a domain for the test range (temporary accounts cannot host it, see [Accounts needed](#accounts-needed)). Stages 1 and 2 do not wait for it; stage 3 and phase 1 gates 3 and 5 do.
3. Ship a configuration-only preview after the phase 1 gate, or wait for phase 4.
