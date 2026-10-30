# Work packages

Development runs as a team of agents with one integrator. Each work package (WP) owns a set of paths and builds against fixed contracts. It works on its own branch `team/<wp>` in its own git worktree. The integrator merges the branches into the development branch, runs the full CI and pushes.

## Contracts

These are owned by the integrator. Work packages build against them and do not edit them. A work package that needs a change describes it in its report; the integrator decides and updates the contract.

| Contract | Where |
| --- | --- |
| Graph schema and write path | [`packages/graph`](../../packages/graph), [data-model.md](../architecture/data-model.md) |
| What collectors emit and evaluators read | [graph-contract.md](../architecture/graph-contract.md) |
| Cloudflare read client, broker RPC, errors, test transport | [`packages/cf-api/src`](../../packages/cf-api/src) (except the per-domain allowlist files) |
| Collector interface and registry | [`packages/collectors/src/types.ts`, `index.ts`](../../packages/collectors/src) |
| Rule format and runtime | [`packages/rules`](../../packages/rules) (except `evaluate.ts`) |

## Packages for phase 1, round 1

Status (2026-10-29): all six are merged. Integration fixes: the broker's refusal test used a path the tokens collector needs; CF-001 required `routes`, which is not a resource class. The compiler now rejects unknown inputs. Contract changes the packages asked for are folded into [graph-contract.md](../architecture/graph-contract.md); the parts marked "round 2" are not implemented yet.

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `broker` | Credential broker Worker: token vault (AES-256-GCM envelope encryption), onboarding write check, `ApiCaller` with allowlist, rate budget Durable Object | `apps/broker/**`, `packages/cf-api/src/allowlist/core.ts` | Tests prove that a write-capable or long-lived token is rejected, calls off the allowlist and to other accounts are refused, tokens never appear in responses or logs, and the rate budget pauses before the quota runs out |
| `platform` | Collectors `zones`, `dns`, `workers`, `pages`, `storage` | `packages/collectors/src/platform/**`, `packages/collectors/test/platform/**`, `packages/cf-api/src/allowlist/platform.ts` | Each collector turns recorded API responses into exactly the nodes and edges of the graph contract; every path it calls is on the allowlist; a 403 becomes `NoPermissionError` |
| `identity` | Collectors `access`, `tunnels`, `tokens`, `members`, `insights`, `traffic` | `packages/collectors/src/identity/**`, `packages/collectors/test/identity/**`, `packages/cf-api/src/allowlist/identity.ts` | As for `platform`, including the Access selector and target normalization |
| `exposure` | Exposure evaluator v1 | `packages/exposure/**` | Table-driven tests cover the precedence rules of the graph contract, including `unknown` |
| `rules` | Findings lifecycle (`evaluateRules`) and the phase 1 rules CF-002, CF-003, CF-004, CF-007, CF-009, CF-010, CF-011, CF-021, CF-022, CF-024 | `packages/rules/src/evaluate.ts`, `packages/rules/test/evaluate*.test.ts`, `rules/CF-0xx/` for those rules, `packages/rules/src/*.gen.ts` | Each rule has positive and negative fixtures written against the graph contract; the lifecycle tests cover not evaluated, resolve, reopen and suppression |
| `scan` | Scan Workflow: scheduled dispatcher, per-account scan with chunked collector steps, coverage, sweep, exposure and rule steps; account index D1; `GraphReader` entrypoint | `apps/core/**` | A Workflow test runs a full scan against a fixture transport with stub collectors, and shows `no_permission`, partial coverage without a sweep, and deterministic instance IDs |

## Packages for phase 1, round 2

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `e2e` | End-to-end test of a full scan: a seeded fake account served through the fixture transport, run through the real collectors, scan orchestration, exposure evaluator and rules | `apps/core/test/e2e/**` | A test scans a fake account with at least one seeded case per phase 1 rule and a clean counterpart each, and compares coverage, exposure and findings with an expected list. Cross-package mismatches are reported, not patched |
| `undecided` | "Unknown is a result" for findings: an optional `decided` output column (0 = undecided) keeps a finding in its current state; rules that read exposure return undecided rows where the relevant exposure is `unknown`; fixtures can expect undecided rows | `packages/rules/src/{evaluate,fixtures,parse,types}.ts`, `packages/rules/test/**`, `rules/**`, `packages/rules/src/*.gen.ts`, the rule sections of `docs/architecture/data-model.md` | Lifecycle tests show that an undecided row neither opens nor resolves; every rule that reads exposure has a fixture for the unknown case |
| `access-v2` | The round 2 items of the graph contract in the identity collectors and the exposure evaluator: overrides, `all_workers`, verbatim Access paths, tunnel hostname IDs with the tunnel ID, `access_required`, `service_token.enabled`, `member.two_factor_enabled` | `packages/collectors/src/identity/**`, `packages/collectors/test/identity/**`, `packages/exposure/**` | Collector output and evaluator match the contract with no "round 2" notes left; override paths are `public`; tests cover each item |
| `web` | Web Worker: static SPA (React, Vite), JSON API and MCP server (`createMcpHandler`, read-only tools), behind Worker-level Access with `ctx.access` and JWT validation; onboarding form using the broker's `TokenIntake` | `apps/web/**` | Every request without a valid Access identity is refused; every string from a scanned account is rendered as text and marked untrusted in MCP output; tests cover the API and MCP tools against a stubbed `GraphReader` |
| `deploy` | `scripts/deploy.ts` (idempotent setup and deploy in dependency order, dry-run mode), dry-run deploys in CI, operator guide | `scripts/**`, `docs/operator/**`, `.github/workflows/ci.yml` | `wrangler deploy --dry-run` passes for every Worker in CI; the guide covers deployment, Access for the UI, creating tokens per profile with the exact permission list, and onboarding |
| `review` | Read-only security review of everything merged | none (report only) | A report of verified findings with severity, location and a proposed fix |

Round 2 status (2026-10-30): all five builders are merged, CI is green, and the end-to-end scan test passes on top of `access-v2` and `undecided`. The security review is in [docs/reviews/2026-10-30-security-review.md](../reviews/2026-10-30-security-review.md): 2 high, 3 medium, 5 low.

- R2-02 is fixed by `undecided`, and R2-05 by `access-v2`.
- R2-10 is fixed by the integrator: `minimumReleaseAge` in `pnpm-workspace.yaml`.
- R2-01 is decided in [decision 0003](../decisions/0003-bypass-and-service-auth-exposure.md).
- The rest goes to round 3.

## Packages for phase 1, round 3

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `fix-exposure` | R2-01 (decision 0003) and R2-03 in the exposure evaluator | `packages/exposure/**` | Tests reproduce each finding's scenario and pass with the fix; the graph contract's exposure semantics hold |
| `fix-collectors` | R2-04, R2-06, R2-09; `Pages Metadata Read` as the pages permission | `packages/collectors/src/**`, `packages/collectors/test/**` | Tests reproduce each finding and pass |
| `fix-rules` | R2-08 (CF-003); the rule changes `access-v2` asked for: CF-011 covers a whole host for hostname paths `""`, `/` and `/*`, `all_workers` reach in CF-010, CF-011 and CF-002, CF-004 fixtures with `<tunnel_id>:` IDs and `access_required`; compiler fixture checks by prefix (`positive-`, `negative-`, `undecided-`; rules that read exposure need an undecided fixture); export `decidedOf` | `rules/**`, `packages/rules/src/` except `evaluate.ts`, `packages/rules/test/` except `evaluate*.test.ts`, `packages/rules/src/*.gen.ts` | `pnpm rules:build` passes with the stricter checks; every changed rule has fixtures for the new cases |
| `fix-core` | R2-07 (a stale or superseded scan cannot write); `GraphReader.listAccounts`; `Admin.removeAccount` (index rows and the account's graph storage); migration 2 adding `undecided` and `error` to `rule_runs`, written by `evaluateRules` and summed in the scan counters | `apps/core/**`, `packages/graph/src/schema.ts`, `packages/graph/test/**`, `packages/rules/src/evaluate.ts`, `packages/rules/test/evaluate*.test.ts` | Tests cover each item; the web Worker's account list works against the real `GraphReader` signature |
| `review-2` | Read-only security review of what round 2 added: `apps/web`, `scripts/`, the `access-v2` and `undecided` changes | none (report only) | A report of verified findings |

Round 3 status (2026-10-30): all four fix packages are merged, and every finding of the round 2 review is fixed. The second review ([round 3 report](../reviews/2026-10-30-security-review-round-3.md)) found 1 high, 2 medium and 4 low issues in what round 2 added. The contract already describes the target behaviour for R3-01 and R3-02.

## Packages for phase 1, round 4

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `fix-tunnels` | R3-01 (`access_required` only from the rule's own block) and R3-02 (rules without a hostname become `via_fallthrough` entry points per hostname), as the graph contract now says | `packages/collectors/src/identity/**`, `packages/collectors/test/identity/**`, `packages/exposure/**`, `apps/core/test/e2e/**` | Tests reproduce both findings end to end (collector, evaluator, CF-004) and pass |
| `fix-deploy` | R3-03 to R3-06 | `scripts/**`, `docs/operator/**` | Tests reproduce each finding and pass; the dry run still passes |
| `fix-lifecycle` | R3-07; a sweep never moves `current_scan`; CF-024 also reports Pages plain-text env vars | `packages/rules/src/evaluate.ts`, `packages/rules/test/evaluate*.test.ts`, `packages/graph/src/write.ts`, `packages/graph/test/**`, `rules/CF-024/**`, `packages/rules/src/*.gen.ts` | Tests cover each item |
| `offboarding` | Account removal end to end: web route and UI (admin only) calling `TokenIntake.remove`, then `Admin.removeAccount`; the broker also clears the account's rate budget; the scan summary shows undecided and error counts | `apps/web/**`, `apps/broker/src/token-intake.ts`, `apps/broker/src/rate-budget.ts`, `apps/broker/test/**`, `apps/core/src/graph/**` | Tests cover removal and the summary |
| `review-3` | Read-only verification: are R2-01 to R2-10 really fixed? Review of the round 3 changes | none (report only) | A report per finding: fixed or not, with evidence; new findings verified |

Round 4 status (2026-10-30): all four packages are merged; R3-01 to R3-07 are fixed, and account offboarding works end to end. The [verification review](../reviews/2026-10-30-verification-round-4.md) confirms R2-01, R2-03 to R2-07 and R2-09. It rates R2-02, R2-08 and R2-10 as partly fixed (variants R4-02, R4-06, R4-07) and found four new low-to-medium issues in the round 3 code (R4-01, R4-03 to R4-05).

## Packages for phase 1, round 5

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `fix-exposure-3` | R4-01 | `packages/exposure/**` | A test reproduces the finding and passes |
| `fix-rules-3` | R4-02 (CF-021); R4-06 (canonical CIDRs from the tokens collector, so CF-003 sees every spelling); R4-04 and R4-05 in the compiler (inputs derived from the tables a rule reads, writes rejected); CF-004 fixtures with `via_fallthrough` | `rules/**`, `packages/rules/src/` except `evaluate.ts`, `packages/rules/test/` except `evaluate*.test.ts`, `packages/collectors/src/identity/tokens.ts`, `packages/collectors/test/identity/tokens*` | Tests reproduce each finding and pass |
| `fix-core-3` | R4-03 (a removed account cannot be scanned again); `GraphReader` reports a suppression past its end as open; a CF-024 Pages case in the end-to-end test | `apps/core/**` | Tests cover each item |
| `supply-chain` | R4-07: a CI check that every version in the lockfile was released at least 14 days before the check runs; re-resolve the versions that fail it | `scripts/check-release-age.ts` and its tests, `.github/workflows/ci.yml`, `pnpm-lock.yaml`, the `scripts` field of the root `package.json` | CI fails on a too-young version; the lockfile passes |
| `docs` | Apply the documentation changes requested in round 4; ADR for the scope of CF-024; review status tables | `docs/**`, `apps/broker/README.md`, `apps/core/README.md` | Every request is applied or answered |
| `review-4` | Read-only verification of R3-01 to R3-07; review of the round 4 changes | none (report only) | A report per finding: fixed or not, with evidence; new findings verified |

Round 5 status (2026-10-30): all five packages are merged. R4-01 to R4-07 are fixed, except the collector half of R4-02 (r2.dev with an unknown `enabled`). A lockfile check enforces the 14-day minimum release age in CI.

- Open trade-off: to pass the age gate, the lockfile went back to body-parser 2.3.0 and fast-uri 3.1.8, which have published advisories. Both reach `apps/web` through the MCP SDK. The patched versions, body-parser 2.4.0 and fast-uri 3.1.9, are old enough on 2026-11-05 and 2026-11-02; an exception in the age gate is a decision for the maintainer.
- The [round 5 verification](../reviews/2026-10-30-verification-round-5.md) rates R3-01 and R3-04 to R3-06 as fixed. It rates R3-02, R3-03 and R3-07 as partly fixed, and found R5-01 to R5-08.

## Packages for phase 1, round 6

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `deploy-hardening` | R5-01 (`__proto__` and other parser differences), R5-02 (`unsafe`, `workflows`, `build` and every other key Wrangler deploys), R5-03 (`.env` files Wrangler loads) | `scripts/**`, `docs/operator/**` | Tests reproduce each finding and pass; the dry run passes |
| `tunnels-limits` | R5-04 to R5-06 as the graph contract now says; the collector half of R4-02 (r2.dev domain with `enabled: null`); R5-07 (Pages env vars the API did not return are unknown, not empty) | `packages/collectors/src/**`, `packages/collectors/test/**`, `packages/exposure/**`, `apps/core/test/e2e/**` | Tests reproduce each finding and pass |
| `core-offboarding` | R5-08: removal order and markers such that a partial failure never hides an account with data left | `apps/core/**` except `test/e2e/**`, `apps/web/src/**` if the route needs to change | Tests cover each failure point |
| `docs-2` | Apply the documentation changes requested in round 5; document `pnpm check:release-age`; update the review status tables | `docs/**` except `team/`, `CONTRIBUTING.md`, `CLAUDE.md`, `apps/broker/README.md`, `apps/core/README.md` | Every request is applied or answered |

## Rules for every work package

- Stay inside the owned paths. `pnpm-lock.yaml` and the own `package.json` may change; the integrator regenerates the lockfile on merge.
- Contract changes go into the report, not into the code.
- New dependencies only when necessary, pinned exactly, and released at least two weeks ago.
- No real Cloudflare credentials and no network calls in tests. API shapes come from the API reference on developers.cloudflare.com, written as fixtures.
- Read-only always (see CLAUDE.md, non-negotiables).
- Before committing: `pnpm install`, the package's own typecheck and tests, and `pnpm lint`.
- Commits carry a DCO sign-off. Branches are not pushed; the integrator merges them.

## Integration

The integrator merges in dependency order: `broker` and `exposure` first, then `platform`, `identity`, `rules` and `scan`. After each merge: `pnpm install`, `pnpm rules:build`, `pnpm ci`. Conflicts in owned paths go back to the work package; conflicts in shared files are the integrator's.
