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

Round 6 status (2026-10-30): all four packages are merged. R5-01 to R5-08 and the collector half of R4-02 are fixed, with tests that reproduce each finding; the [round 5 verification](../reviews/2026-10-30-verification-round-5.md) lists commits, tests and leftovers. No review has verified the round 5 and round 6 fixes yet.

- The body-parser 2.3.0 / fast-uri 3.1.8 trade-off from round 5 is unchanged.
- The Worker side of R5-07 (a version whose `resources.bindings` is missing) waits for evidence of the API shape (S-05 needs a paid account).

## Packages for phase 1, round 7

The integrator adds the CF-024 fixtures for the `unread` and `unknown` entries of `pages_project.plain_text_vars` (R5-07) directly.

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `collectors-4` | R5-06 leftovers: the 1 MiB props budget per tunnel; a truncated tunnel makes `tunnels` coverage `partial` ([decision 0005](../decisions/0005-truncated-collection-coverage.md)) | `packages/collectors/**`, `apps/core/**` | Tests at the budget boundary, with the review's long path, and a finding past the cap that stays open |
| `deploy-env` | R5-03 leftover: build Wrangler's environment from an allowlist; keep `assets.directory` inside the app directory | `scripts/**`, `docs/operator/**` | Tests per variable class and per path case; the dry run passes |
| `web-removing` | The `removing` state in the SPA (notice, retry, no Start scan) and in the MCP `list_accounts` description | `apps/web/**` | Render and route tests |
| `review-6` | Read-only verification of R4-01 to R4-07 and R5-01 to R5-08; review of the round 5 and round 6 changes | none (report only) | A report per finding: fixed or not, with evidence; new findings verified |

Round 7 status (2026-10-30): all four packages are merged.

- Decision 0005 and the 1 MiB props budget per tunnel are implemented, with an e2e test in which a finding past the cap stays open.
- Wrangler's environment comes from an allowlist. `NODE_OPTIONS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `LD_PRELOAD`, `LD_AUDIT`, `DYLD_INSERT_LIBRARIES` and `OPENSSL_CONF` stop the deploy, also in a dry run. `assets.directory` must stay inside the app directory.
- The SPA and the MCP tools show the `removing` state.
- The [round 6 verification](../reviews/2026-10-30-verification-round-6.md) confirms R4-01, R4-03, R4-06, R5-01 to R5-06 and R5-08. It rates R4-02, R4-04, R4-05, R4-07 and R5-07 as partly fixed, and found R6-01 to R6-07.

## Packages for phase 1, round 8

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `deploy-build` | R6-01: builds first, then the checks; the checked config bytes compared before every Wrangler call; Wrangler run from a verified location; symlinks in `spa/public` refused | `scripts/**` except `check-release-age.ts` and its test, `docs/operator/**`, `apps/web/vite.config.ts` | A test in which a build rewrites the config fails the deploy; the dry run passes |
| `supply-chain-2` | R6-03: a strict lockfile reader; R6-04: the pnpm version in `packageManager` under the age rule | `scripts/check-release-age.ts`, its test, `.github/workflows/**`, `CONTRIBUTING.md` | Tests for the three lockfile layouts and a young pnpm |
| `rules-5` | R6-02: bracket identifiers in the parameter scan, no statement tail, and rule runs that write nothing at run time | `packages/rules/**`, `packages/graph/**`, a new `apps/core/test/rules-runtime.test.ts` | Compile tests with `[x--];` and `[a;b]`; a runtime test in workerd |
| `collectors-5` | R6-05 (a Pages value that is null or not a string is uninspected), R6-06 (R2 responses without `domain` or `domains`), a `tunnel_hostname` over the props limit counted as truncation | `packages/collectors/**`, `apps/core/test/e2e/**` | Collector tests per case; e2e for R6-05 and R6-06 |
| `core-web-5` | R6-07 (`last_scan_at` only for a run the index holds); the MCP and SPA text for a `partial` class with resources left out; removal offered for a `removing` account whose summary fails | `apps/core/**` except `test/e2e/**` and `test/rules-runtime.test.ts`, `apps/web/**` except `vite.config.ts` | Tests per case |
| `review-7` | Read-only review of the round 7 changes | none (report only) | New findings verified with a concrete input |

Round 8 status (2026-10-30): all packages are merged and verified. The cloud session stopped part way and handed over to a local agent, which finished the round.

- Merged: `deploy-build` (R6-01), `supply-chain-2` (R6-03, R6-04), and the compiler half of `rules-5` (R6-02: bracket identifiers in the parameter scan, no statement tail).
- The local integrator added the run-time half of `rules-5` (45b6c73): rules run through `SqlRunner.queryReadOnly`, which rolls back any change of rows, schema or connection settings and ends the run `error` ([decision 0006](../decisions/0006-read-only-rule-runs.md)). `cursor.rowsWritten` alone would not do: it counts only the last statement.
- The local integrator ran `collectors-5` as two packages in parallel worktrees, `collectors-5-shapes` (R6-05, R6-06, e2e) and `collectors-5-tunnels` (a node over the props limit is left out and counts as truncation), next to `core-web-5` (R6-07, the MCP and SPA text for a `partial` class, removal for a `removing` account whose summary fails). All three are merged. The integrator added the R6-06 case of a custom entry without a domain (93a0d4e).
- The [round 7 review](../reviews/2026-10-30-review-round-7.md) found R7-01 (`NODE_DEBUG` prints the token) and R7-02 (`LD_LIBRARY_PATH` and the macOS `DYLD_*` paths load code into the deploy). The local integrator fixed both in `UNSAFE_VARS` (58e72bd), with `NODE_COMPILE_CACHE`; `processRunner` refuses them too.
- The [round 8 verification](../reviews/2026-10-30-verification-round-8.md) (two read-only reviewers and a scoped security audit) confirms R6-01, R6-02, R6-03, R6-05, R6-06, R6-07, R7-01 and R7-02 as fixed and R6-04 as partly fixed. It found R8-01 to R8-03, all in the release-age gate, and eight leads that need a Cloudflare API shape or GitHub settings to settle (R8-04 to R8-11). Decision 0006 and the graph contract overstated the run-time guard; both are corrected.

## Packages for phase 1, round 9

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `supply-chain-3` | R8-01 (config dependencies refused), R8-02 gate half (no `packageManager` outside the root `package.json`, no `.corepack.env`), R8-03 (an exception names its reason and source); every workflow under the release-age guard test; `deploy-dry-run` needs `check` | `scripts/check-release-age.ts`, its test, `CONTRIBUTING.md`, `.github/workflows/**` | Tests per finding; the real checkout passes the gate |
| `deploy-3` | R8-02 build half (builds start from the root, `COREPACK_ENV_FILE=0`, app-level pins refused); R8-05 (the deploy compares the generated rules with compiler output); R8-04 (the guide's deploy example and workstation steps run the release-age check first) | `scripts/**` except the gate and its test, `docs/operator/**`, `packages/rules/src/cli.ts` and a Node-only generate module | A stale `rules.gen.ts` stops the deploy; a test over the guide's example; the dry run passes |
| `rules-6` | Run-time guard hardening from the round 8 verification: a read is one statement on every adapter, settings always set back (with `defer_foreign_keys`), guard state a drop cannot keep where workerd offers one, unrewritten placeholders refused at compile time | `packages/graph/**`, `packages/rules/**` except the generate code, `apps/core/test/rules-runtime.test.ts`, `spikes/s03-do-sqlite/**`, decision 0006, the contract's "A rule run only reads" | Tests in workerd for the drop and re-create tail and the shadowing view; every rule still runs on both adapters |
| `web-export` | Phase 1 backlog 13: OCSF export of findings, the tool audit trail for UI, API and MCP calls, the non-affiliation notice in the UI footer (D-01) | `apps/web/**`, `apps/core/**` except `test/rules-runtime.test.ts`, a new `docs/architecture/ocsf-export.md`, the audit table in `docs/architecture/data-model.md` | Tests per route and per channel; untrusted strings stay data |
| `terraform-1` | Phase 1 backlog 14: the test range in Terraform (written, not applied); phase 4: fix snippets per rule ([decision 0007](../decisions/0007-later-phases-before-the-phase-1-gate.md)) | `infra/test-range/**`, `rules/*/fix/**` | A seeded case and a clean counterpart per phase 1 rule, listed in a manifest; snippets per rule; `rules:check` unchanged |
| `docs-4` | Phase 1 backlog 15: threat model v1; phase 4: the non-affiliation notice in the README and docs (D-01), versioning policy, changelog | `README.md`, a new `docs/architecture/threat-model.md`, a new `docs/release/**`, a new `CHANGELOG.md` | Every trust boundary has its threats, controls with file references, and residual risks with review IDs |
| `review-9` | Read-only review of the round 9 changes | none (report only) | A report per finding: fixed or not, with evidence; new findings verified |

Phase 2 logic started once `rules-6` was merged, because it changes `packages/graph`:

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `vulns-1` | OSV advisory matching for npm purls, CVSS severity rank, KEV, the rematch of existing `vulns` rows; an unknown match keeps `vulns` incomplete | a new `packages/vulns/**`, the vulns functions in `packages/graph/src/write.ts`, a new `docs/architecture/vulns.md` | Table-driven range tests; a match whose version or severity cannot be read is never written as harmless |
| `scanner-io-1` | Strict readers for osv-scanner, Trivy and gitleaks output (gate 6, with a seeded fuzz test), secrets masked at the boundary, CycloneDX 1.6 SBOMs (schema validation for gate 2 pending) | a new `packages/scanner-io/**`, a new `docs/architecture/scanner-io.md` | A report that breaks a type or a limit is rejected as a whole; no secret beyond its prefix in any output |

Round 9 status (2026-10-30): all nine packages are merged, and the [round 9 verification](../reviews/2026-10-30-verification-round-9.md) (two read-only reviewers) confirms R8-01 to R8-03, the source side of R8-04 and R8-05, and the guard hardening as fixed. It found R9-01 (medium: the gate does not read `.npmrc`, where `lockfile-dir` points pnpm at an undated lockfile) and R9-02 to R9-06 (low: an app `.npmrc` that fetches a Node runtime, two audit trail gaps, npm purl case between `scanner-io` and `vulns`, and `scanner-io` memory per value). The integrator recorded decisions 0008 to 0010 for `vulns` severity of `MAL-` advisories, the advisory mirror's egress and SBOM schema validation.

Not in round 9: the leads R8-06 to R8-11 wait for an observed API shape (S-05 and a test account), and the hardening notes outside these packages stay listed in the round 8 verification.

## Packages for phase 1, round 10

From the [round 9 verification](../reviews/2026-10-30-verification-round-9.md), decisions [0008](../decisions/0008-malicious-package-advisories.md) and [0010](../decisions/0010-cyclonedx-schema-validation.md), and leftovers that need no Cloudflare account. Decision 0009 (the advisory mirror) waits for the spike that settles its download format.

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `supply-chain-4` | R9-01 (the gate reads the root `.npmrc` strictly and refuses it below the root, also the gate half of R9-02); H-1 (`continue-on-error` and `if: always()` in the workflow guard); L-1 (file names compared with full case folding); the strongest integrity the registry publishes; an allowlist for `package.json` `pnpm` fields; an exact `.nvmrc` | `scripts/check-release-age.ts`, its test, `CONTRIBUTING.md`, `.github/workflows/**`, `.npmrc`, `.nvmrc` | Tests per finding; the real checkout passes the gate |
| `deploy-4` | R9-02 deploy half (an app `.npmrc` refused before and after the builds); L-2 (links of the workspace packages an app bundles); `migrations_dir` and `main` kept in the app; redaction of a token with a trailing newline and of the web settings before the builds; H-2 in the guide; test range: ignore saved plans and `*.tfvars.json`, tie the zone to the account | `scripts/**` except the gate and its test, `docs/operator/**`, `infra/**`, `.gitignore` | Tests per case; the dry run passes |
| `broker-2` | TM-04: `ApiCaller` rechecks a stored token when its last check is older than 24 hours, before it serves a call; a token that fails is removed and the call fails as unreadable | `apps/broker/**`, `packages/cf-api/**` | Tests for a passed, a failed and an unreachable recheck; no write endpoint added |
| `core-6` | TM-11 (a scan whose rules ended `error` is not `complete`); TM-09 (adding and removing one account serialized); audit purge throughput; a `vulns` rematch step with no feed configured (CF-001 stays `not evaluated` with a reason); guard baseline H-3 and decision 0006 wording H-4 | `apps/core/**`, `packages/graph/src/sql.ts` and its tests, `docs/decisions/0006-read-only-rule-runs.md` | Tests per case in workerd |
| `web-audit-2` | R9-03 (a refused MCP call over 64 KiB is recorded); R9-04 (one identity check for web and core); audit rows per request capped; export escaping and OCSF `untruncated_size` | `apps/web/**`, `docs/architecture/ocsf-export.md` | Tests per finding |
| `vulns-2` | R9-05 (npm names case-insensitive; the purl spelling in the data model); duplicate JSON keys rejected; decision 0008 (`MAL-` ranks critical); `package` nodes and `vulns` in the contract | `packages/vulns/**`, `docs/architecture/vulns.md`, `docs/architecture/data-model.md`, the package and vulns parts of `docs/architecture/graph-contract.md` | Tests per finding |
| `scanner-io-2` | R9-06 (containers bounded, measured in workerd); the gitleaks secret guard on partial matches; invisible characters in kept strings; decision 0010 (vendored CycloneDX 1.6 schema, `@cfworker/json-schema` in tests) | `packages/scanner-io/**`, `docs/architecture/scanner-io.md`, the lockfile entries of the new dev dependency | Every SBOM the tests build validates against the schema |
| `review-10` | Read-only review of the round 10 changes | none (report only) | A report per finding: fixed or not, with evidence; new findings verified |

Round 10 status (2026-10-30): all seven packages are merged, and the [round 10 verification](../reviews/2026-10-30-verification-round-10.md) (one reviewer) confirms R9-01 to R9-06, L-1, L-2, H-2 to H-4 and the round 9 hardening items as fixed, and H-1 as partly fixed. It found R10-01 (medium: the gate does not see the root `.pnpmfile.cjs`, whose hook can point pnpm at an undated lockfile) and R10-02 to R10-04 (low: `package.yaml` with `pnpm.executionEnv`, the workflow guard read by indent and raw text, tsconfig `paths` past the L-2 checks). From round 10 on, packages run on Sonnet or Opus by risk: Opus for security-critical design work and every review, Sonnet for docs and well-specified packages.

## Packages for phase 1, round 11

From the [round 10 verification](../reviews/2026-10-30-verification-round-10.md). All three packages touch security-critical checks, so all three run on Opus.

| WP | Model | Scope | Owns | Done when |
| --- | --- | --- | --- | --- |
| `supply-chain-5` | Opus | R10-01 (`.pnpmfile.cjs` and `.pnpmfile.mjs` refused anywhere); R10-02 (`package.yaml` and `package.json5` refused); R10-03 (the workflow guard parses YAML, for `ci.yml` and the guide's example); `.npmrc` messages print only known keys; a fresh-checkout mode that refuses any `node_modules` in the release-age job (lead) | `scripts/check-release-age.ts`, its test, `scripts/test/guide.test.ts`, a new shared test helper, `CONTRIBUTING.md`, `.github/workflows/**` | Tests per finding with the review's inputs; the real checkout passes |
| `deploy-5` | Opus | R10-04 (tsconfig `paths` and `baseUrl`): every tsconfig and workspace `package.json` that esbuild can read for a bundle is recorded before the builds and compared before each Wrangler call; the guide's L-2 text | `scripts/**` except the gate, its test and `guide.test.ts`; `docs/operator/**` | The review's tsconfig case stops the deploy before Wrangler; the dry run passes |
| `hardening-11` | Opus | Broker: a delete or mark after a recheck matches the token it checked, not only its ID; identity: lone surrogates refused on both sides (`isWellFormed`) | `apps/broker/**`, `apps/web/src/auth.ts` and its tests, `apps/core/src/audit.ts` and its tests | Tests per item |
| `review-11` | Opus | Read-only review of the round 11 changes | none (report only) | A report per finding: fixed or not, with evidence |

Round 11 status (2026-10-30): all three packages are merged, and the [round 11 verification](../reviews/2026-10-30-verification-round-11.md) confirms R10-01 to R10-04 and the round 10 hardening items as fixed, and the committed-`node_modules` lead as partly fixed (the guide's Updates steps). It found R11-01 and R11-02 (low: a lone CR, NEL, LS or PS that hides a line from the workflow guard; a Yarn PnP manifest written by a build that retargets `@virga/rules` past the R10-04 record), and hardening for the broker's recheck after a removal.

## Rules for every work package

- Stay inside the owned paths. `pnpm-lock.yaml` and the own `package.json` may change; the integrator regenerates the lockfile on merge.
- Contract changes go into the report, not into the code.
- New dependencies only when necessary, pinned exactly, and released at least two weeks ago.
- No real Cloudflare credentials and no network calls in tests. API shapes come from the API reference on developers.cloudflare.com, written as fixtures.
- Read-only always (see CLAUDE.md, non-negotiables).
- Before committing: `pnpm install`, the package's own typecheck and tests, and `pnpm lint`.
- After any change to `pnpm-lock.yaml`: `pnpm check:release-age` (needs network access to registry.npmjs.org). A version younger than 14 days is removed from the lockfile and resolved again; exceptions go into `EXCEPTIONS` in `scripts/check-release-age.ts` (CONTRIBUTING.md).
- Commits carry a DCO sign-off. Branches are not pushed; the integrator merges them.

## Integration

The integrator merges in dependency order: `broker` and `exposure` first, then `platform`, `identity`, `rules` and `scan`. After each merge: `pnpm install`, `pnpm rules:build`, `pnpm run ci`. Conflicts in owned paths go back to the work package; conflicts in shared files are the integrator's.
