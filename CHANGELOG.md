# Changelog

All notable changes to Virga are recorded here. The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) as the [versioning policy](docs/release/versioning.md) applies it.

## [Unreleased]

No release exists yet. This section summarizes phase 1 so far: rounds 1 to 8 of the [work packages](docs/team/work-packages.md), up to commit 0812b03. Nothing has scanned a real account yet; the spikes and gates that need one are listed in the [threat model](docs/architecture/threat-model.md#open-items-that-need-the-paid-account-or-the-test-range).

### Added

- **Concept and plan.** The [design spec](docs/concept/design-spec.md), its [analysis](docs/analysis.md) with verified platform claims, and the [implementation plan](docs/implementation-plan.md) with phases, gates and spikes. Spike results for [S-02](docs/spikes/S-02-rate-limits.md), [S-03](docs/spikes/S-03-durable-object-sqlite.md) (locally) and [S-04](docs/spikes/S-04-worker-dependencies.md) (in part).
- **Decisions.**
  - [0001](docs/decisions/0001-working-defaults.md): working defaults for D-01 to D-15.
  - [0002](docs/decisions/0002-scan-scheduling.md): scan scheduling, instance IDs, hung scans.
  - [0003](docs/decisions/0003-bypass-and-service-auth-exposure.md): Bypass and Service Auth policies never count as protection by identity (R2-01).
  - [0004](docs/decisions/0004-cf-024-scope.md): one rule, CF-024, for Workers and Pages.
  - [0005](docs/decisions/0005-truncated-collection-coverage.md): a truncated collection makes coverage `partial`.
  - [0006](docs/decisions/0006-read-only-rule-runs.md): a rule run only reads, checked at run time (R6-02).
  - [0007](docs/decisions/0007-later-phases-before-the-phase-1-gate.md): work from phases 2 and 4 before the phase 1 gate.
- **Graph store** (`packages/graph`): schema with migrations, JSON batch upsert with hash-gated writes and history, sweep per complete resource class, `signals`, `coverage`, `exposure`, `findings` and `rule_runs`, Durable Object and Node adapters, and a read-only query path for rules. See the [data model](docs/architecture/data-model.md).
- **Graph contract** ([graph-contract.md](docs/architecture/graph-contract.md)): what collectors emit and what the evaluator and the rules may read.
- **Read client** (`packages/cf-api`): the read client contract, the read allowlist, typed errors, pagination and a fixture transport for tests.
- **Credential broker** (`apps/broker`): token vault with AES-256-GCM envelope encryption and the master key in Secrets Store or a Worker secret (D-15); onboarding write check; `ApiCaller`, which sends allowlisted reads only; `TokenIntake` to store, recheck and remove a token; rate budget per account.
- **Collectors** (`packages/collectors`): `zones`, `dns`, `workers`, `pages`, `storage`, `access`, `tunnels`, `tokens`, `members`, `insights` and `traffic`.
- **Exposure evaluator** (`packages/exposure`), version 1: Worker, Pages, R2 and tunnel entry points; Access hostname, path, Worker-level and account-level apps with overrides; `unknown` wherever the input cannot be decided.
- **Rules** (`rules/`, `packages/rules`): a compiler that refuses writes, statement tails and undeclared inputs, a fixture runner, and the findings lifecycle with undecided rows and expiring suppressions. Eleven rules: CF-001 (version 2), CF-002 (3), CF-003 (3), CF-004 (3), CF-007 (1), CF-009 (2), CF-010 (2), CF-011 (2), CF-021 (3), CF-022 (2) and CF-024 (2). CF-001 stays `not evaluated` until phase 2 supplies packages and vulnerabilities.
- **Core Worker** (`apps/core`): one `AccountGraph` Durable Object per scanned account; the scan Workflow with chunked collector steps, coverage, sweep, exposure and rule steps; the hourly dispatcher; the account index in D1; the `GraphReader` and `Admin` entrypoints; account removal.
- **Web Worker** (`apps/web`): the UI (accounts, coverage, rule runs, findings, finding detail with the graph neighborhood, onboarding, removal), the JSON API and an MCP server with five read-only tools, behind Worker-level Access with the Access token checked in code.
- **Deploy script** (`scripts/deploy.ts`): creates the D1 databases, applies their migrations, checks the master key and the configs against the deployment topology, and deploys the three Workers in order; a dry run needs no credentials.
- **Supply chain checks:** exact dependency versions, `minimumReleaseAge` of 14 days, and `pnpm check:release-age` in CI before any install (`scripts/check-release-age.ts`).
- **CI** (`.github/workflows/ci.yml`): the release-age gate, then lint, `rules:check`, typecheck, tests, script tests and a deploy dry run.
- **End-to-end scan test** (`apps/core/test/e2e`): a seeded fake account scanned through the real collectors, evaluator and rules.
- **Documentation:** the [operator guide](docs/operator/guide.md), the [threat model](docs/architecture/threat-model.md) v1, the [versioning policy](docs/release/versioning.md), this changelog, and the non-affiliation notice in the README (D-01).

### Security

Seven review rounds (2 to 8) ran on the code before any release. Each review lists its findings with the work package, commits and tests that fixed them.

- [Round 2 security review](docs/reviews/2026-10-30-security-review.md), R2-01 to R2-10 (2 high, 3 medium, 5 low): false "protected" exposure results from Bypass and Service Auth policies, Access wildcards and paths; findings resolved while exposure was unknown; tunnel credentials partly kept; writes from stale scans; CF-003 and the any-range; CF-024 and `json` bindings; dependency age not enforced. All fixed, R2-02, R2-08 and R2-10 through the round 4 follow-ups.
- [Round 3 security review](docs/reviews/2026-10-30-security-review-round-3.md), R3-01 to R3-07 (1 high, 2 medium, 4 low): `access_required` taken from the wrong tunnel config level; ingress rules without a hostname; Wrangler deploying a config the checks never read; the deploy token in Worker secrets and builds; D1 IDs; expired suppressions. All fixed, R3-02, R3-03 and R3-07 through the round 5 follow-ups.
- [Round 4 verification](docs/reviews/2026-10-30-verification-round-4.md), R4-01 to R4-07: a narrower Bypass hiding a token-issuing Service Auth policy; CF-021 and unknown domain state; scans after removal; rule inputs and writes the compiler missed; IPv6 spellings in CF-003; locked versions outside the age check. All fixed, R4-02, R4-04, R4-05 and R4-07 through the round 6 follow-ups.
- [Round 5 verification](docs/reviews/2026-10-30-verification-round-5.md), R5-01 to R5-08: Wrangler and the deploy check parsing configs differently; config keys the check ignored; `.env` files; tunnel ID collisions, long IDs and quadratic expansion; Pages env vars; removal order. All fixed, R5-07 through R6-05; the Worker half of R5-07 continues as lead R8-08, and the R5-08 leftovers are open.
- [Round 6 verification](docs/reviews/2026-10-30-verification-round-6.md), R6-01 to R6-07: configs checked before the builds ran; rule statement tails; the lockfile reader; the pnpm version; Pages values; R2 response shapes; `last_scan_at` after a removal. All fixed except R6-04, whose rest is R8-02.
- [Round 7 review](docs/reviews/2026-10-30-review-round-7.md), R7-01 and R7-02: `NODE_DEBUG` printed the deploy token, and `LD_LIBRARY_PATH` loaded code into the deploy. Both fixed.
- [Round 8 verification](docs/reviews/2026-10-30-verification-round-8.md): confirms the round 6 and round 7 fixes. Open: R8-01 to R8-03 in the release-age gate, the leads R8-04 to R8-11, and the hardening notes. The [threat model](docs/architecture/threat-model.md) lists each as a residual risk.
- The lockfile keeps body-parser 2.3.0 and fast-uri 3.1.8, which have published advisories, until their patched versions pass the age gate in November 2026 (TM-16 in the threat model).
