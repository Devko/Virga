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

| WP | Scope | Owns | Done when |
| --- | --- | --- | --- |
| `broker` | Credential broker Worker: token vault (AES-256-GCM envelope encryption), onboarding write check, `ApiCaller` with allowlist, rate budget Durable Object | `apps/broker/**`, `packages/cf-api/src/allowlist/core.ts` | Tests prove that a write-capable or long-lived token is rejected, calls off the allowlist and to other accounts are refused, tokens never appear in responses or logs, and the rate budget pauses before the quota runs out |
| `platform` | Collectors `zones`, `dns`, `workers`, `pages`, `storage` | `packages/collectors/src/platform/**`, `packages/collectors/test/platform/**`, `packages/cf-api/src/allowlist/platform.ts` | Each collector turns recorded API responses into exactly the nodes and edges of the graph contract; every path it calls is on the allowlist; a 403 becomes `NoPermissionError` |
| `identity` | Collectors `access`, `tunnels`, `tokens`, `members`, `insights`, `traffic` | `packages/collectors/src/identity/**`, `packages/collectors/test/identity/**`, `packages/cf-api/src/allowlist/identity.ts` | As for `platform`, including the Access selector and target normalization |
| `exposure` | Exposure evaluator v1 | `packages/exposure/**` | Table-driven tests cover the precedence rules of the graph contract, including `unknown` |
| `rules` | Findings lifecycle (`evaluateRules`) and the phase 1 rules CF-002, CF-003, CF-004, CF-007, CF-009, CF-010, CF-011, CF-021, CF-022, CF-024 | `packages/rules/src/evaluate.ts`, `packages/rules/test/evaluate*.test.ts`, `rules/CF-0xx/` for those rules, `packages/rules/src/*.gen.ts` | Each rule has positive and negative fixtures written against the graph contract; the lifecycle tests cover not evaluated, resolve, reopen and suppression |
| `scan` | Scan Workflow: scheduled dispatcher, per-account scan with chunked collector steps, coverage, sweep, exposure and rule steps; account index D1; `GraphReader` entrypoint | `apps/core/**` | A Workflow test runs a full scan against a fixture transport with stub collectors, and shows `no_permission`, partial coverage without a sweep, and deterministic instance IDs |

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
