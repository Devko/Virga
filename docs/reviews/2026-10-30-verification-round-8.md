# Verification review, round 8

- Date: 2026-10-30
- Scope: (1) are the findings of the [round 6 verification](2026-10-30-verification-round-6.md) (R6-01 to R6-07) and the [round 7 review](2026-10-30-review-round-7.md) (R7-01, R7-02) fixed? (2) review of the round 8 changes, `git diff b8a29c1..13fd01c`, and the code paths they change or rely on, at commit 13fd01c
- Status: round 9 of the [work packages](../team/work-packages.md) fixed R8-01 to R8-03 (`supply-chain-3`, and `deploy-3` for the build half of R8-02), the source side of the leads R8-04 and R8-05 (`deploy-3`, `supply-chain-3`), and the guard hardening (`rules-6`). The [round 9 verification](2026-10-30-verification-round-9.md) confirms all of them as fixed. The deciding facts of R8-04 and R8-05 (the deploy branch's rules) and the leads R8-06 to R8-11 stay open

| Finding | Fixed by | Commits | Test |
| --- | --- | --- | --- |
| R8-01 | `supply-chain-3` | a69a96e, 37dbfbf, e67526e | `scripts/test/check-release-age.test.ts` (R8-01: `configDependencies` as a block key, a quoted key, in a flow map, under an anchor or merge key, nested, and in `package.json`; settings that make pnpm read another lockfile or run code; the committed `pnpm-workspace.yaml`) |
| R8-02 | `supply-chain-3` (gate), `deploy-3` (builds) | 47e59b3; 6c0722e | `check-release-age.test.ts` (R8-02: a pin or `devEngines.packageManager` in `apps/web/package.json`, `.corepack.env` at any depth, a nested `pnpm-workspace.yaml`, symbolic links); `steps.test.ts`, `run.test.ts`, `config.test.ts`, `deploy.test.ts` (R8-02: builds start at the root with `COREPACK_ENV_FILE=0`; app-level pins refused before and after the builds) |
| R8-03 | `supply-chain-3` | a2d141b | `check-release-age.test.ts` (R8-03: with an exception for `a@1.0.0`, a foreign tarball, a tarball without integrity and a sha384 integrity with `version: 1.0.1` still fail; an exception accepts only the failure and resolution it names) |
| R8-04 (source side) | `deploy-3`, `supply-chain-3` | 646af7d; d2d5c8d | `scripts/test/guide.test.ts` (the guide's deploy example needs `release-age`, which installs nothing; the check runs before every install the guide shows); `check-release-age.test.ts` (R8-04: every file in `.github/workflows`) |
| R8-05 (source side) | `deploy-3`, `supply-chain-3` | f10c4f2; d2d5c8d | `packages/rules/test/generate.test.ts`; `deploy.test.ts` and `run.test.ts` (R8-05: a stale `rules.gen.ts` or a rule that fails the compiler stops the deploy before any Wrangler call; a generated module changed after its check is refused before the next one); `ci.yml`: `deploy-dry-run` needs `check` |
| Guard hardening | `rules-6` | 8d03dfd, f8977d9, 2c214c5, bd627b0, c3ab3db | `apps/core/test/rules-runtime.test.ts` (R8 hardening in workerd: drop and re-create, a `$name(...)` variable, the shadowing view, `defer_foreign_keys`, every committed rule still runs); `packages/graph/test/node.test.ts`; `packages/rules/test/params.test.ts` and `compile.test.ts` (placeholders). [Decision 0006](../decisions/0006-read-only-rule-runs.md) |

## Summary

Read-only review. No tracked file was changed. It ran in two parts:

- Two read-only reviewers (rules, deploy) at 7908d53, before the last round 8 merges. Their five leads went into the audit as candidates.
- A scoped security audit at 13fd01c in six phases: reconnaissance, 12 hunters in three waves with a coverage critic after each wave and a final clean critic, 14 candidate verifiers, and a fresh verifier for every record that was kept. 47 agents in all.

Target code ran only in a sandbox: WSL with a loopback-only network, an empty environment plus an allowlist, a read-only copy of 13fd01c under a tmpfs overlay, and cgroup and rlimit limits. No check contacted the Cloudflare API, the npm registry, GitHub or a deployed Worker. The audit's full reports (REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md, the coverage ledger and the records) are kept outside the repository.

All round 8 fixes hold where they were applied. The three confirmed findings are in the release-age gate. The eight leads need a fact that the repository and the sandbox cannot show: most of them a Cloudflare API shape, two of them GitHub settings of the deploy branch.

Not covered (out of scope for a scoped run, candidates for a later full run): the per-app `wrangler deploy` scripts, offset pagination in the collectors, the second tunnel listing in `tunnelsCollector.collect`, tunnels with an unexpected `config_src`, page-based listings through `listByPage`, and the other entry-point reads in the Workers and Pages collectors. None of these lines changed in round 8.

## Verification of R6-01 to R6-07, R7-01 and R7-02

| Finding | Status | Evidence |
| --- | --- | --- |
| R6-01 | fixed | `deploy.ts` runs every build before it compares the recorded Wrangler, runs `checkAppDir` again and reads and hashes each config. Before every Wrangler spawn, `wranglerProblem` compares the config's sha256 with the checked bytes, the `.env` files and the Wrangler closure. With the real install, `recordWrangler` hashed all 139 files that Wrangler loads at start (1,703 entries). An edit to `miniflare/dist/src/index.js` and a planted `node_modules/.pnpm/node_modules/bufferutil` were both named by `wranglerChanges`. The deploy, wrangler, run, config, vite-config and steps tests passed (116). Left as hardening: the link check covers only `apps/<app>`, while core and broker bundle `packages/*/src` |
| R6-02 | fixed | The compiler refuses a tail in two independent layers: the parameter scan and SQLite's own statement boundary (`sourceSQL`). Node SQLite 3.53.4 and workerd 1.20261012.1 carry the same SQLite source id, so they agree on where a statement ends. In workerd, a `DELETE FROM exposure` tail ends the rule `error` and keeps the row and the finding. Two guard gaps reproduce with the compiler bypassed (see Hardening) but are not reachable. Lead R8-05: the deploy does not bind `rules.gen.ts` to compiler output |
| R6-03 | fixed | No accepting differential was found between the strict lockfile reader and pnpm 10.28.0: comments, tabs, anchors, explicit keys, multi-line values and duplicate keys are refused. pnpm checks the downloaded tarball against the locked integrity, which the gate compares with the registry's digest |
| R6-04 | partly fixed | The root `packageManager` and `devEngines.packageManager` are dated, and a URL, range or tag there is refused. Corepack also reads a nested `packageManager` and `.corepack.env`, which the gate never sees: R8-02 |
| R6-05 | fixed | `inspectText` returns `looks_secret` `null` for every value that is not a string, for Pages and Worker `plain_text`. The R6-05 cases keep CF-024 undecided. Gaps around the value, not in it: leads R8-08 and R8-11 |
| R6-06 | fixed | A managed response without `domain` while not disabled, a custom response without a `domains` array, and an enabled entry without `domain` fail the storage chunk; CF-021 is `not_evaluated` and the finding stays open. The same pattern remains in sibling reads: leads R8-09 and R8-10 |
| R6-07 | fixed | `finishRun` sets `last_scan_at` only when `scan_runs` still holds the run and the run began at or after `accounts.created_at`. In workerd, with the real Admin, `d1ScanIndex`, `runScan` and `AccountGraph`, four interleavings of removal, re-adding, queued and retried steps left the new account due. The worst case is an extra scan |
| R7-01 | fixed | `deploy.ts` refuses `NODE_DEBUG` and `NODE_DEBUG_NATIVE` before any app check, record or build, and `processRunner` refuses them again before every spawn. A child Node process with `NODE_DEBUG=child_process` and `*` started nothing, and the token never reached stderr. The run and deploy tests passed (48) |
| R7-02 | fixed | `LD_LIBRARY_PATH`, the macOS `DYLD_*` library and framework paths and `NODE_COMPILE_CACHE` are refused the same way, on every platform. Left as hardening: `DYLD_IMAGE_SUFFIX`, `DYLD_PRINT_ENV` and `DYLD_PRINT_TO_FILE` (not a finding: see Hardening) |

Round 8 changes checked without a new finding:

- **Tunnel nodes left out.** Every node over the props limit, the stop after 1,000 such nodes, the 1,000-node cap and the 1 MiB budget give a truncated reason, so `tunnels` is `partial` ([decision 0005](../decisions/0005-truncated-collection-coverage.md)). The size test measures what `serializeProps` measures, so no node the collector keeps is refused by the write path. The tunnel tests passed (43).
- **Removal offer after a 502.** UI only. The server still requires an admin identity, a same-origin JSON request and `confirm` equal to the account ID. A viewer's `DELETE` for the `removing` account gets 403.
- **Coverage detail in the SPA and MCP.** A truncated reason with `<img onerror>` markup renders as text in `span.untrusted`. In `get_scan_summary` it stays inside one escaped untrusted block.
- **Non-negotiables.** The only new API call site, `readDomains`, wraps `ctx.api.get` on the same paths as before. Round 8 adds no endpoint, cookie or CORS header. Token-shaped strings added in round 8 are synthetic.

## New findings

### R8-01 [medium] The release-age gate never dates pnpm `configDependencies`, which pnpm 10.28.0 installs and, for plugin names, runs on every pnpm command in CI and in the deploy

Area: supply chain. Location: `scripts/check-release-age.ts:910`

**Scenario**

The gate dates only `pnpm-lock.yaml` entries and the pnpm version in `packageManager`. pnpm 10.28.0 also installs `configDependencies`, declared in `pnpm-workspace.yaml` or in `package.json` `pnpm.configDependencies` as version plus integrity, outside the lockfile. It installs them when it loads its config, before any lockfile work. A `pnpm-plugin-*` config dependency is loaded as a pnpmfile on every later pnpm command. 13fd01c declares none, so a commit has to add one, and a release of it younger than 14 days has to be malicious.

**Fix**

In `main`, also read `pnpm-workspace.yaml` strictly, the way R6-03 reads the lockfile: only the block layout and the keys the project uses (`packages`, `onlyBuiltDependencies`, `minimumReleaseAge`, `minimumReleaseAgeExclude`). Refuse anything else with its line number. Refuse a `package.json` `pnpm` field that is not an object or that holds `configDependencies`. The project has no config dependencies, so refusing them is the simplest correct gate. Update CONTRIBUTING.md, the CI comment and the operator guide.

**How it was verified**

`main()` on a fixture whose `package.json` pins `pnpm.configDependencies` `{pnpm-plugin-young: 1.0.0+sha512-...}`, published one day before the check, returned 0. The stub registry was asked only for the locked package and pnpm. pnpm 10.28.0 then installed the config dependency and ran its pnpmfile on `pnpm store path` and on the deploy's `pnpm run build`.

### R8-02 [low] The gate dates only the root `packageManager`, while corepack runs the deploy's builds with the app directory's own pnpm pin and `.corepack.env` (R6-04 variant)

Area: supply chain. Location: `scripts/check-release-age.ts:549`

**Scenario**

`build()` starts `pnpm run build` with `cwd` `apps/<app>`. On a workstation where `pnpm` is corepack's shim (the guide prescribes `corepack enable`), corepack 0.36.0 takes the nearest `package.json` that names `packageManager` and loads a `.corepack.env` from the directories it walks. The gate reads only the root `package.json`. So `"packageManager": "pnpm@<young>"` in `apps/web/package.json`, or a URL pin there together with `apps/web/.corepack.env` holding `COREPACK_ENABLE_UNSAFE_CUSTOM_URLS=1`, passes the gate. The deploy's build then runs that pnpm as a direct child of the process that holds the deploy token. A `.corepack.env` that redirects the registry needs `COREPACK_INTEGRITY_KEYS=0` too and acts only on a cold corepack cache. The CI path (pnpm/action-setup) is not shown to be affected.

**Fix**

- `check-release-age.ts`: refuse `packageManager` or `devEngines.packageManager` in any `package.json` other than the root, and any `.corepack.env`, anywhere in the checkout outside `node_modules` and `.git`.
- `steps.ts`: start each build at the root as `pnpm --dir apps/<app> run build`, so corepack reads the root pin.
- `run.ts` `childEnv`: set `COREPACK_ENV_FILE=0` for builds.
- Optionally pin the root with its sha512 (`pnpm@10.28.0+sha512.<digest>`), which the gate already compares and corepack enforces against any registry.
- CONTRIBUTING.md: only the root `package.json` may name a package manager.

**How it was verified**

In the sandbox, with fixed registry data (pnpm 10.33.2 published 2026-10-27, now 2026-10-30), `main()` returned 0 for every modified tree. With 10.33.2 in the root it returned 1 ("too young"), and with the URL in the root it returned 1 ("not an exact version"). The deploy's real `build()` through `processRunner` then made corepack log "apps/web/package.json defines pnpm@10.33.2", and a stand-in for that version ran with `run build`. It could read the dummy token marker from its parent's `/proc/<pid>/environ`. Reproduced three times by independent agents.

### R8-03 [low] A release-age exception for `name@version` also accepts a non-registry or unverifiable resolution under the same lockfile key

Area: supply chain. Location: `scripts/check-release-age.ts:868`

**Scenario**

An exception is matched by the lockfile key alone. CONTRIBUTING.md says an exception never accepts an integrity mismatch, and for a registry resolution it does not. But under the same key, a tarball from another host is reported `not_registry`, and an integrity in an algorithm the registry does not publish together with a `version:` field is reported `unverified`. The exception accepts both, so the bytes pnpm installs are no longer the registry's bytes for that version.

**Fix**

For a registry key, an exception accepts only `too_young`, which the check reaches only after the locked integrity matched the registry. A non-registry exception names its exact resolution (tarball, commit or directory, and integrity), and the check compares it with the locked one. `unverified` and `mismatch` are never accepted. Update the existing directory exception test and add the three cases.

**How it was verified**

With `EXCEPTIONS` `[{package: 'a@1.0.0'}]`: `a@1.0.0` with a foreign sha512 and the registry source is a mismatch failure. The same integrity with tarball `https://attacker.invalid/a-1.0.0.tgz`, and a sha384 integrity with `version: 1.0.1`, gave failures `[]` and exit 0. Both fail without the exception.

## Leads that need validation

These have a source trace that holds and a local reproduction of Virga's side. The deciding fact is outside the repository. They have no severity. Each lead names the owner check that settles it; all of them use a dedicated test account or read-only settings, never production.

| Lead | Area | What reads as clean | Deciding fact |
| --- | --- | --- | --- |
| R8-04 | deploy | The guide's "Deploy from CI" example and the workstation steps install the commit's pnpm and packages without the release-age gate that guide.md:185 relies on. The guard test reads only `ci.yml` | Whether the deploy branch's rules require `release-age`, and whether the real deploy workflow runs only on commits that passed it |
| R8-05 | deploy, rules | `scripts/deploy.ts` ships the committed `rules.gen.ts` without comparing it with compiler output. A tail added by hand runs on Durable Object SQL and resolves findings; only CI's `rules:check` catches it | Whether the deploy branch requires the CI `check` status, with no bypass |
| R8-06 | collectors | Tunnel ingress the collector cannot read (a non-object `config`, a non-array `ingress`, rules without a string `service`, keys in another case) counts as no entry point, and CF-004 resolves with `tunnels` complete. The R6-06 pattern, in tunnels | Whether the tunnel configurations endpoint stores and returns such shapes |
| R8-07 | collectors | Shadowing folds hostname case (`tunnels.ts:201`), so a mixed-case rule hides a later origin rule, and CF-004 resolves | Whether cloudflared matches the configured hostname case-sensitively |
| R8-08 | collectors | A Worker version or Pages project returned with `result` `null`, without `resources.bindings`, or a deployments result without `deployments`, is dropped or read as having no variables, and CF-024 resolves. Includes the R5-07 Worker leftover | Whether the API answers 200 with these shapes |
| R8-09 | collectors | An R2 bucket list without a `buckets` array reads as zero buckets (`storage.ts:96`); every bucket is swept and CF-021 resolves | Whether `GET /accounts/{id}/r2/buckets` ever answers success with that shape |
| R8-10 | collectors | R2 reads never send `cf-r2-jurisdiction`, and every 404 on a listed bucket's domain reads means "bucket deleted". A public `eu` or `fedramp` bucket can read as having no entry point | Whether the domain reads answer 404 for such a bucket without the header. Wrangler 4.151.0 sends the header on the same reads |
| R8-11 | collectors | `detectSecret` inspects the first 16 KiB of a value and reports the rest as clean, so a secret after 16 KiB resolves CF-024 (recorded as remaining in the [round 4 verification](2026-10-30-verification-round-4.md)) | Whether Cloudflare stores and returns a plain-text value that long |

For R8-04 and R8-05, a source fix is possible without the deciding fact: test every workflow and the guide's example with the existing `ungated()` rule, add `release-age` and `rules:check` to the guide's deploy job, and let `deploy-dry-run` need `check`. For R8-06, R8-08, R8-09 and R8-11, failing the chunk or marking the value unknown costs nothing if the API never returns these shapes, and it keeps "unknown is a result".

## Hardening

Not findings. Each was checked and is either unreachable today or within a documented residual.

- **Guard: drop and identical re-create** (`packages/graph/src/sql.ts`, `guardRead`). In workerd 1.20261012.1, a tail `DROP TABLE exposure; <the same CREATE TABLE>` passes the guard: `total_changes()` does not count a drop, and the schema text is unchanged. Unreachable while the compiler refuses every tail. Fix: make the Durable Object read single-statement by construction, for example by running `SELECT * FROM (<sql>)`, and add the case to `apps/core/test/rules-runtime.test.ts`.
- **Guard: settings read shadowed by a view.** A view named like a `pragma_*` function makes the settings read fail or lie, so a changed setting stays on the connection. Unreachable for the same reason. Fix: read settings with `PRAGMA <name>` and set all five back on every exit path.
- **Decision 0006 overstated the guard.** It said `case_sensitive_like` has no effect in workerd (it does: `'a' LIKE 'A'` went from 1 to 0) and `defer_foreign_keys` ends with the transaction (it survives the guard; the schema declares no foreign keys). Corrected in this round, with the drop and re-create gap, in the decision and the graph contract.
- **Wrangler record and the pnpm store** (`scripts/lib/wrangler.ts`). The record is trust on first use, and pnpm's shared store carries an in-place edit into a fresh clone. The guide's recovery (deploy from a fresh clone) should also name the pnpm store and the deploy token. Consider `package-import-method=copy` and a deploy-only `--store-dir`.
- **Bundle inputs outside the app directory** (`scripts/lib/config.ts`). `checkAppDir` walks only `apps/<app>`, while core and broker bundle most sources from `packages/*` through workspace links. `migrations_dir` and `main` get no containment check.
- **Gate inputs.** A sha1 integrity is accepted when it equals `dist.shasum` although the registry publishes sha512. Settings that make pnpm read another lockfile (`gitBranchLockfile`, `sharedWorkspaceLockfile`, `lockfileDir`) and runtime downloads (`useNodeVersion`) are not refused. `.nvmrc` floats to the newest Node 22.
- **Deploy environment.** `redact` does not catch a token stored with a trailing newline. Builds get the operator's environment minus `CLOUDFLARE_`/`CF_`, including variables that make build tools load code. The uploaded web settings are added to the redaction list only after the builds. `DYLD_IMAGE_SUFFIX` only selects names in directories that already hold Node's libraries, and `DYLD_PRINT_ENV` acts at exec, before any check.
- **Rules.** `@name`, `$name` and `#name` placeholders are neither rewritten nor refused: they pass the fixtures and end `error` on every production run (fail-safe). Lifecycle tables need no `requires`.
- **Tunnels.** Sets keyed by strings over 16,383 characters grow quadratically (V8 hashes such strings by length alone): 297 ms for 800 rules of 16,384 characters. An unexpected `config_src` emits no entry point and no truncation.
- **Core.** `evaluateRules` returns `complete` when single rules end `error`. `addAccount` and `removeAccount` are not serialized per account. The guide says retained Workflow instances hold counters only; they also hold coverage detail and chunk units for 3 to 7 days.
