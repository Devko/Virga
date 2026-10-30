# Verification review, round 10

- Date: 2026-10-30
- Scope: (1) are the round 9 findings fixed: R9-01 to R9-06, the leads L-1 and L-2, the hardening items H-1 to H-4 and the other round 9 hardening items that the round 10 packages claim to close? (2) review of every round 10 change at commit e33ffca: `broker-2`, `vulns-2`, `supply-chain-4`, `web-audit-2`, `core-6`, `deploy-4` and `scanner-io-2`, each diffed against afeef0c
- Status: round 11 of the [work packages](../team/work-packages.md) fixed R10-01 to R10-04 and the hardening items; the [round 11 verification](2026-10-30-verification-round-11.md) confirms them, and the committed-`node_modules` lead as partly fixed

| Finding | Fixed by | Commits | Test |
| --- | --- | --- | --- |
| R10-01 | `supply-chain-5` | 8ccf3c1 | `scripts/test/check-release-age.test.ts` (R10-01: the review's `.pnpmfile.cjs` with an `updateConfig` hook; pnpmfiles and `.pnp.cjs` in any spelling) |
| R10-02 | `supply-chain-5` | 1bf346c | `check-release-age.test.ts` (R10-02: `apps/x/package.yaml` with `pnpm.executionEnv`; `package.yaml` and `package.json5` anywhere) |
| R10-03 | `supply-chain-5` | 51114a1 | `scripts/test/workflow-guard.ts`, used by `check-release-age.test.ts` and `guide.test.ts` (R10-03: the 5-space job and the escaped `always()`) |
| R10-04 | `deploy-5` | 3d19740, 319c1d8 | `scripts/test/workspace.test.ts`, `deploy.test.ts`, `run.test.ts` (R10-04: `paths` in `apps/core/tsconfig.json` or `tsconfig.base.json`, `exports` in `packages/rules/package.json`, a file changed before a Wrangler call) |
| Broker, same token ID | `hardening-11` | 9aebbe1 | `apps/broker/test/recheck.test.ts`, `vault.test.ts` ("R10 hardening: broker same token ID") |
| Identity check | `hardening-11` | 809590e | `apps/web/test/identity.test.ts`, `apps/core/test/audit.test.ts` (lone surrogates) |
| `.npmrc` messages, committed `node_modules` | `supply-chain-5` | 261409d, a523e4f | `check-release-age.test.ts` (".npmrc messages: …", "Fresh checkout: …") |

## Summary

Read-only review by one reviewer (Opus) in a disposable worktree at e33ffca. No tracked file was changed. Every check ran in WSL inside a network namespace with loopback only; nothing contacted Cloudflare, the npm registry, GitHub, osv.dev or cisa.gov, and every token or secret was synthetic. Corepack used its cached pnpm 10.28.0.

The full `pnpm run ci` passed at e33ffca: cf-api 6, graph 103, scanner-io 261, web 120, vulns 424, exposure 194, collectors 278, broker 154 (workerd), rules 449, core 314 (workerd), scripts 330; 2,633 tests. `rules:check` passed with 11 rules and 71 fixtures, and the deploy dry run passed offline. The gate's offline parts pass on the real checkout (workspace file, checkout walk, `.npmrc`, `packageManager`, 333 lockfile entries).

All round 9 items are fixed except H-1, which is partly fixed. The new findings are one medium (the gate does not see the root `.pnpmfile.cjs`) and three lows (`package.yaml` past the nested `pnpm` field check; the workflow guard read by indentation and raw text; tsconfig `paths` past the L-2 checks). The broker recheck, core's add and remove queue, the `partial` scan status, the `vulns` step, the guard's fixed defaults, and the web, `vulns` and `scanner-io` changes showed no defect.

## Verification of round 9

| Item | Status | Evidence |
| --- | --- | --- |
| R9-01 | fixed (the `.npmrc` path) | `main()` with fixed registry data returned 1 for a root `.npmrc` with `lockfile-dir=other`, and 0 for a BOM, CRLF, `#` and `;` comments and trailing spaces. An `_authToken` line returned 1 without printing the key or the value. pnpm 10.28.0 reads INI through `ini` 1.3.8, 3.0.1 and 4.1.1, all splitting on `[\r\n]+`; the reader accepts only blank lines, comment lines and two exact lines, so no differential remains. The same outcome is still reachable through `.pnpmfile.cjs`: R10-01 |
| R9-02, gate half | fixed | `apps/web/.npmrc` and `apps/web/.NPMRC`: `main()` returned 1 ("only the root may hold .npmrc"). A related path through `package.yaml`: R10-02 |
| R9-02, deploy half | fixed | `checkAppDir` refuses an app `.npmrc`; the config and deploy tests "R9-02: …" passed |
| R9-03 | fixed | A body over 64 KiB, by `content-length` or by the limited read, gets 413 and one `["unknown_tool", null, "refused"]` row, also above 4 MiB |
| R9-04 | fixed | `isIdentity` uses core's rule and length; the comparison test against core's `checkToolCall` passed. A lone surrogate passes both sides (hardening) |
| R9-05 | fixed | `npmPurl("JSONStream","1.3.1")` gives `pkg:npm/jsonstream@1.3.1`; `rematch` against a `JSONStream` advisory fixed in 1.3.6 with complete inputs keeps the row `open` (round 9: `fixed`) |
| R9-06 | fixed | `maxContainers` 100,000 and keys counted as values; the review's 499,996-value report is refused; the memory tests passed. Not measured in workerd by the reviewer |
| L-1 | fixed | `apps/web/pnpm-workſpace.yaml` (U+017F) and a root `.Npmrc` make `main()` return 1. Names are NFKC-normalized, stripped of default-ignorable characters, then upper- and lower-cased |
| L-2 | fixed (links) | The nine `workspace.test.ts` tests and the run and deploy tests "L-2: …" passed (retargeted, removed or added links, links or `node_modules` inside packages, the rules directory taken from the link). Core and broker bundle no third-party module. Past the checks through tsconfig `paths`: R10-04 |
| H-1 | partly fixed | A plain `if: always()` on an installing job is flagged. A `release-age` job indented by 5 spaces with `continue-on-error: true`, and `if: "\x61lways()"`, pass the guard: R10-03 |
| H-3 | fixed | `guardRead` compares the six settings with frozen defaults and fails closed before the query; the workerd tests "H-3: …" passed |
| H-4 | fixed | Decision 0006 and the `sql.ts` comment say that only whitespace may follow the `;` on Durable Object SQL |
| Audit amplification | fixed | At most 8 tool calls and 9 rows per MCP request (tests with batches of 12 and 100); the purge runs up to 50 steps of 100,000 rows an hour |
| Export escaping, `untruncated_size` | fixed | Every format and default-ignorable character is escaped, checked against the runtime's Unicode properties; `untruncated_size` is the whole record in KiB |
| Duplicate keys in `vulns` | fixed | An OSV record with a second `affected` is rejected ("duplicate key at offset 269"), its ID kept; the rematch is not complete and the old row is unchanged |
| Secret guard (gitleaks) | fixed | A file name with 23 or with 6 characters of a 24-character secret is rejected; 5 shared characters pass (by design); 7- and 4-character secrets are searched; no error holds the secret |
| Invisible characters (`scanner-io`) | fixed | U+200B and U+E0041 in `File` give `invalid_text` |
| Strongest integrity | fixed | A sha1 equal to `dist.shasum` fails while the registry publishes sha512 ("lock the sha512 integrity"), and passes when only sha1 is published |
| `.nvmrc` | fixed | `22.23.3` |
| H-2 | fixed | The guide names `yaml` and the workspace packages that the deploy loads into its own process |
| Test range | fixed (not run) | `.gitignore` covers saved plans and `*.tfvars.json`; the zone data source has a precondition and postconditions on ID, account and name, and resources take their IDs from it. No Terraform binary, so not run |
| TM-04 (broker recheck) | done | See below |
| Decision 0008 | done | A `MAL-` record without severity matched with rank 4 in a complete result |
| Decision 0010 | done | The sha256 of the three vendored schema files equals the README; upstream not checked (no network) |

Checked without a new finding:

- **Broker recheck (TM-04).** The claim is a conditional `UPDATE` on the token ID, `checked_at` and a lapsed claim; a release clears only its own claim; storing or marking a token clears claims, and a delete by token ID spares a token stored meanwhile under another ID. Waiting calls fail closed after 10 seconds. An unanswered recheck (429, 5xx, broker error) keeps the token and sends nothing; any other failure deletes it and answers 401. A waiting call never gets a deleted token. Logs carry the account ID and reason codes only.
- **Core.** Adding and removing one account are ordered inside its graph object, which refuses another account's ID and no longer offers `deleteAll` over RPC. A rule run that ended `error` makes the scan `partial`. Without a feed, `vulns` coverage is always `partial` and CF-001 stays `not_evaluated`; only rows of packages gone from a complete package set become `fixed`, and nothing writes package nodes yet.
- **MCP.** Refused attempts are matched by JSON-RPC ID, including duplicate IDs and notifications; the limit is counted per request and independent of the body parse, so a tool that runs is always recorded.
- **Deploy.** `main` and `migrations_dir`, the default included, are resolved with links followed and refused outside the app or inside its `node_modules`. The workspace record is keyed like the Wrangler record, so no Wrangler call skips the link check. The trimmed token is redacted.

## New findings

### R10-01 [medium] The release-age gate does not see the root `.pnpmfile.cjs`, which pnpm loads on every command; its `updateConfig` hook reopens R9-01

Area: supply chain. Location: `scripts/check-release-age.ts` (`checkCheckout` and `main` never look at `.pnpmfile.cjs`). pnpm 10.28.0 loads `.pnpmfile.cjs` from the lockfile directory or the workspace root whenever `pnpmfile` is not set, and runs its `hooks.updateConfig`.

**Scenario**

A commit adds a root `.pnpmfile.cjs` whose `updateConfig` hook sets `lockfileDir` to `other`, and an `other/pnpm-lock.yaml` with that file's `pnpmfileChecksum` and young versions. The gate dates the untouched root lockfile and passes. Every `pnpm install --frozen-lockfile` (CI's `check` and `deploy-dry-run`, the guide's deploy job, workstations) then installs from `other/`. The hook can set any setting the gate refuses by name, and the file also runs as code on every pnpm command, including the deploy's builds. CONTRIBUTING lists `pnpmfile` among the refused settings, and the threat model said "Left: none known" for TM-29.

**Fix**

Refuse `.pnpmfile.cjs` and `.pnpmfile.mjs` anywhere in the checkout walk, compared by folded name; or require `ignore-pnpmfile=true` in the root `.npmrc`. Update CONTRIBUTING, the CI comment and TM-29.

**How it was verified**

A scratch workspace pinned `yaml` 2.9.1 in `package.json` and locked 2.8.0 at the root; fixed registry data dated 2.8.0 at 400 days and 2.9.1 at 1 day. `main()` returned 0. `pnpm install --frozen-lockfile --offline` printed the marker from `.pnpmfile.cjs` and "+ yaml 2.9.1", and installed `other/node_modules/.pnpm/yaml@2.9.1`; `pnpm --version` printed the marker too. Without `pnpmfileChecksum`, pnpm refused (`ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`). Control without `.pnpmfile.cjs`: pnpm refused ("lockfile: 2.8.0, manifest: 2.9.1").

### R10-02 [low] A workspace project's `package.yaml` carries `pnpm.executionEnv` past the nested `pnpm` field check, and `pnpm -r` downloads and runs that Node

Area: supply chain. Location: `scripts/check-release-age.ts:1018` (the walk checks only `package.json`). pnpm 10.28.0 reads `package.json`, `package.json5` and `package.yaml` as manifests, and a recursive `run` takes `pnpm.executionEnv` from each project's manifest.

**Scenario**

A new project `apps/x/package.yaml` (matched by the `apps/*` glob) sets `pnpm.executionEnv.nodeVersion: 23.0.0` and has a `build`, `test` or `typecheck` script. The gate passes. `pnpm build`, and CI's `pnpm test` and `pnpm typecheck` (all `pnpm -r`), make pnpm fetch that Node and run the script with it. Round 10 refuses the same field in `package.json`. The mirror stays nodejs.org, since `node-mirror` is refused elsewhere, so the impact is an undated or outdated Node in CI.

**Fix**

Refuse `package.yaml` and `package.json5` anywhere in the walk (the project uses neither), or apply the nested manifest check to them.

**How it was verified**

In a scratch workspace, `main()` returned 0; `pnpm install --frozen-lockfile --offline` reported "Already up to date"; `pnpm run build` printed "Fetching Node.js 23.0.0 ..." and then failed on the namespace's missing network. `pnpm --dir apps/x run build` used v22.23.4, as round 9 saw. Control: the same field in `apps/x/package.json` made `main()` return 1.

### R10-03 [low] The workflow guard reads keys only at fixed indents and `if:` only as raw text (H-1 partly fixed)

Area: supply chain, CI. Location: `scripts/test/check-release-age.test.ts` (the job checks read job keys at exactly 4 spaces and step keys at fixed indents; the status-function check runs on the raw text)

**Scenario**

(a) The `release-age` job's keys are indented by 5 spaces, including `continue-on-error: true`, with its steps at 6. The guard sees no key, and the required `run: node scripts/check-release-age.ts` line still matches; a failed check no longer fails the job, and the jobs that need it install. (b) An installing job has `if: "\x61lways()"`, a YAML double-quoted escape; the guard finds no `always(`, but YAML yields `always()`.

**Fix**

Parse each workflow with a YAML parser in the test (`yaml` is already locked) and check the parsed jobs and steps; or refuse any indentation other than 2 per level and any quote or backslash in `if:` values. Apply the same to the guide's example in `scripts/test/guide.test.ts`.

**How it was verified**

With scratch workflows for (a), (b) and a control with a plain `if: always()`, the guard test reported only the control. `yaml` 2.9.1 parsed (a) with job-level `continue-on-error: true` and (b) with `if: always()`. GitHub itself was not observed (lead).

### R10-04 [low] tsconfig `paths` retarget `@virga/rules` past every L-2 check and the generated-rules digest

Area: deploy. Location: `scripts/lib/workspace.ts` (`recordWorkspace` checks links only), `scripts/lib/rules.ts` (`bundledRulesDir`), and the guide's L-2 bullet ("not from a copy elsewhere"). No deploy check reads a tsconfig file.

**Scenario**

A build writes `baseUrl` and `"paths": {"@virga/rules": [...]}` into `apps/core/tsconfig.json` or `tsconfig.base.json`. Wrangler's esbuild resolves `paths` before `node_modules`, so virga-core bundles another rules module, while the link still leads to `packages/rules`, the deploy checks the untouched `rules.gen.ts`, and every check before each Wrangler call passes. The capability is close to the documented residual (a build changes sources), but the guide claims this case is covered.

**Fix**

Record the sha256 of every tsconfig esbuild can read for the bundled sources (the app's file and its `extends` chain, `tsconfig.base.json`, `packages/*/tsconfig.json`) before the builds and compare it before each Wrangler call; or refuse `paths` and `baseUrl` in them. Correct the guide.

**How it was verified**

A scratch Worker whose `node_modules/@virga/rules` led to `packages/rules` and whose tsconfig mapped the name to another module: the repository's Wrangler 4.151.0 (`deploy --dry-run --outdir`) bundled the other module's marker once and "CF-001" zero times; without the tsconfig, the marker zero times and "CF-001" three times.

## Leads

- **H-1 on GitHub.** Whether GitHub's workflow parser reads R10-03's variants as YAML 1.2 does: a 5-space job mapping, and `\x61` in a double-quoted `if:`.
- **Committed `node_modules`.** The walk skips every `node_modules` directory. Whether pnpm 10.28.0 with `--frozen-lockfile` treats a committed `node_modules/.modules.yaml` and `.pnpm/lock.yaml` as up to date and keeps the committed package files.
- **Lone surrogates in identities.** In miniflare, `Admin.recordToolCall` stored `a\uD800b@example.com` as bytes that read back as U+FFFD. Unknown in production D1, and whether Access ever issues such a claim.
- **Vendored CycloneDX schema.** The hashes match the README; equality with the upstream 1.6.2 files was not checked (no network).
- **Test range.** The zone postconditions against provider v5 were not run (no binary).
- **Still open from round 9:** whether service-binding RPCs count toward the subrequest limit (now at most 8 tool calls per request), and the IdP behaviour behind R9-04.

## Hardening

- **Broker, same token ID.** After a recheck, `deleteToken` and `markChecked` match on account and token ID only, so a token rolled and stored again under the same ID during the old secret's recheck could be deleted by it. Fails closed (availability). Match on `checked_at` or the ciphertext as well.
- **Identity check.** `isIdentity` and `checkToolCall` accept lone surrogates; refuse strings that are not well formed on both sides.
- **`.npmrc` messages.** The gate prints a refused key when it is shaped like a setting name; a lowercase hex secret written as a key would be printed. Print only keys from the known setting lists.
- **Guide.** The L-2 bullet in "What the build checks cover" should name tsconfig files and the `exports` of `packages/rules/package.json` among what a build can still change.
