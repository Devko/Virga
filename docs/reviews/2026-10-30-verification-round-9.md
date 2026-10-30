# Verification review, round 9

- Date: 2026-10-30
- Scope: (1) are the round 8 findings fixed: R8-01 to R8-03, the source side of the leads R8-04 and R8-05, and the guard hardening of the [round 8 verification](2026-10-30-verification-round-8.md)? (2) review of every round 9 change at commit 7570672: `deploy-3`, `supply-chain-3`, `rules-6`, `web-export`, `vulns-1`, `scanner-io-1`, `terraform-1` (and `docs-4`, docs only)
- Status: round 10 of the [work packages](../team/work-packages.md) fixed R9-01 to R9-06, the leads L-1 and L-2, and the hardening items H-1 to H-4 and those listed below; the [round 10 verification](2026-10-30-verification-round-10.md) confirms them, with H-1 partly fixed (R10-03)

| Finding | Fixed by | Commits | Test |
| --- | --- | --- | --- |
| R9-01 | `supply-chain-4` | d373a5e | `scripts/test/check-release-age.test.ts` (R9-01: `lockfile-dir=other` and 22 more settings refused, the root `.npmrc` read strictly) |
| R9-02 | `supply-chain-4` (gate), `deploy-4` (deploy) | d373a5e; 7144a22 | `check-release-age.test.ts` (R9-02: an app `.npmrc`); `config.test.ts` and `deploy.test.ts` (R9-02: refused before and after the builds) |
| R9-03 | `web-audit-2` | e2b18c1 | `apps/web` (R9-03: 413 and one `refused` row for a body over 64 KiB) |
| R9-04 | `web-audit-2` | 1cc2527 | `apps/web/test/identity.test.ts` (the web and core rules compared on the same cases; 403 for an identity core cannot store) |
| R9-05 | `vulns-2` | 28dbdbf | `packages/vulns` (R9-05: npm names in either case, the review's `JSONStream` case through `rematch`) |
| R9-06 | `scanner-io-2` | efa7449 | `packages/scanner-io/test/memory.test.ts` (R9-06: nine hostile shapes, capped heaps) |
| L-1, H-1, strongest integrity, `pnpm` fields, `.nvmrc` | `supply-chain-4` | 2c46c37, 5aa55a0, 56d6f29, d4390ed, ca67a3d | `check-release-age.test.ts` (L-1, H-1, TM-32, TM-29) |
| L-2, H-2, `main` and `migrations_dir`, redaction, Terraform | `deploy-4` | 6c6c98e, 3724810, 54ac814, cfa1551, 68ae3a0, 0848d6d | `scripts/test/workspace.test.ts`, `config.test.ts`, `deploy.test.ts`, `run.test.ts`, `guide.test.ts`, `test-range.test.ts` |
| H-3, H-4, audit purge | `core-6` | 8691afc, 05c5dba, dfc4453 | `apps/core/test/rules-runtime.test.ts` (H-3, H-4), `audit.test.ts` (audit amplification) |
| Audit rows per request, export escaping, `untruncated_size` | `web-audit-2` | f22a18a, 8400701, a2dcafb | `apps/web` tests named after each item |
| Duplicate keys in `vulns` | `vulns-2` | 3cfea6f | `packages/vulns/test/json.test.ts`, `osv.test.ts`, `kev.test.ts`, `rematch.test.ts` |
| Secret guard, invisible characters | `scanner-io-2` | 89198d9, 440fd16, 017a5a2 | `packages/scanner-io` ("R9 secret guard: …", "R9 invisible characters: …") |

## Summary

Read-only review by two reviewers in disposable worktrees at 7570672: part A verified the fixes and reviewed `deploy-3`, `supply-chain-3` and `rules-6`; part B reviewed `web-export`, `vulns-1`, `scanner-io-1` and `terraform-1`. No tracked file was changed. Checks ran in WSL; scratch tests and probes stayed in the worktrees.

The full `pnpm run ci` passed at 7570672: cf-api 6, graph 103, scanner-io 180, web 109, vulns 381, exposure 194, collectors 278, broker 127, rules 449, core 286 (workerd), scripts 281; 2,394 tests. `rules:check` passed with 11 rules and 71 fixtures.

Every round 8 item in scope is fixed. The new findings are one medium in the release-age gate (`.npmrc` is not read), one low variant of it, two low gaps in the audit trail, one latent contract gap between `scanner-io` and `vulns`, and one low memory bound in `scanner-io`.

Network use: part B fetched the OCSF 1.9.0 schema pages from schema.ocsf.io to check the mapping. Part A ran `pnpm store path` once outside the project, which made corepack 0.36.0 download pnpm 12.16.1 from registry.npmjs.org into the WSL corepack cache; every later check ran in a network namespace with loopback only. No check contacted Cloudflare, GitHub, osv.dev or cisa.gov, and every token or secret was synthetic.

## Verification of round 8

| Item | Status | Evidence |
| --- | --- | --- |
| R8-01 | fixed | `main()` with fixed registry data returned 1, naming the line, for `configDependencies` as a block key, a quoted key, a flow map, a `<<` merge key, and in `package.json` `pnpm.configDependencies`. A value holding NEL (U+0085) returned 1. A BOM with CRLF and a comment line returned 0 |
| R8-02, gate half | fixed | `main()` returned 1 for an app `packageManager`, an app `devEngines.packageManager`, `.corepack.env` at depth, in upper case and with a Kelvin sign (U+212A), a nested `pnpm-workspace.yaml`, and a symbolic link. A `.corepack.env` inside a committed `node_modules` passes, as designed. Lead L-1 below |
| R8-02, build half | fixed | pnpm 10.28.0 with corepack 0.36.0: `pnpm --dir apps/web run build` at the root ran in `apps/web` with pnpm 10.28.0, loaded no `.corepack.env` with `COREPACK_ENV_FILE=0` and the root one without it, and ran 10.28.0 with an app pin of 10.27.0. Run inside `apps/web`, corepack tried to fetch 10.27.0. New variant: R9-02 |
| R8-03 | fixed | With `a@1.0.0 accepts too_young`, the registry entry was excepted. A foreign tarball and a registry tarball without integrity (`not_registry`), sha384 with `version: 1.0.1` (`unverified`), and 1.0.1's sha512 under `a@1.0.0` (`mismatch`) still failed. The old exception format throws `ExceptionError` |
| R8-04, source side | fixed | The guide's example has a `release-age` job that `deploy` needs, and the workstation and update steps run the check first. A scratch workflow with an ungated job failed the guard test, so the guard reads every workflow file. Hardening H-1. The deciding fact (the deploy branch's rules) stays open |
| R8-05, source side | fixed | `checkGenerated` on copies: nothing stale as committed; a tail added by hand to `rules.gen.ts` is stale and the deploy throws `DeployError`; a tail in `rules/CF-001/rule.sql` gives "a rule must contain exactly one statement". `deploy-dry-run` needs `[release-age, check]`. The deciding fact stays open. Lead L-2, hardening H-2 |
| Guard: drop and re-create | fixed | workerd 1.20261012.1: `queryReadOnly` refused `SELECT 1; DROP TABLE exposure; <same CREATE>; SELECT 1` as "text after its first statement". With the tail check bypassed, the guard alone threw "emptied exposure" and kept the row |
| Guard: shadowing view | fixed | The guard alone, given a view `pragma_legacy_alter_table` and `legacy_alter_table`, `defer_foreign_keys` and `case_sensitive_like` set to 1, threw `ReadOnlyError` naming the schema and the settings. Afterwards all three were 0 and `'a' LIKE 'A'` was 1 |
| Guard: `defer_foreign_keys` | fixed | `PRAGMA defer_foreign_keys = 1` through `queryReadOnly` threw "changed the setting defer_foreign_keys"; the value afterwards was 0 |
| Guard: unrewritten placeholders | fixed | The compiler refused `>= @min_conf` in CF-001 ("unsupported placeholder @min_conf"). At run time `$`, `@`, `#` and `:` are refused outside quotes and comments |

Checked without a new finding:

- **The run-time one-statement check.** All 11 committed rules pass it. Fifteen tricky inputs in workerd (`x'''`, `/*/`, `--\r`, `--` with U+2028 or U+0085, `[a'b]`, `"a""` and others): every accepted input ran no tail, and every input whose tail ran was refused. A fuzz of 3,000,000 strings (330,544 accepted strings with a `;`) against `sqlite3_complete` found no differential. `SELECT 1; -- c` and `SELECT 1; /* c */` are accepted and then refused by workerd ("did not contain a statement"), which fails closed (H-4).
- **Pragmas.** Of 27 pragmas probed in workerd, only `foreign_keys`, `optimize` and `data_version` are authorized besides the guard's six; none changed state the guard let pass.
- **OCSF export.** Access is required on every route; viewers, admins and service tokens get the export. A cursor is only a position used inside the Durable Object of the account in the path, after `knownAccount`, so it cannot read another account. The size bound holds; strings from scanned accounts, keys included, stay JSON strings in JSON and NDJSON. The mapping holds against the OCSF 1.9.0 schema (`time`, `status_id`, `activity_id`, `is_alert`, `evidences`, required attributes, `resource_details.role_id`).
- **Audit trail.** The identity comes from the verified JWT; the account ID is checked; core rebuilds and checks every field and the table's CHECK constraints repeat the bounds; failures are logged by error name only; the purge deletes only rows older than 90 days. Gaps: R9-03, R9-04.
- **`vulns`.** Range evaluation follows the OSV pseudocode; SemVer precedence is strict; CVSS 3.0 and 3.1 weights, scope handling and Roundup match the FIRST specification (9.8, 10.0, 7.5, 6.1 tested). An unknown rank is never written as 0; rejected IDs, incomplete feeds or package sets, unparsed packages and undecided matches keep their rows; ignored rows stay ignored; `first_seen` is kept; a KEV catalog whose `count` does not match is rejected. Contract gap: R9-05.
- **`scanner-io`.** The result is built only after the last check; errors carry JSON pointers or offsets only; `Match`, `Line` and `Code` are never read; the fuzz passed with seed 9 at 3,000 iterations per reader; 15 MiB of escaped strings parsed in 304 ms. SBOM values enter only through `JSON.stringify`. Memory: R9-06.
- **Test range.** No real ID or token in a committed file; the CF-003 tokens accept only unrouted addresses; every Worker runs `dummy.mjs`; stores are empty; tunnel origins are `.invalid`; Access apps come first. The fix templates weaken no control.
- **TM-04 confirmed.** `TokenIntake.recheck` has no caller outside tests: the web Worker's `TokenIntakeRpc` declares only `store` and `remove`, core binds only `ApiCaller`, and the broker has no scheduled handler.

## New findings

### R9-01 [medium] The release-age gate never reads `.npmrc`, where `lockfile-dir` makes pnpm install from a lockfile the gate never dated

Area: supply chain. Location: `scripts/check-release-age.ts:1253` (`main` reads `pnpm-lock.yaml`, `package.json` and `pnpm-workspace.yaml`), `:796` (`checkCheckout` never looks at `.npmrc`)

**Scenario**

A commit adds `lockfile-dir=other` to the root `.npmrc` and an `other/pnpm-lock.yaml` with young versions. The gate dates the untouched `pnpm-lock.yaml` and passes. CI's `check` and `deploy-dry-run`, the guide's deploy job and the workstation steps then run `pnpm install --frozen-lockfile`, which installs from `other/pnpm-lock.yaml`. Since round 9 the deploy also loads `yaml` into the process that holds the token (H-2), so a young `yaml` installed this way runs there. `git-branch-lockfile` and `shared-workspace-lockfile=false` are the same class (not tested). This is the round 8 "gate inputs" hardening item, which round 9 closed only for `pnpm-workspace.yaml`.

**Fix**

Read the root `.npmrc` strictly with an allowlist of the keys the project uses (today `save-exact` and `engine-strict`), and refuse `.npmrc` anywhere else in the checkout walk. Update CONTRIBUTING.md, the CI comment and the operator guide.

**How it was verified**

`package.json` pins `yaml` 2.9.1, the root lockfile locks 2.8.0, and fixed registry data dates 2.8.0 at 400 days and 2.9.1 at 1 day. With `.npmrc` `lockfile-dir=other`, `main()` returned 0, and `pnpm install --frozen-lockfile --offline` exited 0 and installed `yaml` 2.9.1. Without the `.npmrc`, pnpm refused ("lockfile: 2.8.0, manifest: 2.9.1"). Control: with 2.9.1 in the root lockfile, the gate printed "too young: yaml@2.9.1" and returned 1.

### R9-02 [low] An app's `.npmrc` makes the deploy's build download and run a Node runtime from any mirror (R8-02 variant)

Area: supply chain, deploy. Location: `scripts/lib/config.ts:172` (`corepackProblems`), `scripts/check-release-age.ts:796` (`checkCheckout`), `scripts/lib/steps.ts` (`build`)

**Scenario**

`pnpm --dir apps/web run build` also reads `apps/web/.npmrc`. With `use-node-version=23.0.0` and `node-mirror:release=<url>`, pnpm fetches `SHASUMS256.txt` and the tarball from that mirror and runs the build with that binary, as a child of the deploy. Neither the gate nor `checkAppDir` reads the file. (`pnpm.executionEnv.nodeVersion` in an app's `package.json` did not trigger a download for `run build`.)

**Fix**

The gate's walk refuses `.npmrc` below the root (with R9-01). `checkAppDir` refuses `apps/<app>/.npmrc` before and after the builds. Add a row to the guide's troubleshooting table.

**How it was verified**

In a network namespace with loopback only, a local server served a stand-in Node tarball. The deploy's own `build()` through `processRunner` printed "Fetching Node.js 23.0.0", then the stand-in's marker line; the server logged both requests. `checkAppDir` returned the config path with `apps/web/.npmrc` present; the `.corepack.env` control was refused.

### R9-03 [low] A refused MCP `tools/call` whose body is over 64 KiB leaves no audit row

Area: audit trail. Location: `apps/web/src/mcp.ts` (`MAX_CALL_BODY`, `toolCallIn`, `handleMcp`)

**Scenario**

`toolCallIn` reads at most 65,536 bytes of a clone of the body and returns null above that, so `handleMcp` writes no `refused` row. The MCP SDK accepts bodies up to 4 MB. A client can pad a call to an unknown tool, or with invalid input, and the refused attempt leaves no trace. The docs (`apps/web/README.md`, the `outcome` row in `docs/architecture/data-model.md`) say every `tools/call` that runs no tool is recorded as `refused`. Tools that run are still recorded.

**Fix**

When the body cannot be inspected and no tool ran, record one `refused` row with action `unknown_tool` and account `null`, or read up to the SDK's limit. Add a test with a padded body.

**How it was verified**

Scratch test in workerd: the unpadded call to an unknown tool gave 200 and the row `["unknown_tool", <account>, "refused"]`; the same call followed by 70,000 spaces gave 200 and no row.

### R9-04 [low] An Access email that core cannot store is served, and none of its calls is recorded

Area: audit trail. Location: `apps/web/src/auth.ts` (any `email` claim of 1 to 320 characters), `apps/web/src/audit.ts` (`actorOf`), `apps/core/src/audit.ts` (`checkToolCall`)

**Scenario**

The web Worker accepts any `email` claim up to 320 characters. Core refuses identities with spaces, C0 or C1 controls, U+00A0, U+200B to U+200F, U+2028 to U+202E, U+2066 to U+2069 or U+FEFF. For such an identity `Admin.recordToolCall` throws, the web Worker logs `audit: record failed TypeError`, and the request is answered normally. Every API request and MCP tool call of that identity is served without an audit row, although the docs say every call of an identity that passed Access is recorded. Whether an IdP behind Access issues such a claim is a lead; generic OIDC and SAML IdPs pass the attribute through.

**Fix**

Use one identity check on both sides: refuse such identities in `authenticate` (403, as for requests Access refused), or escape the characters before recording so that the row always fits. Add a test across web and core.

**How it was verified**

In workerd, a JWT with `email` `a​b@example.com` got 200 on `/api/accounts`, and the audit entry it sent carried the identity unchanged. Core's `checkToolCall` threw `TypeError: invalid identity` for `a​b@example.com`, `a b@example.com` and `x y@example.com`.

### R9-05 [low, latent] `scanner-io` writes npm purls in lower case and `vulns` matches names exactly, so a vulnerable package with capitals reads as not affected in a complete result

Area: `vulns` and `scanner-io` contract. Location: `packages/scanner-io/src/text.ts` (`npmPurl` lowercases the name), `packages/vulns/src/purl.ts` and `src/match.ts` (names compared exactly)

**Scenario**

`docs/architecture/scanner-io.md` lowercases npm names ("the purl rule for npm"); `docs/architecture/vulns.md` says the collector must keep npm's spelling; the data model says nothing about case. Once `scanner-io` output, or any collector that follows the purl spec, feeds `package` nodes, a legacy package such as `JSONStream` becomes `package:pkg:npm/jsonstream@1.3.1`. OSV names it `JSONStream`, so the match is `not_affected`, `rematch` reports `complete: true`, and an existing open row becomes `fixed`. CF-001 then runs with `vulns` complete and misses the package: a confident false negative. Nothing writes package nodes yet, so this is latent.

**Fix**

Fix the purl spelling in the data model before a package writer lands, and compare npm names case-insensitively in `vulns` (extra matches are the safe direction). Add a test that sends `scanner-io` purls through `rematch`.

**How it was verified**

`npmPurl("JSONStream","1.3.1")` gave `pkg:npm/jsonstream@1.3.1`, and `parseNpmPurl` read the name `jsonstream`. Against an advisory for `JSONStream` fixed in 1.3.6 the match was `not_affected`; the purl that keeps the case gave `affected`. `rematch` with complete packages, feed and KEV returned `complete: true` and set the old row `package:pkg:npm/JSONStream@1.3.1` to `fixed`. `readOsvScanner` gives the same lowercased purl.

### R9-06 [low] `scanner-io` memory is driven by the value count, not the byte limit: a 1.4 MB report keeps about 94 MB of parsed tree

Area: `scanner-io` resource bound. Location: `packages/scanner-io/src/limits.ts` (`maxValues` 500,000), `src/json.ts` (every object becomes a `Map`)

**Scenario**

Each reader parses the whole document before it checks the shape. Five arrays of 99,998 `{}` (499,996 values, 1.4 MB) stay within every default limit, and each `{}` becomes a `Map`. With whitespace up to 16 MiB of input and the decoded string on top, a Worker may pass 128 MB and fail with an out-of-memory error instead of `ScannerOutputRejected`. `docs/architecture/scanner-io.md` says 16 MiB of text plus the tree fits a Worker. workerd compresses pointers and Node 22 does not, so the tree there is likely about half the size; not measured in workerd.

**Fix**

Bound containers separately (for example at most 100,000 objects and arrays) or lower `maxValues`, measure the worst case in workerd, and correct the doc.

**How it was verified**

`node --expose-gc`: the parse was accepted in 101 ms and the heap kept 93.7 MB after collection. For comparison, an osv-scanner report with 50,000 packages (3.3 MB) kept 12.1 MB.

## Leads

- **L-1 (case-insensitive file systems).** The gate compares file names with `toLowerCase()`, which does not fold U+017F (long s): `apps/web/pnpm-workſpace.yaml` with `configDependencies` passes `main()`. NTFS on the review machine does not open it as `pnpm-workspace.yaml`. Deciding fact: whether APFS folds it for pnpm's lookup. Cheap fix: compare `toUpperCase().toLowerCase()`, or refuse non-ASCII names for the files the gate looks for.
- **L-2 (workspace links).** The R8-05 digest binds `packages/rules/src/*.gen.ts`, but core imports `@virga/rules` through `apps/core/node_modules/@virga/rules`, which neither `checkAppDir` nor the Wrangler record covers. A build that retargets that link would make Wrangler bundle another `rules.gen.ts`. Not run through Wrangler. The guide's sentence that Wrangler never bundles generated rules the script has not checked is stronger than the code.
- **R9-04, IdP behaviour.** Whether an IdP behind Access (generic OIDC or SAML, one-time PIN) issues `email` claims with spaces or invisible characters.
- **MCP batches.** A JSON-RPC batch of 100 `tools/call` makes 100 GraphReader and 100 `recordToolCall` RPCs in one request. Whether service-binding RPCs count against the plan's subrequest limit, so that audit writes after a tool ran could fail.
- **The CF-003 fallback range.** The test range README offers `fc00::/7` as a fallback IP condition. Whether requests from such a source can reach the Cloudflare API, for example from inside Cloudflare. Low impact: the token value lives only in the Terraform state.

## Hardening

- **H-1 (workflow guard).** The R8-04 guard passes a workflow whose check step has `continue-on-error: true` and whose installing job has `if: always()`; GitHub runs that job when the check fails. Verified with a scratch workflow.
- **H-2 (third-party code in the token process).** `loadRuleCompiler()` loads `yaml` 2.9.1 into the deploy process, which holds the token. Before round 9 that process loaded only Node built-ins and repository code. It is within the documented residual (build code can read the deploy's environment), but the guide should name the dependency. R9-01 made it reachable with a young `yaml`.
- **H-3 (guard baseline).** The guard takes the settings before each run as its baseline, so a setting stuck on the connection becomes the baseline of later runs. Not reachable with one statement; comparing with fixed defaults would fail closed.
- **H-4 (decision 0006 wording).** Decision 0006 says comments after the `;` are allowed; workerd refuses such a query. Fails closed; no committed rule does it.
- **Audit amplification.** One MCP request can write 100 rows, and the purge removes at most 100,000 rows per hour, so an identity writing faster keeps rows past 90 days.
- **Export escaping.** Tag characters U+E0000 to U+E007F, U+3164 and U+034F stay raw; the doc's "nothing that hides text" overclaims. OCSF `untruncated_size` is defined as the size of the whole event in kilobytes; the export writes the evidence size.
- **Duplicate keys in `vulns`.** The readers use `JSON.parse`, so a duplicate key keeps its last value; an OSV record with a second, empty `affected` read as skipped, which counts as read, so its rows would become `fixed` in a complete result. Reject duplicate keys, for example with `scanner-io`'s parser.
- **Secret guard in gitleaks reports.** A file name is rejected only when it holds the whole secret body of 8 characters or more; 23 of 24 characters passed, and a 7-character secret is not searched.
- **Invisible characters.** `scanner-io` and SBOM clean text allow zero-width and other invisible characters (U+200B to U+200D, U+2060, U+FEFF, tags) in names and paths.
- **Terraform.** `.gitignore` does not cover saved plans (`tfplan`, `*.tfplan`) or `*.tfvars.json`; a saved plan holds the prior state with the CF-003 token values. `account_id` and `zone_id` are checked only for shape and nothing ties the zone to the account; `CLOUDFLARE_API_TOKEN` is also the deploy's variable. Add a zone data source with preconditions. Whoever can fetch the tunnel token can run a connector and serve content on the seeded hostname; one line in the README's safety table.
- **Still open from round 8:** a sha1 integrity equal to `dist.shasum` is accepted; `.nvmrc` floats; a build can still change `packages/*/src` after the rules check (listed as not covered in the guide).
