# Verification review, round 12

- Date: 2026-11-20
- Scope: are the round 11 findings and hardening items fixed: R11-01, R11-02, the hardening items "Broker: a pass after the token was removed", "Guard: require `--fresh-checkout`", "Updates flow" and "Guard: characters", and the lead "Non-ASCII status functions" of the [round 11 verification](2026-10-30-verification-round-11.md); and the TM-16 lockfile update. Review of the round 12 commits 60fd2cc, b99324b, 6663a1f, 1c94c52 and edacd84 at edacd84, diffed against 70b1d1a
- Status: from this round on, only high or critical findings block. R12-01 (low) was fixed in the round 12 pull request, since the guard's comment, CONTRIBUTING.md and TM-31 already claimed it; R12-02 (low) is [issue #3](https://github.com/Devko/Virga/issues/3); the leads and hardening items are [issue #4](https://github.com/Devko/Virga/issues/4)

| Finding | Fixed by | Test |
| --- | --- | --- |
| R12-01 | `supply-chain-6`, after this review | `scripts/test/check-release-age.test.ts` ("R12-01: refuses non-ASCII letters written as YAML escapes in keys and values"): every parsed key and string value must be printable ASCII too |

## Summary

Read-only review by one reviewer (Opus) in a disposable worktree at edacd84 and in copies of it. No tracked file was changed. Nothing contacted Cloudflare, and every token was synthetic. The registry (registry.npmjs.org) was reached for the release-age check, the integrity of the two updated packages and `pnpm audit`; osv.dev and GitHub's advisory API were not reachable.

The full `pnpm run ci` passed: cf-api 6, graph 103, scanner-io 261, web 121, vulns 424, exposure 194, collectors 278, broker 161 (workerd), rules 449, core 314 (workerd), scripts 365; 2,676 tests. `rules:check` passed with 11 rules and 71 fixtures, and offline deploy dry runs passed on copies of the tree.

Both round 11 findings are fixed for the review's own inputs and for every bypass tried; the broker hardening, the `--fresh-checkout` requirement, the Updates flow and the TM-16 update are fixed. Two new lows: the workflow guard checks characters in the raw text only, so a double-quoted escape such as `"ſlways()"` still puts a non-ASCII letter into a parsed `if:`, contrary to the guard's comment, CONTRIBUTING.md and TM-31 (R12-01); and `pnpm audit` lists 18 further advisories, in zod (a direct dependency of `apps/web`), hono and `@hono/node-server` (in `apps/web` through the MCP SDK) and in test-only packages, whose patched versions all pass the age gate (R12-02).

## Verification of round 11

| Item | Status | Evidence |
| --- | --- | --- |
| R11-01 | fixed | On `ci.yml`, `timeout-minutes: 10 # limit<X>    continue-on-error: true` in `release-age` with X = lone CR, NEL, LS, PS, VT, FF, TAB, NUL, BOM and DEL: `gateProblems` returned exactly one problem each, "line 41: …" (a CR not followed by LF, or the character's code point). CR CR LF is refused as a lone CR; the whole file in CRLF passes, as intended. A lone surrogate and an astral character are each reported once. `characterProblems` runs before the parser in `readWorkflow`, so `gateProblems` and `nodeProblems` both see it; the guide's example is checked by `guide.test.ts` with the same four breaks |
| R11-02 | fixed | Offline `node scripts/deploy.ts --dry-run` on a copy of the tree, the web build set to run a script after `vite build`: a `.pnp.data.json` written at the repository root, `.PNP.CJS` in the directory above the root, a symlink `.pnp.cjs` at the root, `packages/rules/.Pnp.Js`, `apps/core/.pnp.js`, and a detached process that writes `.pnp.cjs` at the root 1.5 s after the build ended each exit 1 with the Yarn PnP refusal (the last one before a later Wrangler call); a `.pnp.data.json` above the root before the deploy stops it at the record; a symlink `apps/core/.pnp.cjs` (to a file or dangling) is refused as a symlink in the app; `apps/core/src/x/.pnp.data.json` is refused. The control exits 0, "Dry run complete." With esbuild 0.28.2 directly, a manifest that maps `foo` to another directory is used when it stands in an ancestor of `absWorkingDir` and ignored when it stands only above the importing file, so the app directory and the directories above it are the places that matter; Wrangler 4.151.0 sets `absWorkingDir` to the config's directory, `apps/<app>`. esbuild's directory lookup is case-insensitive even on Linux, which the any-case refusal matches; no non-ASCII character lowercases to a letter of these names in Go or JavaScript |
| Broker: a pass after the token was removed | fixed | `recheckToken` acts on the results of `markChecked` and `deleteToken`; when either is false it returns `changedDuring`: `ok: false`, `retryable: true`, `changed: true`, `removed: false`, reason `token_changed`, `stored` from `hasToken`. `outcomeOf` maps `changed` to 503/99006 before the retryable branch, so neither a 401 "was deleted" nor a 429 can come out of it, and `usableToken` returns that outcome once; it does not loop. The caller's retries are core's bounded Workflow retries. A store or removal after `markChecked` returned true is a new row with its own check, or no row; a store before it makes `markChecked` false. If `hasToken` throws, `ApiCaller` answers 500 (`BROKER_ERROR_CODE`) and `TokenIntake.recheck` answers `broker_error`, retryable; nothing is sent in either case. The tests "Round 11 hardening: a token removed during its recheck" (pass, failure, `TokenIntake.recheck` after removal and replacement) and "R10 hardening: broker same token ID" pass |
| Guard: require `--fresh-checkout` | fixed | `CHECK_RUNS` holds only the command with the flag. On `ci.yml` without the flag: "no release-age job that runs the check before anything else" and "release-age runs the check without --fresh-checkout …"; the flag twice, or the command as a block scalar with a trailing newline, is refused as another command; the quoted form `"node scripts/check-release-age.ts --fresh-checkout"` is the same parsed string and passes. The guide's example without the flag is refused (`guide.test.ts`) |
| Updates flow | fixed | The guide's Updates section deploys from a fresh clone with `node scripts/check-release-age.ts --fresh-checkout` and says why a pull into an installed checkout is unsafe; the first-deploy paragraph says to leave the flag out only in a checkout one develops in. In a fresh clone of edacd84 the check with the flag passed ("all 333 locked package versions …"); in the installed worktree it refused `apps/broker/node_modules` |
| Guard: characters | fixed (raw text) | Every character outside printable ASCII, LF and CRLF in the file is refused, including in keys and in `if:` values. A non-ASCII letter written as a double-quoted escape is not: R12-01 |
| Non-ASCII status functions (lead) | partly fixed | `if: alwayſ()` and `if: faılure()` written literally are refused ("the character U+017F", "U+0131"). `if: "ſlways()"`, `if: "faılure()"` and `if: "fa\N\Lılure()"` on `check` pass `gateProblems` with `[]`: R12-01. Whether GitHub's expression lexer accepts a non-ASCII letter in a function name is still not known |
| TM-16 | fixed | The lockfile entries' integrity equals the registry's: body-parser 2.4.0 `sha512-Ifk1KcLr…`, fast-uri 3.1.9 `sha512-hS/0Wt3Y…`. body-parser 2.4.0 declares `qs ^6.16.1`, `on-finished ^2.4.1`, `content-type ^2.1.0`, `iconv-lite ^0.7.3` and five more, all satisfied by the locked versions; its engines field (`node >=18`) matches the lockfile. Only the two versions and their references changed. Published 2026-10-22 and 2026-10-19; `node scripts/check-release-age.ts` passes (333 versions). `pnpm install --frozen-lockfile` passed in the worktree (offline) and in a fresh clone, and `pnpm install --lockfile-only --offline` left the lockfile byte for byte unchanged. `pnpm audit` lists no advisory for body-parser or fast-uri any more; it lists others: R12-02 |

## New findings

### R12-01 [low] A double-quoted escape puts a non-ASCII letter into a parsed `if:` past the workflow guard's character check

Area: supply chain, CI. Location: `scripts/test/workflow-guard.ts:87` (`characterProblems` checks the raw text), `:319` (`STATUS_FUNCTION`, `/i` without `u`); the claims in the comment at `:78`, CONTRIBUTING.md line 40 and TM-31

**Scenario**

`ci.yml` gets `if: "ſlways()"` on the `check` job (or `"faılure()"` on any job that installs or deploys). The raw text is printable ASCII, so `characterProblems` passes it; `yaml` decodes the escape to `ſlways()`, and `STATUS_FUNCTION` does not match U+017F, so `runsAfterFailure` returns false and the guard reports nothing. If GitHub's expression lexer accepts the letter and compares function names with .NET's `OrdinalIgnoreCase`, which folds U+017F to `S` and U+0131 to `I`, the job runs after a failed `release-age` (H-1). The guard's comment, CONTRIBUTING.md and TM-31 ("no non-ASCII letter reaches a key or an `if:`") claim this case is closed. In the `release-age` job an escaped non-ASCII key is refused as a key the guard does not know, and an escaped ASCII key is matched by its parsed spelling, so keys are not affected.

The rating is low, not higher: a reviewer sees an escape in an `if:` of a reviewed workflow, and the attack works only if GitHub accepts a non-ASCII letter in a function name, which is not known (if GitHub's lexer allows only ASCII letters in identifiers, the workflow fails to load instead, which is harmless).

**Fix**

After parsing, refuse any non-ASCII character in the parsed keys and string values of every workflow, or at least in `if:` values; or refuse escape sequences in double-quoted scalars. Add the escaped forms to the "R11-01 lead" test and correct the three claims.

**How it was verified**

`gateProblems` on `ci.yml` with `    if: "ſlways()"`, `    if: "faılure()"` and `    if: "fa\N\Lılure()"` added to `check` returned `[]`; the same with `\x61lways()`, `always()` and `\U00000061lways()` returned "job check has an if: that runs it when release-age failed", and the literal U+017F and U+0131 are refused by `characterProblems`. GitHub itself was not observed.

### R12-02 [low] `pnpm audit` lists 18 further advisories whose patched versions pass the age gate, one in a direct dependency of `apps/web`

Area: dependencies. Location: `pnpm-lock.yaml` (zod 4.6.5, hono 4.13.13, `@hono/node-server` 2.1.5, undici 7.29.1, `@vitest/mocker` 4.1.11), `apps/web/package.json` (`zod`), TM-16

**Scenario**

TM-16 now says "Left: none" for body-parser and fast-uri, and nothing tracks other advisories. `pnpm audit` on edacd84 lists 18 advisories, none for the two updated packages:

- zod < 4.6.6, high, GHSA-mrhx-c7xc-m3w5 (published 2026-10-01): memory exhaustion while validating oversized constrained collections. zod is a direct dependency of `apps/web`, whose MCP tools validate input with `z.array(...).max(n)`. The MCP body is capped at 64 KiB (`MAX_MCP_BODY`) and the caller is behind Access, which bounds the effect to one request. zod 4.6.6 was published 2026-10-11.
- hono < 4.13.16 (5 advisories, moderate and low, 2026-11-12) and `@hono/node-server` < 2.1.6 (2, moderate), in `apps/web` through `agents` > `@modelcontextprotocol/sdk`. Whether the Worker reaches hono's router, `csrf()`, `validator('form')` or the Node server was not assessed. hono 4.13.16 was published 2026-11-01, `@hono/node-server` 2.1.6 on 2026-11-02.
- undici < 7.30.1 (8 advisories, 4 high) through `@cloudflare/vitest-plugin` > miniflare, and `@vitest/mocker` < 4.1.12 (2, moderate): test tooling only, not deployed. Patched versions published 2026-10-15.

All patched versions are older than 14 days today. Low: the deployed reach is bounded (zod) or unassessed but behind Access (hono), and the rest runs only in tests.

**Fix**

A `deps-2` package: update zod to 4.6.6 in `apps/web`, and hono, `@hono/node-server`, undici and `@vitest/mocker` to their patched versions where the parents' ranges allow it (or through `overrides`, which the gate's `pnpm` field allowlist would have to permit); extend TM-16 to them, and run `pnpm audit` on a schedule or in the release checklist so that advisories are tracked, not found by a review.

**How it was verified**

`pnpm audit --json` in a fresh clone of edacd84 (the registry's audit endpoint; it sends the locked package names and versions only). Publication dates from the registry's metadata. The advisories themselves were not reproduced.

## Leads

- **Non-ASCII function names on GitHub.** Whether GitHub's expression lexer accepts `ſlways()` or `faılure()` (R12-01) and whether it folds them to ASCII.
- **R11-01 on GitHub.** Whether GitHub's workflow parser ends a comment at a lone CR, NEL, LS or PS; the guard now refuses them, so this only decides whether R11-01 was exploitable.
- **Still open from round 10:** equality of the vendored CycloneDX schema with upstream, the test range against provider v5, the subrequest limit, and the IdP behaviour behind R9-04.

## Hardening

- **Broker: `stored` after a failure.** `TokenIntake.recheck` answers `stored: true` from its `catch` (for example when `hasToken` throws) and from the no-answer path, without reading the vault; after a removal during the check both are wrong. Nothing calls `recheck` yet. Read `hasToken` there too, or leave `stored` out when it is not known. Under a D1 failure in `hasToken`, `ApiCaller` answers 500 (`BROKER_ERROR_CODE`), not the 503/99006 the README describes for a changed token; nothing is sent either way.
- **PnP test above the root.** The workspace test skips the directory above the temporary checkout ("may not be writable"), so no unit test covers a manifest above the repository root; the dry runs in this review did (refused before and after the builds). A test could create the checkout one level deeper inside its own temporary directory.
- **Race before each Wrangler call.** The checks before each Wrangler call cannot see a manifest, or any other file, that a process left running by a build writes after the check and before Wrangler's esbuild reads it (about a second). This adds nothing to TM-27's residual risk, since a build can already change the workspace packages' sources, which are not checked; it is noted so that the guide's "caught before the next Wrangler call" is not read as "before this one".
