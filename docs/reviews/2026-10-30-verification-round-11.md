# Verification review, round 11

- Date: 2026-10-30
- Scope: (1) are the round 10 findings fixed: R10-01 to R10-04, the hardening items "Broker, same token ID", "Identity check", ".npmrc messages" and "Guide", and the lead "Committed node_modules" of the [round 10 verification](2026-10-30-verification-round-10.md)? (2) review of the round 11 merges at commit ff05f56: `hardening-11` (cb7d409), `deploy-5` (aa5f71c) and `supply-chain-5` (8eb7462), each diffed against 953b930, and the integrator's doc commits
- Status: not yet fixed; R11-01 and R11-02 are open

## Summary

Read-only review by one reviewer (Opus) in a disposable worktree at ff05f56. No tracked file was changed. Every check ran in WSL in a network namespace with loopback only; nothing contacted Cloudflare, the npm registry, GitHub, osv.dev or cisa.gov, and every token was synthetic.

The full `pnpm run ci` passed: cf-api 6, graph 103, scanner-io 261, web 121, vulns 424, exposure 194, collectors 278, broker 158 (workerd), rules 449, core 314 (workerd), scripts 355; 2,663 tests. `rules:check` passed with 11 rules and 71 fixtures, and offline deploy dry runs passed on copies of the tree.

All four round 10 findings are fixed for the review's own inputs, the hardening items are fixed, and the committed-`node_modules` lead is partly fixed. Two new lows: the parsed-YAML guard reads a comment through a lone CR, NEL, LS or PS (R11-01), and a Yarn PnP manifest written by a build retargets `@virga/rules` past the R10-04 record (R11-02). The broker's ciphertext match held through store, rotate and remove; the identity rule and the gate's new refusals showed no defect.

## Verification of round 10

| Item | Status | Evidence |
| --- | --- | --- |
| R10-01 | fixed | The review's checkout (root lockfile with `yaml` 2.8.0, `other/pnpm-lock.yaml` with 2.9.1, `.pnpmfile.cjs` with the `updateConfig` hook): `main()` returned 1 ("pnpm loads .pnpmfile.cjs on every command and runs its hooks"); without the pnpmfile, 0. `.pnp.data.json`, `.pnp.loader.mjs`, `apps/core/.pnp.js` and `packages/rules/.Pnpmfile.cjs` return 1 too |
| R10-02 | fixed | `apps/x/package.yaml` with `pnpm.executionEnv.nodeVersion: 23.0.0` and `apps/x/Package.Json5`: `main()` returned 1 |
| R10-03 | fixed (the review's inputs) | On `ci.yml`: the 5-space `release-age` job with `continue-on-error` and `if: "\x61lways()"` are both reported, like the plain `always()` control. Line breaks inside plain scalars fail closed. A lone CR, NEL, LS or PS inside a comment still hides a line: R11-01 |
| R10-04 | fixed (tsconfig, `package.json`) | Offline dry runs on copies: committed `paths`/`baseUrl` in `apps/core/tsconfig.json`, a build that writes that mapping, a build that adds `apps/core/src/tsconfig.json`, and a build that adds a second `compilerOptions` to `tsconfig.base.json` each exit 1 with no Wrangler call; the control exits 0 with 3 calls. esbuild 0.28.2 ignores `Paths`, `BaseUrl` and `CompilerOptions` in other cases, so the exact-case check is right. A PnP manifest is not recorded: R11-02 |
| Broker, same token ID | fixed | The tests for a store during a failing and a passing recheck, and for a master key rotation, pass. Each store seals with a fresh data key and IV, so a store in between never matches; a rotation keeps the match. A removal in between: hardening below |
| Identity check | fixed | Web and core on every surrogate code unit at the start, middle and end (6,144 strings): all refused, as `isWellFormed()` would; surrogate pairs accepted by both; the round 10 input refused by both |
| `.npmrc` messages | fixed | A 40-character hex key gives "an unknown setting, whose key the check does not print"; scoped registries and mirror channels print only the setting name; no message held the hex |
| Guide | fixed | "What the build checks cover" names the tsconfig and jsconfig files, the `extends` chain and the `package.json` fields esbuild reads. Its claim that core bundles the checked `rules.gen.ts` fails with a PnP manifest (R11-02) |
| Committed `node_modules` (lead) | partly fixed | With `--fresh-checkout`, a committed `node_modules/.modules.yaml` makes `main()` return 1, and CI and the guide's deploy example use the flag. The guide's Updates steps do not: in a scratch repo, a pull that force-added a changed file under `node_modules/.pnpm/…/yaml` overwrote the installed file; the check without the flag passed, `pnpm install --frozen-lockfile --offline` kept the changed file, and importing `yaml` ran it |

## New findings

### R11-01 [low] The workflow guard reads a comment through a lone CR, NEL, LS or PS, where YAML 1.1 parsers (and, for CR, the YAML 1.2 spec) start a new line

Area: supply chain, CI. Location: `scripts/test/workflow-guard.ts:80` (`readWorkflow` parses with `yaml` 2.9.1 and refuses no line-break character)

**Scenario**

In `ci.yml`, `release-age`'s `timeout-minutes: 10` becomes `timeout-minutes: 10 # limit<CR>    continue-on-error: true`, or the same with U+0085, U+2028 or U+2029. `yaml` 2.9.1 reads the rest of the line as a comment and the guard reports nothing; libyaml (YAML 1.1) ends the comment at the break and reads `continue-on-error: true` as a job key. YAML 1.2's `b-break` also counts a lone CR as a line break, which `yaml` 2.9.1 does not (`a: 1\rb: 2` gave one key `1\rb`). The same works for `if: always()` on `check`, and in the guide's example. If GitHub reads such a break, H-1 is back, and a reviewer sees only a comment.

**Fix**

Before parsing, refuse any CR not followed by LF, and U+0085, U+2028 and U+2029; or allow only printable ASCII, LF and CRLF in workflows and in the guide's example. Add tests with these inputs.

**How it was verified**

`gateProblems` returned `[]` for nine variants (LS, PS and NEL after a trailing comment, inside a comment line, and before an `if:`), for the lone-CR variant, and for the guide's example with LS. PyYAML 6.0.1 with both SafeLoader and CSafeLoader (libyaml) read the same files with `continue-on-error=True` in `release-age`, or `if='always()'` on `check`. `parseDocument("a: 1 # c\rb: 2\n")` gave `{"a":1}`. GitHub itself was not observed (lead).

### R11-02 [low] A Yarn PnP manifest written by a build makes Wrangler's esbuild bundle another module as `@virga/rules`, past the R10-04 record and the generated-rules check

Area: deploy. Location: `scripts/lib/workspace.ts:44` (`RESOLUTION_FILES` holds `package.json`, `tsconfig.json` and `jsconfig.json` only), `recordResolution`, `checkAppDir`

**Scenario**

esbuild 0.28.2 reads `.pnp.data.json`, `.pnp.cjs` or `.pnp.js` from its working directory and every directory above it, and resolves bare imports through the manifest before `node_modules`. Wrangler 4.151.0 sets that working directory to the config's directory. A build writes `.pnp.data.json` at the repository root that maps `@virga/rules`, imported from `apps/core`, to another directory, and maps the other `@virga` imports to `packages/`. Every deploy check passes: the link still leads to `packages/rules`, `rules.gen.ts` is unchanged, and the resolution record is unchanged. Wrangler bundles virga-core with the other module. The gate refuses `.pnp.*`, but it runs before the install, not after the builds. The guide's "Before every Wrangler call" paragraph and TM-27 claim this case is covered.

**Fix**

Record and refuse `.pnp.data.json`, `.pnp.cjs` and `.pnp.js`, in any case, in the app directory, in each package tree and in every directory above them, before and after the builds and before each Wrangler call. Name them in the guide and in TM-27.

**How it was verified**

`node scripts/deploy.ts --dry-run` on a copy of the tree, with the web build set to also write the manifest: exit 0, "Dry run complete." The repository's Wrangler with the same config and `--outdir` bundled the planted marker once with the manifest and zero times without it; esbuild's verbose log printed `Resolved "@virga/rules" via Yarn PnP`. In a scratch app with a `node_modules/@virga/rules` link, each of `.pnp.cjs`, `.pnp.js` and `.pnp.data.json` in the working directory's parent made esbuild bundle the other module; with the working directory elsewhere, esbuild ignored it.

## Leads

- **R11-01 on GitHub.** Whether GitHub's workflow parser ends a comment at a lone CR, NEL, LS or PS.
- **Non-ASCII status functions.** The guard's status-function pattern uses `/i` without `u`, so `if: alwayſ()` (U+017F) and `if: faılure()` (U+0131) pass it; .NET's case-insensitive comparison folds both to ASCII. Whether GitHub's expression lexer accepts non-ASCII letters is not known.
- **Still open from round 10:** equality of the vendored CycloneDX schema with upstream, the test range against provider v5, the subrequest limit, and the IdP behaviour behind R9-04.

## Hardening

- **Broker: a pass after the token was removed.** `recheckToken` ignores the result of `markChecked`. In a scratch workerd test, removing the row during a passing recheck still answered 200 and sent the call with the removed token; in a failing recheck in the same race the answer said "was deleted" although nothing was deleted; and `TokenIntake.recheck` returned `stored: true` for a secret replaced meanwhile. Fail closed (503, retry) when `markChecked` returns false, and report the removal that actually happened.
- **Guard: require `--fresh-checkout`.** The guard also accepts the check without the flag, and only `ci.yml` is pinned to it by a test; the guide's example with the flag removed raised no problem.
- **Updates flow.** The guide's Updates steps run the gate without `--fresh-checkout` in an installed checkout (the lead row above). Advise updating in a fresh clone, as the guide already does for deploys, or have the gate refuse `node_modules` paths that git tracks.
- **Guard: characters.** With R11-01, refuse non-ASCII in keys and in the `if:` of gated jobs, or use `/iu` and also refuse U+0131.
