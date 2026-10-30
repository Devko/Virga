# Contributing

Virga is in phase 1 (see the [implementation plan](docs/implementation-plan.md)). Reviews of the documents in [`docs/`](docs/) are welcome, with issues for errors, gaps or platform facts that have changed.

## Developer Certificate of Origin

Every commit must be signed off under the [Developer Certificate of Origin 1.1](https://developercertificate.org/). The sign-off certifies that you wrote the change or have the right to submit it under the project's license:

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds the line automatically. Commits without a sign-off cannot be merged.

## Checks

Run `pnpm run ci` before every push: lint, `rules:check`, typecheck, the package tests and the script tests. pnpm's own `pnpm ci` command is not implemented, so call the script with `run`.

## Dependencies

Pin dependencies to exact versions released at least 14 days ago. `minimumReleaseAge` in `pnpm-workspace.yaml` makes pnpm resolve only such versions, but an install from the lockfile, as in CI, takes whatever the lockfile holds, and pnpm itself is the version `packageManager` in `package.json` names. `pnpm check:release-age` ([`scripts/check-release-age.ts`](scripts/check-release-age.ts)) closes that gap (reviews R4-07, R6-03 and R6-04). It checks, against the npm registry:

- Every version in `pnpm-lock.yaml`: it must have been published at least 14 days before the check runs, and its locked integrity must be the digest the registry publishes for that version. pnpm installs whatever matches the integrity, wherever it fetches it from, so a mismatch fails and no exception accepts it.
- The pnpm version in `packageManager`, which pnpm/action-setup in CI and corepack install, and the one in `devEngines.packageManager` if present, under the same 14-day rule and exception list. `packageManager` must name an exact version (`pnpm@10.28.0`). A hash is optional; if there is one it must be the sha512 hash that `corepack use pnpm@<version>` writes, and it must match the registry. The check refuses a range, a tag, a URL or another hash algorithm and says why, since it could not date or compare what would run.

A version it cannot date fails too: one not resolved from the npm registry, one without a publish time or digest, or a registry error.

The check reads `pnpm-lock.yaml` strictly. It accepts only the YAML layout pnpm writes and refuses anything else with the line number: a comment, an entry written on one line, a different indentation, a value that continues on the next line, anchors, aliases and tags. A reader that skipped such a line could miss an entry that pnpm installs. Every snapshot and every importer dependency must also lead to an entry in `packages`. If a pnpm upgrade writes a layout the check refuses, extend the reader; do not rewrite the lockfile by hand.

pnpm also installs config dependencies outside the lockfile, before it reads the lockfile, and runs `pnpm-plugin-*` ones as a pnpmfile on every command. The project declares none, and the check refuses them (review R8-01):

- `pnpm-workspace.yaml` is read as strictly as the lockfile: block layout only, with comments on their own lines. It may hold only `packages`, `onlyBuiltDependencies`, `minimumReleaseAge` and `minimumReleaseAgeExclude`. Any other setting is refused with its line number: `configDependencies`, and also settings such as `pnpmfile`, `lockfileDir` or `gitBranchLockfile` that make pnpm run code or read another lockfile. To add a setting, extend the check first.
- The `pnpm` field in `package.json`, if present, must be an object without `configDependencies`.

Corepack takes the nearest `package.json` that names `packageManager` or `devEngines.packageManager`, and loads `.corepack.env` files, starting from the directory a command runs in; pnpm finds `pnpm-workspace.yaml` the same way. So only the root `package.json` may name a package manager, only the root holds `pnpm-workspace.yaml`, and the project uses no `.corepack.env` at all (review R8-02). The check walks the checkout, without `node_modules` and `.git`, and refuses any of these elsewhere. It does not follow symbolic links and refuses them too, since corepack and pnpm would follow them.

- Run it after any change to `pnpm-lock.yaml` or `packageManager`. It needs network access to `registry.npmjs.org` and nothing else, so `pnpm run ci` does not run it.
- CI runs it in the `release-age` job before anything is installed: every job that installs packages or pnpm needs that job, and pnpm/action-setup gets no `version` input, so it follows `packageManager`. The `release-age` job installs nothing and runs no package code, and the script imports only Node built-ins. A script test applies these rules to every file in `.github/workflows`, so a new workflow that installs needs its own `release-age` job (review R8-04). `deploy-dry-run` also needs `check`, so one green status covers the bundle and `rules:check` (R8-05).

When a locked version is too young, remove it from `pnpm-lock.yaml` and run `pnpm install`, which resolves it again under `minimumReleaseAge`. `pnpm update` alone can fail when a locked parent pins the young version exactly. When the pnpm in `packageManager` is too young, pin an older release.

Exceptions are for versions the project accepts although they fail the check, for example a security fix that cannot wait 14 days:

- Add an entry to `EXCEPTIONS` in `scripts/check-release-age.ts`: `package` is the exact lockfile key (`name@version`, or the key of a package that is not from the registry) or, for the pnpm in `packageManager`, `pnpm@<version>`. `accepts` names the failure it accepts, `reason` says why, and a comment above it gives the context.
- For a version from the registry, `accepts` is `too_young`. The check reaches that failure only after the locked integrity matched the registry's, so the exception accepts only the registry's bytes for that version (review R8-03).
- For a package that is not from the registry, `accepts` is `not_registry` and `resolution` is its resolution exactly as `pnpm-lock.yaml` records it: the tarball with its integrity, the repository and commit, or the directory. The check compares it with the locked resolution, so the exception accepts no other source under the same key.
- One entry covers one exact version. A newer version needs its own entry.
- An exception never accepts an integrity mismatch or a version the check could not verify. The check refuses an exception that names another failure, or a tarball without its integrity.
- The check prints each accepted failure as `excepted` and names entries that no longer match a failure, because the version is gone or old enough. Remove those.
- pnpm resolves a version younger than `minimumReleaseAge` only if `minimumReleaseAgeExclude` in `pnpm-workspace.yaml` exempts the package.
- Adding an exception is the maintainer's decision.

## Ground rules

- **Read-only, always.** Code must never call a Cloudflare API endpoint that changes state in a scanned account. All API calls go through the credential broker and its allowlist of read calls.
- **Untrusted input.** Every string from a scanned account is untrusted: names, DNS records, policy names, code and scanner output. Validate it, limit its size, and mark it as untrusted wherever it reaches the UI, the MCP server or logs.
- **No secrets in the repository**, in fixtures, or in logs. Fixtures use synthetic or sanitized data.
- **Unknown is a result.** If a collector lacks permission or the evaluator cannot decide, report `not evaluated` or `unknown`. Never report a pass or `public` instead.

## Rules

A rule contribution contains:

- `rules/CF-xxx/rule.sql` with front matter (ID, version, title, severity, kind, required resource classes, parameters) and exactly one `SELECT` or `WITH` statement
- at least one positive and one negative fixture in `rules/CF-xxx/fixtures/`, and an undecided one when the rule reads or requires `exposure`
- a fix proposal in `rules/CF-xxx/fix/`

The format is described in [docs/architecture/data-model.md](docs/architecture/data-model.md#rule-files).
