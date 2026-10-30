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

Pin dependencies to exact versions released at least 14 days ago. `minimumReleaseAge` in `pnpm-workspace.yaml` makes pnpm resolve only such versions, but an install from the lockfile, as in CI, takes whatever the lockfile holds. `pnpm check:release-age` ([`scripts/check-release-age.ts`](scripts/check-release-age.ts)) closes that gap (review R4-07):

- It checks every version in `pnpm-lock.yaml` against the npm registry: each must have been published at least 14 days before the check runs. A version it cannot date fails too: one not resolved from the npm registry, one without a publish time, or a registry error.
- Run it after any change to `pnpm-lock.yaml`. It needs network access to `registry.npmjs.org` and nothing else, so `pnpm run ci` does not run it.
- CI runs it in the `release-age` job, before any job installs. That job installs nothing and runs no package code.

When a locked version is too young, remove it from `pnpm-lock.yaml` and run `pnpm install`, which resolves it again under `minimumReleaseAge`. `pnpm update` alone can fail when a locked parent pins the young version exactly.

Exceptions are for versions the project accepts although they fail the check, for example a security fix that cannot wait 14 days:

- Add an entry to `EXCEPTIONS` in `scripts/check-release-age.ts`: `package` is the exact lockfile key (`name@version`, or the key of a package that is not from the registry), `reason` says why, and a comment above it gives the context.
- One entry covers one exact version. A newer version needs its own entry.
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
