# S-04: Worker dependencies and source maps

- Status: partly answered; the API side is still open
- Date: 2026-10-29
- Code: [`spikes/s04-deps`](../../spikes/s04-deps)

## Question

What does `package_dependencies` on a Worker version contain: devDependencies, transitive packages, how many entries? Does the Versions API return source maps?

## What Wrangler sends

From the source of Wrangler 4.151.0 (`collectPackageDependencies`):

- It reads `dependencies` and `devDependencies` from the project's `package.json` and merges them. Nothing in an entry records which of the two it came from.
- Direct dependencies only. Transitive packages are not listed.
- At most 200 entries.
- Entries with `workspace:`, `catalog:`, `file:` or `link:` versions are skipped, as are packages that are not installed.
- Each entry is `{ name, packageJsonVersion, installedVersion }`, with the installed version read from the package's own `package.json`.
- Opt-out: `dependencies_instrumentation.enabled = false`; `exclude_packages` filters by name pattern.
- Wrangler 4.150+ generates source maps by default; the deploy reported `sourceMapSize: 37665`.

## What the API returned

The test Worker has one runtime dependency (`debug` 4.4.3, which depends on `ms`) and one devDependency (`is-number` 7.0.0) that it never imports. It was deployed twice to a temporary account. The deploy paths differ: the first creates the Worker, the second uploads a version.

`GET /accounts/{id}/workers/workers/{worker}/versions/{version}?include=modules` returned:

- `package_dependencies: null` for both versions
- one module, `index.js`, ending in a `sourceMappingURL` comment, and no source map module

Both packages resolve from the project directory, so Wrangler should have collected both entries. Either temporary accounts do not keep this metadata, or the API does not return it in this case. This needs a run in a regular account.

## Consequences

- **Confirmed: devDependencies are mixed in.** A package listed only in `package_dependencies` gets low confidence (A-11). It rises to medium or high only when bundle content or source maps show it. The fixture `negative-low-confidence-package` covers this for CF-001.
- **Transitive packages need source maps or an SBOM from CI.** `package_dependencies` will never list them.
- **Collectors must expect `null`.** Customers can opt out, and older Wrangler versions send nothing.

## Open

- Repeat the deploy and the API read in a regular account. Check whether `package_dependencies` and source maps come back, and in what form (separate module or another field).
