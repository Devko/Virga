# Versioning policy

Status: policy, 2026-10-30. No release exists yet. Under [decision 0007](../decisions/0007-later-phases-before-the-phase-1-gate.md), nothing is released before its phase gate and every earlier gate have passed; the first release comes with the phase 4 gate of the [implementation plan](../implementation-plan.md#phase-4-hardening-and-first-release). Everything this policy says a release contains is planned, not done.

## What a version covers

- **One version for the repository.** A release is a tag `v<major>.<minor>.<patch>` on a commit of the main branch. It covers the three Workers, the rules, the graph schema and the D1 migrations, the deploy script, the JSON API, the MCP tools, the OCSF output and the operator documentation.
- **One version per instance.** The deploy script deploys `virga-broker`, `virga-core` and `virga-web` from one checkout, and the Workers are not meant to run at different versions.
- **No package versions.** The workspace packages under `apps/` and `packages/` are private, are not published, and keep the version `0.0.0`.

## Version numbers

Virga follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html):

- **Major:** a breaking change, as defined below.
- **Minor:** something new that keeps existing instances working: a new rule or collector, a new optional setting, a new API field or route, a new MCP tool, a graph migration that applies in place.
- **Patch:** a fix that changes no interface: a bug fix, a rule fix within the rule's meaning, a dependency update, documentation.

Before 1.0.0, a breaking change raises the minor version and everything else the patch version. Release candidates carry `-rc.<n>`; the phase 4 gate runs against one. Whether the first release is 0.1.0 or 1.0.0 is the maintainer's decision.

## Breaking changes

A change is breaking when an operator who updates and runs the deploy script as before can lose data, findings, suppressions or access, has to do something first, or when a program that reads Virga's output has to change.

| Area | Breaking | Not breaking |
| --- | --- | --- |
| Graph schema | A migration that cannot be applied in place in every account's Durable Object: one that drops findings, suppressions, history or coverage, or needs a rescan from an empty graph | A new entry in `MIGRATIONS` (`packages/graph/src/schema.ts`) that keeps existing rows; new tables, columns or indexes. Applied migrations are never edited |
| Index and vault databases | A D1 migration of `virga-index` or `virga-vault` that cannot be applied in place; a change of the vault format or its encryption that needs tokens onboarded again | A migration that keeps existing rows |
| Rules | A rule ID removed, or its meaning changed (see [Rule versions](#rule-versions)); a new fingerprint format, which separates new findings from existing findings and suppressions; a resource class added to `requires` that needs a permission group existing scan tokens do not have; an evidence column removed or renamed | A new rule; a fix within the rule's meaning; a new severity; a new evidence column |
| JSON API (`/api`) | A route, query parameter or response field removed or renamed; a field whose type or meaning changes; a new required request field; a tighter limit that refuses requests the previous release accepted | A new route, optional parameter or response field; a new value of an existing enumeration. Clients ignore fields they do not know and treat unknown values as unknown |
| MCP tools | A tool or input removed or renamed; a result whose shape or meaning changes; a change of the notice or the `<untrusted-data>` block around results | A new read-only tool, optional input or result field. A tool that changes state is never added (see the non-negotiables in [CLAUDE.md](../../CLAUDE.md)) |
| OCSF output, once it exists | Another OCSF schema version or event class; a different mapping of an existing attribute | A new optional attribute within the same schema version |
| Deploy and operation | A new required step, setting, secret or binding; a renamed Worker, binding, database, Workflow or Durable Object class; a new permission group in the deploy token or in a scan token profile; a deploy check that refuses a setup the previous release accepted; a Node.js, pnpm or Wrangler version that is no longer supported | A new optional setting; a new warning |

**Security fixes** ship when they are ready. A fix that refuses something the previous release accepted, such as a token, a config key or an environment variable, is breaking: it raises the major version, and the release notes say what to change. The fix is not held back to avoid a major version.

**Deprecation.** Before a major release removes an API field, an MCP tool, a rule ID or a setting, a minor release marks it as deprecated where possible, under "Deprecated" in the changelog, with its replacement. Security fixes may skip this step.

**No downgrades.** Durable Object and D1 migrations run forward only. Going back to an earlier release after a migration is not supported.

## Rule versions

Each rule has a `version` in the front matter of its `rule.sql`, an integer that starts at 1 ([data model](../architecture/data-model.md#rule-files)). Each finding stores the version of the rule that last wrote it (`findings.rule_version`).

- **Raise the version** on any change to the query, the parameters, the severity, `requires`, or the evidence columns. A change to fixtures alone does not raise it.
- **Same meaning, same ID.** As long as a rule answers the same question about the same subject, its fingerprints stay the same across versions, so findings and suppressions carry over ([data model](../architecture/data-model.md#findings-lifecycle)).
- **New meaning, new ID.** A rule that answers a different question, is about a different subject, or keys its fingerprint differently gets a new ID. The old ID is retired and never reused. [Decision 0004](../decisions/0004-cf-024-scope.md) describes such a case: if Pages moves out of CF-024, it gets an ID of its own. What happens to the findings of a retired ID is not decided yet; until it is, retiring an ID is a breaking change.

How rule changes map to version numbers:

| Rule change | Release |
| --- | --- |
| A new rule | Minor |
| A new rule version with the same meaning, fingerprints and inputs | Patch, also when it opens or resolves findings that the earlier version got wrong |
| A new default severity, a new evidence column, a new optional parameter | Minor |
| A resource class added to `requires` that needs a new permission group | Major |
| A rule retired, its meaning changed, or its fingerprint format changed | Major |

The release notes list every rule whose version changed, with the old and the new version and what changed.

## What a release contains

Planned for the first release, as the phase 4 scope and gate and the [design spec](../concept/design-spec.md#security-of-the-tool-itself) describe it. None of it exists yet.

- **A signed release.** A signed tag on a commit whose CI passed, including the `release-age` job and `rules:check`, and signed release artifacts. How they are signed is not decided yet.
- **An SBOM.** A CycloneDX SBOM of the dependencies the release ships, from the lockfile and the Workers' bundles.
- **Release notes**, taken from the changelog section of the version:
  - breaking changes first, each with what the operator has to do before or after the deploy;
  - graph, index and vault migrations;
  - rules added, changed (with their versions) or retired;
  - changes to the JSON API, the MCP tools and the OCSF output;
  - security fixes with their review IDs;
  - residual risks the [threat model](../architecture/threat-model.md) adds or closes;
  - the non-affiliation notice below.
- **Documentation for that version:** the operator guide and the threat model.
- **From phase 2 on:** scanner images pinned by digest and checked by signature.

The phase 4 gate adds three conditions: a fresh install from a signed release passes the phase 1 to 3 gates on the test range, a third party deploys an instance using only the documentation, and the release notes and this policy are published with the release.

Release notes end with this notice (D-01):

> Virga is an independent open source project. It is not affiliated with or endorsed by Cloudflare, Inc., and it uses no Cloudflare logos.

## Changelog

[CHANGELOG.md](../../CHANGELOG.md) follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

- A change that an operator, a rule author, or a reader of the API, MCP or OCSF output would notice gets an entry under "Unreleased" in the same merge.
- Entries go under Added, Changed, Deprecated, Removed, Fixed or Security. A breaking entry starts with "**Breaking:**".
- At a release, "Unreleased" becomes the version heading with the date, and a new empty "Unreleased" section starts.

## Supported versions

Until a support policy exists, only the latest release gets fixes. Report vulnerabilities as [SECURITY.md](../../SECURITY.md) describes.
