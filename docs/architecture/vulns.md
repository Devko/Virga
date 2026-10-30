# Vulnerability matching

Status: implemented in [`packages/vulns`](../../packages/vulns) and in the vulns functions of [`packages/graph/src/write.ts`](../../packages/graph/src/write.ts) (`applyVulnRematch`, `listVulns`). It is phase 2 work started early under [decision 0007](../decisions/0007-later-phases-before-the-phase-1-gate.md). Nothing calls it yet: no collector emits package nodes, there is no advisory mirror, and no scan or schedule runs a rematch. The OSV and KEV fixtures are hand-written from the published schemas; no real advisory data has gone through the code.

The goal is the `vulns` input of CF-001 (and later CF-005): which package nodes have an open vulnerability, how severe, and whether it is known to be exploited. "Unknown is a result" holds here too: a match that cannot be decided or ranked is never written as harmless, and it keeps CF-001 `not_evaluated`.

## Inputs

| Input | Form | Source |
| --- | --- | --- |
| Package nodes | Node IDs `package:<purl>`, npm purls such as `pkg:npm/%40scope/name@1.2.3` | Not built yet: the `workers` collector from `package_dependencies`, after [S-04](../spikes/S-04-worker-dependencies.md) |
| Advisories | One OSV record per JSON text, read with `readOsvFeed` | Not built yet: the advisory mirror |
| KEV catalog | The CISA catalog JSON, read with `readKevCatalog` | Not built yet: the same mirror |
| Existing rows | `listVulns(db)` | The `vulns` table |
| Completeness | `packagesComplete`, `feedComplete` | The caller: is the package set every live package node, is the feed the whole mirror? |
| Time | Epoch milliseconds | `first_seen` of new rows |

`rematch` is pure. `applyVulnRematch` writes its result in one transaction.

## OSV records

The reader follows [OSV schema 1.9.2](https://ossf.github.io/osv-schema/) (`OSV_SCHEMA_VERSION`). A record that declares a `schema_version` other than `1.x.y` is rejected.

Advisory data is untrusted. `readOsvRecord` reads only what matching needs and checks it strictly; a record that breaks the schema or a limit is rejected as a whole, with a reason, and never used in part. Reasons hold a path and fixed words (`affected[2].ranges[0].events: no introduced event`), never text from the record. `summary`, `details`, `references` and `credits` are not read.

| Field | Rule |
| --- | --- |
| Record | At most 4 MiB of UTF-8, checked before parsing; a JSON object |
| `id` | Required; `^[a-zA-Z0-9:_.-]+$`, at most 128 characters. Without a readable ID the rejection has `id: null` |
| `modified` | Required string, at most 64 characters |
| `withdrawn` | Optional string. A valid withdrawn record matches nothing |
| `aliases` | Optional; at most 100, each in the ID format |
| `severity`, `affected[].severity` | Optional; at most 16 entries of `type` (32 characters) and `score` (256). Both levels set in one record is a violation |
| `database_specific.severity` | Optional string, at most 32 characters. Nothing else of `database_specific` is read |
| `affected` | At most 1,000 entries. Only `package.ecosystem` is checked for entries of other ecosystems; they are counted (`skippedEntries`) and skipped. An entry without `package` counts as another ecosystem |
| `package.name` (npm) | Required, not empty, at most 256 characters. `*` is the schema's wildcard for every package |
| `ranges` | At most 100 per entry. `type` is `SEMVER`, `ECOSYSTEM` or `GIT`; at most 500 events; each event has exactly one of `introduced`, `fixed`, `last_affected`, `limit` with a non-empty string of at most 256 characters; at least one `introduced`; not both `fixed` and `last_affected` |
| `versions` | At most 50,000 per entry, strings of at most 256 characters. osv.dev lists every affected release, and some packages have thousands of canary builds |

Ecosystem `npm` only, compared exactly. `readOsvFeed` reads a set of records. An ID that has a rejected record, or more than one record, is rejected as a whole. The feed keeps the IDs of withdrawn records and of records without npm entries apart from the advisories, so the rematch knows the advisory was read.

Version strings are not checked by the reader: `ECOSYSTEM` versions are uninterpreted strings in the schema. A version that does not parse is an unknown match for packages of that name only, not a rejected record.

## Packages and versions

`parseNpmPurl` accepts the canonical npm form only:

- `pkg:npm/` in lower case, without slashes after `pkg:`. Another purl type is `unsupported purl type`.
- No qualifiers or subpath. A qualifier such as `repository_url` can name another registry, where the same name is another package.
- An optional scope, `%40scope` or `@scope`, then the name. Each part uses the characters `encodeURIComponent` leaves alone; at most 214 characters together, as npm allows.
- The version is percent-decoded and must be [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html): no `v` or `=` prefix, no ranges. Numeric parts compare as strings, so numbers above 2^53 compare exactly.
- The name keeps its case and is compared exactly. npm names are case sensitive, and old packages such as `JSONStream` have capitals. The collector must keep npm's spelling.

A package that does not parse is reported in `unparsed` with the reason and is not matched.

## Matching

For a package and an advisory, every npm entry whose name equals the package name (or is `*`) is evaluated; the others do not apply. Three results: `affected`, `not_affected`, `unknown`.

- **Ranges** follow the schema's evaluation pseudocode. With `limit` events, the version must be below one of them (`*` is infinity). Then the events are walked in version order, `introduced: "0"` first: `introduced` at or below the version starts an affected span, `fixed` at or below it ends one, `last_affected` below it ends one. At equal versions, `introduced` comes first, so `introduced: X, fixed: X` affects nothing and `introduced: X, last_affected: X` affects exactly X. Several spans in one range work, and the order of events in the record does not matter.
- **`SEMVER` and `ECOSYSTEM`** are evaluated alike: npm versions are SemVer, ordered by SemVer precedence. Build metadata does not count.
- **Prereleases** are ordered by precedence. `2.0.0-rc.1` lies inside `introduced: 1.0.0, fixed: 2.0.0`, and `1.0.0-rc.1` lies outside `introduced: 1.0.0`. npm's rule that ranges skip prereleases does not apply to advisories.
- **`versions`** matches by SemVer equality, or by exact text.
- **Unknown**: an event version that does not parse (`1.2`, `v1.0.0`, `>=1.0.0`, `0` outside `introduced`, `*` outside `limit`) makes the whole range `unknown`; a `GIT` range is `unknown`; a listed version that does not parse makes the list `unknown` when it does not match; an entry with neither ranges nor versions is `unknown`.
- **Combining**: ranges and the list of an entry, and the entries of an advisory, combine as `affected` over `unknown` over `not_affected`.
- **`fixed_in`** is the lowest `fixed` version above the installed one in the entries that matched, or null.

## Severity

`severity_rank` is 0 none, 1 low, 2 medium, 3 high, 4 critical (data model). The entry's own `severity` applies when it has one, otherwise the top level.

1. CVSS v3.0 and v3.1 vectors (`CVSS_V3`) decide when there is at least one. The base score follows the FIRST specifications, including each version's Roundup; temporal and environmental metrics are validated and ignored. The highest score counts: 0.0 none, 0.1 to 3.9 low, 4.0 to 6.9 medium, 7.0 to 8.9 high, 9.0 to 10.0 critical. A vector that does not parse makes the rank unknown, unless a valid vector already gives critical.
2. Without a v3 vector, `database_specific.severity` as GitHub advisories carry it: `LOW` 1, `MODERATE` 2, `HIGH` 3, `CRITICAL` 4. Any other value is unknown.
3. Otherwise the rank is unknown, for example with only a CVSS v4 or v2 vector.

An unknown rank is never written as 0: CF-001 would read 0 as harmless. The match is reported in `unknown` with reason `severity unknown`.

## KEV

`readKevCatalog` reads the [CISA catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) strictly: at most 32 MiB and 100,000 entries; `catalogVersion` and `dateReleased` (strings, at most 64 characters) for provenance; `count`, which must equal the number of entries, so a cut file is caught; and every `cveID`, which must match the schema's `^CVE-[0-9]{4}-[0-9]{4,19}$`. Other fields are not read. Any violation rejects the catalog.

A match has `kev = 1` when the advisory ID or any alias is in the catalog. Without a catalog (`kev: null`), new rows get `kev = 0`, existing rows keep their flag, and the result is not complete.

## Rematch

`rematch` returns the rows to write, the unknown matches, the packages it could not parse, counts, and whether the result is complete. Rows that do not change are left out, so a daily rematch without news writes nothing.

| Case | Row |
| --- | --- |
| New decided match with a known rank | Inserted as `open`, `first_seen = at` |
| Existing row that still matches | Fields refreshed; `first_seen` kept; `fixed` becomes `open` again; `ignored` stays |
| Existing `open` row that no longer matches: the version is outside the advisory, the advisory is withdrawn or not in a complete feed, or the package is gone from a complete package set | `fixed`, other fields kept |
| Unknown match | Not written; an existing row stays as it is |
| Package that does not parse | Not matched; its rows stay |
| Advisory whose record was rejected | Its rows stay |
| Advisory missing from a feed that is not complete, or after a rejection without a readable ID | Its rows stay |
| Package missing from a package set that is not complete | Its rows stay |
| `ignored` row | Stays `ignored` |
| Row of another `source` | Not touched, unless a match has its key: the rematch takes it over and keeps `first_seen` and `ignored` |

The `source` of rematch rows is `osv` unless the caller names another. Rule fixtures write `fixture` rows through `upsertVulns`, which is not for rematches.

`applyVulnRematch(db, scanId, result)` checks every row first (package ID prefix and length, vuln ID and alias format, rank 0 to 4, boolean KEV, status, the result's `source`, integer `first_seen`, no key twice) and throws before writing anything. In one transaction it upserts the rows and records the scan's `vulns` coverage. On a key that exists, `first_seen` and an `ignored` status are kept whatever the row says, so a stale rematch cannot reset them. Rows are never deleted.

## Completeness and CF-001

A result is complete when every package parsed, no match is unknown, no record was rejected, the KEV catalog was read, and both the package set and the feed are complete. `applyVulnRematch` then records `vulns` as `complete`; otherwise as `partial`, with a detail made of counts only, such as `unknown matches: 2; no KEV catalog`. The detail holds no text from advisories or the scanned account.

CF-001 requires `vulns` (and `packages`), and `evaluateRules` runs a rule only when every input it requires is `complete` in the scan. An incomplete rematch therefore leaves CF-001 `not_evaluated`: its findings neither open nor resolve. Its decided rows are still written, so the table stays current.

The lists `unknown` and `unparsed` hold package IDs from the scanned account. A caller that logs them treats them as untrusted, like every string from a scanned account; counts are enough for the scan summary.

## Not done yet

- **Packages.** No collector emits `package` nodes or `CONTAINS` edges. Extraction from Worker versions waits for [S-04](../spikes/S-04-worker-dependencies.md): `package_dependencies` came back `null` in a temporary account, and source maps were not returned.
- **Advisory mirror and its sync.** Where the OSV npm records and the KEV catalog come from, how they are stored (R2, indexed by package name), how often they sync, and how the tool reaches osv.dev and cisa.gov (these are not Cloudflare API calls and do not go through the broker) are open. The sync decides `feedComplete`.
- **Scheduling.** Neither the scan nor a daily schedule runs the rematch.
- **Malicious packages.** OSV `MAL-` records carry no severity, so a match is `severity unknown` and keeps CF-001 `not_evaluated`. Ranking them critical needs a decision.
- **CVSS v4.** Advisories with only a v4 vector and no database severity are unknown. GitHub advisories carry a database severity, so this mostly concerns other sources.
- **Aliases.** Two records that alias each other, for example a GitHub malware advisory and its `MAL-` record, give two matches. Matches are not merged by alias.
- **Real data.** The limits come from the schema and estimates; check them against a copy of the real mirror before relying on them. A record over a limit is rejected and makes the result incomplete.
