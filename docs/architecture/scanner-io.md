# Scanner I/O

Status: implemented in [`packages/scanner-io`](../../packages/scanner-io). Phase 2 logic, started before the phase 1 gate under [decision 0007](../decisions/0007-later-phases-before-the-phase-1-gate.md). The readers follow the documented output of each tool; none has read captured output yet. The scanner container that produces the reports waits for spike S-07.

The package has two parts:

- **Readers** turn the JSON output of osv-scanner, Trivy and gitleaks into one normalized, typed result. They are the boundary for scanner output, which is untrusted ([design spec](../concept/design-spec.md#security-of-the-tool-itself): "validated against a schema with size limits"; phase 2 gate 6).
- **SBOM generator** writes a CycloneDX 1.6 JSON document for one Worker version (phase 2 gate 2).

The package is runtime-agnostic: no `node:` imports and no dependencies, so it runs in a Worker or a Workflow step.

## Formats and versions

| Tool | Output | Format followed | Read | Never read |
| --- | --- | --- | --- | --- |
| osv-scanner | `osv-scanner scan --format json` | osv-scanner 2 output reference (1.x writes the same members); vulnerability entries in the OSV schema 1.6 | `results[].packages[]`: `package.name`, `.version`, `.ecosystem`; per vulnerability `id`, `aliases`, `database_specific.severity`, the `fixed` events of `affected[].ranges[]` (types `ECOSYSTEM` and `SEMVER`) for the same package; per group `ids`, `max_severity` | Everything else |
| Trivy | `trivy image\|fs\|rootfs --format json` | Report `SchemaVersion` 2 as Trivy 0.5x and 0.6x write it (`types.Report`). Any other schema version is rejected | `Results[]`: `Target`, `Type`; `Packages[]`: `ID`, `Name`, `Version`, `Release`, `Epoch`, `Identifier.PURL`; `Vulnerabilities[]`: `VulnerabilityID`, `VendorIDs`, `PkgID`, `PkgName`, `PkgIdentifier.PURL`, `InstalledVersion`, `FixedVersion`, `Severity`; `Secrets[]`: `RuleID`, `StartLine`, `EndLine` | `Secrets[].Match` and `.Code`, which hold the secret |
| gitleaks | `gitleaks dir\|git --report-format json` | gitleaks 8, an array of `report.Finding` | `RuleID`, `File`, `StartLine`, `EndLine`, and `Secret` once, for its prefix | `Match` and `Line`, which hold the secret |

Members that are not read are ignored, so a newer tool version that adds members still passes. They still count against every limit. The sample reports in `test/samples.ts` are hand-written from the documentation; S-07 should replace them with captured output and re-check the members above.

## Result

Every reader returns the same shape, sorted and without duplicates, so equal input gives equal output:

- `packages`: `purl` (or `null`), `ecosystem`, `name`, `version` (or `null` for an empty version). A package is identified by its purl, or by ecosystem, name and version when it has none. The first entry seen wins.
- `vulnerabilities`: `package`, `id`, `aliases` (without `id`), `severity`, `fixedVersions`. A match is identified by package and ID. Merged matches take the higher severity and the union of aliases and fixed versions.
- `secrets`: `ruleId`, `file`, `line`, `endLine`, `prefix`, `masked` (see [masking](#masking)).

`name`, `version`, `file` and Trivy's `Target` come from the scanned workload. They are checked for length and characters but remain untrusted display strings; the UI, the MCP server and logs mark them as such.

**Package URLs.** Trivy's purls are kept as Trivy wrote them, after validation. osv-scanner writes no purl; the reader derives one for npm only: name lowercased (the purl rule for npm), the scope as namespace with `@` encoded as `%40`, everything outside `A-Z a-z 0-9 . - _ ~` percent-encoded, for example `pkg:npm/%40babel/traverse@7.22.0`. Other ecosystems get `purl: null`, because a wrong purl would join the wrong package node. Worker bundles are npm.

**Severity** is the graph's rank (0 none, 1 low, 2 medium, 3 high, 4 critical) or `null`:

| Source | Mapping |
| --- | --- |
| Trivy `Severity` | `LOW` 1, `MEDIUM` 2, `HIGH` 3, `CRITICAL` 4, `UNKNOWN` null; any other value rejects the report |
| osv-scanner `groups[].max_severity` | A CVSS base score as text, rated as CVSS v3 does: 0.0 none, 0.1 to 3.9 low, 4.0 to 6.9 medium, 7.0 to 8.9 high, 9.0 to 10.0 critical. A label (`LOW`, `MODERATE`, `MEDIUM`, `HIGH`, `CRITICAL`) maps as below. Empty or other text: no severity from the group |
| osv-scanner `database_specific.severity` (fallback) | `LOW` 1, `MODERATE` and `MEDIUM` 2, `HIGH` 3, `CRITICAL` 4; anything else null. `database_specific` is free-form in the OSV schema, so a surprise there is not an error |

`null` means the tool stated no severity Virga can map. It is unknown, never "none".

**Fixed versions.** Trivy writes several in one string (`"8.17.1, 7.5.10"`); the reader splits them. For osv-scanner they are the `fixed` events of the package's version ranges; `GIT` ranges carry commits and are skipped.

## The rejection rule

A report that breaks a type, a pattern or a limit is rejected as a whole. It is never partly used: the reader builds its result only after the last check. The only error a reader throws for bad input is `ScannerOutputRejected` with:

- `tool`
- `reason`: one of `too_large`, `invalid_encoding`, `invalid_json`, `too_deep`, `too_many_values`, `too_many_items`, `too_many_keys`, `string_too_long`, `number_out_of_range`, `duplicate_key`, `wrong_type`, `missing_field`, `invalid_text`, `invalid_format`, `unsupported_version`, `out_of_range`, `secret_in_kept_field`
- `at`: a JSON pointer built from Virga's own field names and array indices (`/Results/2/Secrets/0/StartLine`), or a character offset for parse errors

The message never quotes the input, so neither a secret nor a hostile string travels in an error or a log line.

A rejected report means the workload was not evaluated. The caller records it that way and never as clean. Someone who controls a workload can force a rejection (for example with a control character in a module name); that hides nothing, because "not evaluated" is visible, but it does mean an attacker can turn a finding into a gap. Rules and the UI treat the gap as a result.

Some reports are rejected on purpose even though they are valid JSON: an osv-scanner object without `results` and a Trivy report without `SchemaVersion` 2 are not scans, and treating them as empty would report a clean workload.

## Strict JSON

`JSON.parse` cannot enforce limits while it parses, keeps the last of two duplicate keys without a word, and accepts lone surrogates. The package has its own RFC 8259 parser instead. It checks every limit as it goes, so an oversized array is refused before it is built, and it rejects:

- duplicate keys anywhere in the document (two parsers that pick different values are a known smuggling route)
- lone surrogates, raw or escaped; invalid UTF-8 when the input is bytes (decoded with `fatal: true`)
- numbers that do not fit a double (`1e400`) and number literals longer than 64 characters
- a byte order mark, comments, trailing commas and trailing data

Objects become `Map`s, so a key such as `__proto__` is only a string. Recursion depth is bounded by `maxDepth` (at most 256), far from the stack limit.

## Limits and why

Defaults, overridable per call through `ReaderOptions.limits`. They are first estimates; S-07 and the test range will show real report sizes.

| Limit | Default | Why |
| --- | --- | --- |
| `maxBytes` | 16 MiB | A large image with every package listed stays below a few MiB. 16 MiB of text plus the parsed tree still fits the 128 MB of a Worker |
| `maxDepth` | 32 | osv-scanner output nests 13 levels down to `affected[].ranges[].events[]`; free-form members get the rest |
| `maxValues` | 500,000 | Bounds the parsed tree, whatever the shape |
| `maxArrayItems` | 100,000 | OSV `affected[].versions` can list thousands of versions |
| `maxObjectKeys` | 1,000 | Report objects have a few dozen members |
| `maxStringLength` | 256 Ki UTF-16 units | OSV `details` and Trivy `Description` are prose, rarely above 50 KB |
| `maxPackages`, `maxVulnerabilities` | 50,000 each | Distinct entries in the result |
| `maxSecrets` | 10,000 | Distinct secret findings |

Kept strings have their own limits:

| Field | Limit | Rule |
| --- | --- | --- |
| Advisory ID, alias | 128 | `[A-Za-z0-9][A-Za-z0-9._:-]*` (CVE, GHSA, PYSEC, `RHSA-2024:1234`) |
| Rule ID | 128 | `[A-Za-z0-9][A-Za-z0-9._-]*` |
| purl | 512 (the graph's native ID limit) | See below |
| Package name | 512 | Clean text, not empty |
| Version, fixed version | 256 | Clean text |
| File, Trivy `Target` | 1,024 (the graph's name limit) | Clean text, may be empty |
| Ecosystem, Trivy `Type` | 128 | `[A-Za-z0-9][A-Za-z0-9 ._:+-]*` (`Debian:12`, `Red Hat:enterprise_linux:9`) |
| Aliases, fixed versions per match | 100 each | |
| OSV `affected`, `ranges`, `events` | 1,000, 100, 1,000 | Per entry |

**Clean text** has no C0 or C1 control character, no lone surrogate, no bidi control (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) and no line or paragraph separator.

**purls** use only the characters the purl spec leaves unencoded (`A-Z a-z 0-9 . - _ ~ % ! $ & ' ( ) * + , ; = : @ / ?`), valid percent escapes, a lowercase type, a non-empty version after the last `@`, and qualifiers as `key=value` pairs. A subpath (`#`) is refused: graph edge IDs use `#` before the edge key, so a purl with `#` could make two edges collide.

## Masking

The reader never returns or keeps a raw secret:

1. gitleaks: `Secret` is read once, inside the loop over findings, to see whether it starts with a known prefix (`cfat_`, `cfut_`, `cfk_`, followed by at least one character). `Match` and `Line` are never read. Trivy: no member that holds the secret is read; Trivy masks them by default, but Virga does not rely on that.
2. What leaves is the rule ID, the file, the lines, the prefix and `masked`: the prefix followed by `********`. The prefix is Virga's own constant, not a slice of the input. The mask is the same for every secret, whatever its length.
3. No hash of the secret is kept. A hash of a weak or short secret can be guessed, which would turn the finding store into a secret store.
4. Two guards keep a secret from leaving through another field. A gitleaks finding whose file or rule ID contains its own secret (without the prefix, eight characters or more) is rejected. Any kept string in any reader that contains a Cloudflare token shape (a prefix and 40 or more token characters) is rejected with `secret_in_kept_field`. A secret of one finding inside the file name of another is not searched for; file names are account metadata, not scanner classifications.

Trivy findings therefore have `prefix: null`; the kind is the rule ID. A Virga-supplied Trivy rule for Cloudflare tokens would need a rule-ID-to-prefix map, which does not exist yet. A prefix links a finding to the token inventory by kind only: without the value or a hash, it cannot name the token.

`test/masking.test.ts` seeds dummy secrets (built at run time, so no token-shaped literal sits in the repository) into every member that holds a secret. It checks that no six-character piece of any secret body appears in a result, nor in the message, stack, own properties or string form of any rejection, for ten kinds of broken report.

## Fuzz test (gate 6)

`test/fuzz.test.ts` runs a deterministic mutation fuzzer with no dependency. A seeded PRNG (mulberry32) starts from the valid samples and applies one to three mutations of the parsed value, then sometimes a mutation of the text, and sometimes turns the text into bytes with invalid UTF-8:

- value: wrong types, missing fields and items, extra fields (`__proto__` and `constructor` included), huge strings, huge arrays, deep nesting, invalid UTF-16, NUL, other controls and bidi characters, edge numbers, duplicated items, emptied containers
- text: duplicate keys, truncation, inserted and deleted characters, a byte order mark, trailing data, `1e400` and long digit strings, deep nesting around the document, single quotes
- bytes: overlong forms, encoded surrogates, stray bytes

For each run, the reader must either return a result that passes an independent invariant check (`test/invariants.ts`: types, patterns, limits, sort order, uniqueness, every match's package listed, masks well formed, no piece of a seeded secret) or throw `ScannerOutputRejected` for its own tool with a known reason and no secret in it. Each run must finish within 2 s; runs take a few milliseconds. The test also requires that mutations reach both sides: enough accepted results, enough rejections, and more than five distinct reasons.

| Parameter | Value |
| --- | --- |
| Seed | `20261030` (`SCANNER_IO_FUZZ_SEED`) |
| Iterations per reader | 600 with small limits, 60 at the default limits (`SCANNER_IO_FUZZ_ITERATIONS`, the second pass runs a tenth) |
| Time bound | 2,000 ms per run |

A longer local run:

```sh
SCANNER_IO_FUZZ_ITERATIONS=20000 SCANNER_IO_FUZZ_SEED=7 \
  pnpm --filter @virga/scanner-io exec vitest run test/fuzz.test.ts
```

A failure names the seed and the iteration, so it can be replayed. Three seeds at 10,000 iterations each passed when the package was written.

## CycloneDX SBOM

`buildWorkerSbom` writes one CycloneDX 1.6 JSON document per Worker version from its package list. `serializeSbom` gives the bytes to store.

| CycloneDX | Value |
| --- | --- |
| `$schema` | `http://cyclonedx.org/schema/bom-1.6.schema.json` |
| `bomFormat`, `specVersion`, `version` | `CycloneDX`, `1.6`, `1` |
| `serialNumber` | `urn:uuid:` and `crypto.randomUUID()`, or one the caller passes (checked against the schema's pattern) |
| `metadata.timestamp` | The collection time, ISO 8601 UTC |
| `metadata.tools.components[0]` | `application` `virga` with Virga's version (the object form; the list form is deprecated since 1.5) |
| `metadata.component` | `application`; `name` the script name, `version` the version ID, `bom-ref` `worker_version:<version ID>` |
| `components[]` | `library` with `bom-ref` and `purl` set to the purl, `name`, `version` |
| `components[].properties` | `virga:confidence` (`low`, `medium`, `high` for the graph's 0, 1, 2) and `virga:source` (`package_dependencies`, `sourcemap`, `banner`, `sbom`, as on the `CONTAINS` edge) |

Components are sorted by purl. A purl listed twice becomes one component: the higher confidence wins, then the source in the order above, then name and version. The same packages in any order give the same bytes, apart from the serial number and timestamp the caller controls.

Strings from the scanned account (script name, package names and versions) are values in the JSON document and nothing else; `JSON.stringify` escapes them, and nothing is concatenated into JSON text. The generator refuses input with control characters, lone surrogates or bidi controls, an invalid purl, an unknown source or confidence, a version ID that is not an ID, or a time outside years 1970 to 9999. Its errors name the field, never the value.

`checkSbom` is a structural self-check of what the generator emits, and the generator runs it on every document. It checks the members above and nothing else (stricter than the schema where Virga is: no other members, `bom-ref` equal to the purl, both properties present, components sorted, `bom-ref` unique). It is not schema validation.

## Not done yet

- **Schema validation for gate 2.** Validation against the official CycloneDX 1.6 JSON schema needs the schema files (`bom-1.6.schema.json` with `spdx.schema.json` and `jsf-0.82.schema.json`) and a JSON Schema validator. Neither is in the repository, and adding a validator is a dependency decision. The generator returns a plain JSON value, so a schema test can validate `JSON.parse(serializeSbom(bom))` later without changing it.
- **The scanner container** (Trivy, osv-scanner, gitleaks unmodified, no internet, outbound handlers): waits for S-07. The tool versions above must be pinned there by digest, and the samples replaced with captured output from exactly those versions.
- **Storing SBOMs in R2**: bucket layout, object keys and lifecycle are not decided.
- **Writing results to the graph**: `package` nodes, `CONTAINS` edges with `source: "sbom"` for container images, `vulns` rows and secret findings. The `vulns` table has `severity_rank NOT NULL`, so a writer must decide how to store an unknown severity without reporting it as "none".
- **Linking secret findings to the token inventory**, and a rule-ID-to-prefix map for Trivy.
- **purls for ecosystems other than npm** from osv-scanner, and matching purls written by different tools (Trivy and a future `package_dependencies` collector may encode the same package differently).
