# Scanner I/O

Status: implemented in [`packages/scanner-io`](../../packages/scanner-io). Phase 2 logic, started before the phase 1 gate under [decision 0007](../decisions/0007-later-phases-before-the-phase-1-gate.md). The readers follow the documented output of each tool; none has read captured output yet. The scanner container that produces the reports waits for spike S-07.

The package has two parts:

- **Readers** turn the JSON output of osv-scanner, Trivy and gitleaks into one normalized, typed result. They are the boundary for scanner output, which is untrusted ([design spec](../concept/design-spec.md#security-of-the-tool-itself): "validated against a schema with size limits"; phase 2 gate 6).
- **SBOM generator** writes a CycloneDX 1.6 JSON document for one Worker version (phase 2 gate 2).

The package is runtime-agnostic: `src/` has no `node:` imports and the package no runtime dependencies, so it runs in a Worker or a Workflow step. Its one dev dependency, `@cfworker/json-schema`, serves the schema tests.

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

The parser counts values and object keys against `maxValues` and objects and arrays against `maxContainers` as well; both give `too_many_values`. A string with escapes is collected in pieces and joined once, so it is one flat string: appending each escape to the string built so far makes a rope of one node per escape, which V8 keeps as it is (see [memory budget](#memory-budget)).

## Limits and why

Defaults, overridable per call through `ReaderOptions.limits`. They are first estimates; S-07 and the test range will show real report sizes.

| Limit | Default | Why |
| --- | --- | --- |
| `maxBytes` | 16 MiB | A large image with every package listed stays below a few MiB. Memory follows the next two limits more than this one; see [memory budget](#memory-budget) |
| `maxDepth` | 32 | osv-scanner output nests 13 levels down to `affected[].ranges[].events[]`; free-form members get the rest |
| `maxValues` | 500,000 | Values and object keys. Each costs at most about 30 bytes of heap in workerd (a string, a number or a map entry) |
| `maxContainers` | 100,000 | Objects and arrays. An object costs about 100 bytes in workerd for two bytes of text, so containers have their own, tighter limit. Estimated from the format, not from captured output: a Trivy report near `maxBytes` has about 6,000 vulnerabilities and 65,000 containers |
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

**Clean text** has no C0 or C1 control character, no lone surrogate, no line or paragraph separator, and no character that renders as nothing: Unicode's Default_Ignorable_Code_Point, which holds the bidi controls (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) and also the soft hyphen (U+00AD), the combining grapheme joiner (U+034F), the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0), the Khmer inherent vowels (U+17B4, U+17B5), the Mongolian variation selectors and vowel separator (U+180B to U+180F), zero-width space, non-joiner and joiner (U+200B to U+200D), the word joiner, invisible operators and deprecated format characters (U+2060 to U+2065, U+206A to U+206F), variation selectors (U+FE00 to U+FE0F, U+E0100 to U+E01EF), the byte order mark (U+FEFF), U+FFF0 to U+FFF8, U+1BCA0 to U+1BCA3, U+1D173 to U+1D17A, and the tag characters (U+E0000 to U+E007F, with the rest of U+E0000 to U+E0FFF). Such characters can hide text or make two names look the same (R9 hardening).

They are refused, not escaped or removed, and the same everywhere: a reader rejects the report with `invalid_text`, and the SBOM generator throws `SbomInputError`. A kept string is compared and joined as written (purls, package keys, advisory names), so an escaped or shortened name would no longer match its advisory, and removing a character could make two names equal. The cost is a gap: a workload with such a character in a package name or a path is not evaluated, including text that uses U+200C or U+200D in its own script, and paths with emoji variation selectors. The list is written out in `src/text.ts`, so that Node and workerd refuse the same set; a test compares it with the engine's `\p{Default_Ignorable_Code_Point}` over all code points, and the fuzz invariants check the readers' output with that property.

**purls** use only the characters the purl spec leaves unencoded (`A-Z a-z 0-9 . - _ ~ % ! $ & ' ( ) * + , ; = : @ / ?`), valid percent escapes, a lowercase type, a non-empty version after the last `@`, and qualifiers as `key=value` pairs. A subpath (`#`) is refused: graph edge IDs use `#` before the edge key, so a purl with `#` could make two edges collide.

## Memory budget

A reader parses the whole report before it checks the shape, so the text, the parsed tree and the reader's own state must fit the 128 MB of a Worker together. Their size follows what is built, not the byte count (R9-06): `{}` is two bytes of text and a `Map` of about 100 bytes in workerd. Before round 10, five arrays of 99,998 `{}` (1.5 MB, 499,996 values) kept 48.3 MB in workerd, and 16 MiB of `\n` escapes kept 162.5 MB, because the parser built each escaped string as a rope of one node per escape. The fix bounds containers separately, counts object keys as values, builds every string flat, and keys the reader's matches by package and its secrets by file, so that no long string is copied once per entry (one package with a 900-character key and 50,000 matches held 127 MB in Node while the result was built).

Measured at the default limits: heap kept after two full collections. workerd 1.20261012.1, read through the V8 inspector (`HeapProfiler.collectGarbage`, then `Runtime.getHeapUsage`) with a harness that is not committed, because this package does not depend on workerd; Node 22.23 with `--expose-gc`. Node does not compress pointers, so objects take about twice the heap there; strings take the same.

| Input (accepted) | Bytes | Text | Tree, workerd | Tree, Node |
| --- | --- | --- | --- | --- |
| 99,980 `{}` (the container limit) | 0.3 MB | 0.3 MB | 9.7 MB | 19.4 MB |
| 499,980 strings of 12 characters | 7.5 MB | 7.6 MB | 14.3 MB | 20.7 MB |
| 499,980 strings that start with `\n` | 8.5 MB | 8.5 MB | 16.3 MB | 20.7 MB |
| 16 MiB of `\n` escapes in strings with one two-byte character | 16.3 MB | 32.5 MB | 16.3 MB | 16.4 MB |
| 249,000 members with 13-character keys and values | 8.0 MB | 8.0 MB | 15.5 MB | 23.2 MB |
| 99,540 `{}` and 199,000 such members (both limits) | 6.7 MB | 6.7 MB | 22.0 MB | 37.8 MB |
| The same with one two-byte character, padded to 16 MiB | 16.8 MB | 33.6 MB | 22.1 MB | |

The text is a JavaScript string: one byte per character, or two for the whole text once one character is above U+00FF, so 16 MiB of input can take 33.6 MB as text. The worst parse measured holds 55.7 MB in workerd (text and tree; 77 MB in Node). A caller that passes bytes also holds the bytes, up to 16.8 MB: about 73 MB in all, 57% of a Worker. The reader's state and result come on top and stay small. Peaks of whole reads in Node, found by shrinking a worker thread's heap cap until the read fails, are upper bounds for workerd: 35 MB for one osv-scanner package with a 512-character name and 50,000 advisories, 49 MB for 50,000 Trivy matches linked to one such package, 55 MB for 20,000 Trivy packages with a match each, and 33 MB for 5,000 gitleaks findings with 1,000-character paths.

`test/memory.test.ts` keeps these bounds in CI: the tree of every input above stays below 48 MB in Node, and the worst parse and the two match cases run in a worker thread with a capped heap (96 MB and 64 MB).

## Masking

The reader never returns or keeps a raw secret:

1. gitleaks: `Secret` is read once, inside the loop over findings, to see whether it starts with a known prefix (`cfat_`, `cfut_`, `cfk_`, followed by at least one character). `Match` and `Line` are never read. Trivy: no member that holds the secret is read; Trivy masks them by default, but Virga does not rely on that.
2. What leaves is the rule ID, the file, the lines, the prefix and `masked`: the prefix followed by `********`. The prefix is Virga's own constant, not a slice of the input. The mask is the same for every secret, whatever its length.
3. No hash of the secret is kept. A hash of a weak or short secret can be guessed, which would turn the finding store into a secret store.
4. Two guards keep a secret from leaving through another field, both with `secret_in_kept_field`. Any kept string in any reader that contains a Cloudflare token shape (a prefix and 40 or more token characters) is rejected. A gitleaks finding whose file or rule ID holds a piece of its own secret is rejected; see [the piece rule](#the-piece-rule). A secret of one finding inside the file name of another is not searched for; file names are account metadata, not scanner classifications.

Trivy findings therefore have `prefix: null`; the kind is the rule ID. A Virga-supplied Trivy rule for Cloudflare tokens would need a rule-ID-to-prefix map, which does not exist yet. A prefix links a finding to the token inventory by kind only: without the value or a hash, it cannot name the token.

`test/masking.test.ts` seeds dummy secrets (built at run time, so no token-shaped literal sits in the repository) into every member that holds a secret. It checks that no six-character piece of any secret body appears in a result, nor in the message, stack, own properties or string form of any rejection, for eleven kinds of broken report.

### The piece rule

The search runs on the secret's body: the secret without its known prefix, and without PEM armor (`-----BEGIN RSA PRIVATE KEY-----` and the `END` line), which gitleaks keeps in the secret of a private key. The armor names the kind of key and is no secret; left in, a key in `PRIVATE_KEY.pem` would reject its own report. A kept field holds a piece of the body when it contains:

- six consecutive characters of it, when the body has six or more. Six is the measure the masking test uses for a leak. Until round 10 only the whole body was searched, so a file with 23 of the 24 characters of its secret passed (R9 hardening).
- all of it, when the body has four or five characters.

A body under four characters is not searched: it would match ordinary paths, and three characters are no secret worth a gap in the report. Neither is `REDACTED`, which gitleaks writes with `--redact`. The search is linear in both lengths: a rolling hash over the pieces of the shorter text finds candidates in the longer one, and a candidate counts only when the piece itself matches. Nothing of the secret outlives the check. 60 findings with 250,000-character secrets and 1,000-character paths are read in about 0.6 s in Node.

What the rule does not catch: a file that spreads the secret in runs of five characters or fewer between other characters. The guard is for files and rules named after a secret, by accident or by a tool; a workload that hides its own secret on purpose has the secret already. A file that shares six characters with its own secret by chance is rejected, which turns the report into a gap; for random secrets that is rare.

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

Strings from the scanned account (script name, package names and versions) are values in the JSON document and nothing else; `JSON.stringify` escapes them, and nothing is concatenated into JSON text. The generator refuses input that is not clean text (control characters, lone surrogates, invisible characters including bidi controls), an invalid purl, an unknown source or confidence, a version ID that is not an ID, or a time outside years 1970 to 9999. Its errors name the field, never the value.

`checkSbom` is a structural self-check of what the generator emits, and the generator runs it on every document. It checks the members above and nothing else (stricter than the schema where Virga is: no other members, `bom-ref` equal to the purl, both properties present, components sorted, `bom-ref` unique). It is not schema validation.

**Schema validation (gate 2, [decision 0010](../decisions/0010-cyclonedx-schema-validation.md)).** The tests validate the stored form of every SBOM they build against the official CycloneDX 1.6 JSON schema: `bom-1.6.schema.json` with `spdx.schema.json` and `jsf-0.82.schema.json`, vendored unchanged from tag `1.6.2` of the CycloneDX specification repository in [`test/schema/cyclonedx-1.6`](../../packages/scanner-io/test/schema/cyclonedx-1.6/README.md), which records the source, the hashes and the license. The validator is `@cfworker/json-schema` 4.1.1, a dev dependency of this package only, with no dependencies of its own. `test/sbom.test.ts` validates each SBOM it builds; `test/sbom-schema.test.ts` checks the vendored files by size and SHA-256, that every `$ref` resolves and every format is covered, that the validator rejects documents the schema forbids (as a check that it runs), and validates SBOMs with hostile names, versions, script names and purls.

The validator does not implement two formats the schema uses, `iri-reference` (18 uses) and `idn-email` (2 uses), and it passes formats it does not know. The tests put a function under each name that records the hit and fails the value, so a document that reaches either one fails its test. A test also fails if the validator brings its own entry for either name, or if the schema uses any other format it lacks. The SBOMs carry no URL and no e-mail address, so they reach neither. The guard lives in the test code; nothing in `src/` touches the validator.

## Not done yet

- **The scanner container** (Trivy, osv-scanner, gitleaks unmodified, no internet, outbound handlers): waits for S-07. The tool versions above must be pinned there by digest, and the samples replaced with captured output from exactly those versions.
- **Storing SBOMs in R2**: bucket layout, object keys and lifecycle are not decided.
- **Writing results to the graph**: `package` nodes, `CONTAINS` edges with `source: "sbom"` for container images, `vulns` rows and secret findings. The `vulns` table has `severity_rank NOT NULL`, so a writer must decide how to store an unknown severity without reporting it as "none".
- **Linking secret findings to the token inventory**, and a rule-ID-to-prefix map for Trivy.
- **purls for ecosystems other than npm** from osv-scanner, and matching purls written by different tools (Trivy and a future `package_dependencies` collector may encode the same package differently).
