# CycloneDX 1.6 JSON schema

Test input for the SBOM generator ([decision 0010](../../../../../docs/decisions/0010-cyclonedx-schema-validation.md)): `test/sbom.test.ts` and `test/sbom-schema.test.ts` validate every SBOM the tests build against these files with `@cfworker/json-schema`. The files are data. Nothing here is run, and nothing in `src/` reads them.

## Source

- Repository: <https://github.com/CycloneDX/specification>
- Tag: `1.6.2`, which pointed at commit `e833d732337dd33aceb45ff1991f896796f1e5e7` when the files were downloaded on 2026-10-30
- URL: `https://raw.githubusercontent.com/CycloneDX/specification/1.6.2/schema/<file>`
- License: Apache License 2.0, the license of the repository. `bom-1.6.schema.json` and `jsf-0.82.schema.json` say so in their `$comment`. `spdx.schema.json` lists the SPDX license identifiers of the SPDX License List (its `$comment`: `v1.0-3.24.0`).

| File | `$id` | Bytes | SHA-256 |
| --- | --- | --- | --- |
| `bom-1.6.schema.json` | `http://cyclonedx.org/schema/bom-1.6.schema.json` | 262,666 | `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d` |
| `spdx.schema.json` | `http://cyclonedx.org/schema/spdx.schema.json` | 14,830 | `c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6` |
| `jsf-0.82.schema.json` | `http://cyclonedx.org/schema/jsf-0.82.schema.json` | 8,058 | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |

The files are unchanged, CRLF line endings included. `test/sbom-schema.test.ts` checks each size and hash. `../biome.json` keeps Biome from formatting them.

`bom-1.6.schema.json` refers to the other two as `spdx.schema.json` and `jsf-0.82.schema.json#/definitions/signature`. The test loads all three by their `$id`, and it checks that every `$ref` resolves.

## Formats the validator does not check

`@cfworker/json-schema` 4.1.1 checks `date-time` (26 uses in `bom-1.6.schema.json`) and `uri` (1 use in `jsf-0.82.schema.json`). It does not implement two formats the schema uses, and it passes a format it does not know:

- `iri-reference`, 18 uses in `bom-1.6.schema.json`: `bomLinkDocumentType`, `bomLinkElementType`, the `url` of `organizationalEntity` (items), `swid`, `license`, `commit`, `diff`, `advisory` and `componentData.contents`, the `url` of `externalReference` (first branch of `anyOf`), `issue.source.url`, `issue.references` (items), `service.endpoints` (items), `serviceData.source` and `serviceData.destination` (items, first branch of `anyOf`), `releaseNotes.featuredImage` and `releaseNotes.socialImage`, and `declarations.evidence[].data[].contents.url`
- `idn-email`, 2 uses in `bom-1.6.schema.json`: `organizationalContact.email` and `identifiableAction.email`

The test code (`test/cdx-schema.ts`) puts a function under each of the two names in the validator's format table that records the hit and fails the value. A test fails when a document reaches either format, and a test fails when the validator already has an entry of its own for either name, so the guard cannot stop applying unseen after an upgrade. Another test fails when the schemas use any other format the validator does not implement. The SBOMs Virga writes carry no URL and no e-mail address, so they reach neither format.

## Refreshing

Replace the three files with the files of a newer 1.6.x tag, unchanged, and update this README and the hashes in `test/sbom-schema.test.ts`. A move to CycloneDX 1.7 is a new folder and a change to the generator.
