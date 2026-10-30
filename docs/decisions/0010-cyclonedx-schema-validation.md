# 0010: SBOMs are validated against the vendored CycloneDX schema in tests

- Status: accepted
- Date: 2026-10-30
- Changes: phase 2 gate 2 ("SBOMs validate against the CycloneDX schema")

## Context

`packages/scanner-io` builds CycloneDX 1.6 JSON SBOMs and checks their structure itself. Gate 2 needs validation against the official schema. The schema files and a validator are not in the repository.

## Decision

- Vendor the CycloneDX 1.6 JSON schema (`bom-1.6.schema.json` and the schemas it references, `spdx.schema.json` and `jsf-0.82.schema.json`) unchanged from a tagged release of the CycloneDX specification repository. A README next to them records the source URL, the tag and each file's sha256. They are test inputs.
- Validate with `@cfworker/json-schema` as a dev dependency of `packages/scanner-io` only, pinned to an exact version that is at least 14 days old. It has no dependencies of its own, so it adds nothing else to the lockfile, and it runs in Workers if validation is ever needed at run time.
- The tests validate every SBOM the generator's tests build, including hostile names and versions. If the validator cannot handle a schema feature, the test fails; it never skips.

## Consequences

- One new dev dependency, under the release-age rule. If it turns out to pull in other packages, it is not added and this decision is revisited.
- The schema is refreshed by hand when Virga moves to a newer CycloneDX version.
