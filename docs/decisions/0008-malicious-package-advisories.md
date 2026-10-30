# 0008: Malicious package advisories rank critical

- Status: accepted
- Date: 2026-10-30
- Changes: severity ranking in [vulnerability matching](../architecture/vulns.md)

## Context

`packages/vulns` ranks a match from a CVSS v3 vector, or from the GitHub severity when there is no vector. A match whose severity it cannot determine is unknown: it is not written, and `vulns` coverage is `partial`, so CF-001 is `not evaluated` for the whole account.

OSV records with IDs that start with `MAL-` come from the OpenSSF malicious packages database. They mark a package version as malware and carry no severity. Today one such match keeps CF-001 from running at all, and the malicious package itself never shows as a finding.

## Decision

A match on a record whose ID starts with `MAL-` gets severity rank 4 (critical), whatever its severity fields hold. The `kev` flag stays reserved for the CISA catalog.

## Consequences

- A malicious package in a Worker that a public entry point serves and that reaches data raises CF-001 as critical.
- A withdrawn `MAL-` record does not match, as for any other record.
- If OSV adds severity data to `MAL-` records later, this rule still wins; revisit it then.
