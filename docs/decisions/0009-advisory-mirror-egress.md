# 0009: Advisory data comes in bulk from two fixed hosts

- Status: accepted; the download format is confirmed by a spike when an account exists
- Date: 2026-10-30
- Changes: Virga's outbound traffic, the [deployment topology](../implementation-plan.md#deployment-topology-proposal)

## Context

Vulnerability matching needs OSV advisories for npm and the CISA Known Exploited Vulnerabilities catalog. Both come from outside Cloudflare. Until now Virga's only outbound calls go to the Cloudflare API, through the broker's read allowlist. Asking a query API such as `api.osv.dev` per package would send the package names and versions of the scanned accounts to a third party.

## Decision

- Virga downloads advisory data in bulk. It never sends anything from a scanned account to a third party: no package names, versions, account IDs or other data.
- Sources: OSV's public data bucket for the npm ecosystem (`osv-vulnerabilities.storage.googleapis.com`) and the KEV catalog JSON (`www.cisa.gov`). `GET` only, no credentials, no cookies.
- A dedicated mirror Worker syncs them on a schedule and writes them to an R2 bucket. Its code refuses every other host, like the broker's allowlist. It has no binding to the broker, no token, and no access to the graph.
- Core reads the mirror from R2. Everything in it is untrusted and goes through the strict readers of `packages/vulns`.
- A failed, partial or stale sync (older than 48 hours) makes the feed incomplete. Then `vulns` is not complete and CF-001 is `not evaluated`.
- Whether the sync reads one bulk archive or single records with an index is settled by a spike once an account exists. Until then the readers work on local files.

## Consequences

- A new Worker and an R2 bucket in the topology; the deploy script's checks must allow them.
- The operator guide lists the two hosts, so that an egress policy can allow exactly them.
- The mirror sees nothing from the scanned accounts, so a compromised mirror can feed false data but cannot leak any.
