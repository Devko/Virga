# 0001: Working defaults for the open decisions

- Status: accepted
- Date: 2026-10-29

## Context

[analysis.md](../analysis.md#open-decisions) lists fifteen open decisions (D-01 to D-15), each with a recommendation. Implementation starts now, before every decision has been discussed in depth.

## Decision

All fifteen recommendations are accepted as working defaults. A default stands until a later record replaces it. The record that changes a default names the decision ID it replaces.

| ID | Default |
| --- | --- |
| D-01 | Name "Virga" with a non-affiliation notice in README, UI footer and docs; no Cloudflare logos |
| D-02 | TypeScript strict, pnpm workspaces, Wrangler 4, Vitest with `@cloudflare/vitest-pool-workers`, Biome, Zod |
| D-03 | One directory per rule: `rule.sql` with front matter, `fixtures/`, `fix/` |
| D-04 | Findings, vulnerabilities and insights as tables, `finding_nodes` instead of `AFFECTS` |
| D-05 | `seen_scan` written on every observed row; hash gate for content and history |
| D-06 | Three Workers: broker, core, web (UI, API and MCP together) |
| D-07 | Small SPA as static assets: React, Vite, a graph library such as Cytoscape.js |
| D-08 | Separate D1 database for the vault, bound only to the broker |
| D-09 | Daily full scan plus event-driven updates; hourly opt-in for small accounts |
| D-10 | One finding per subject with evidence lists; suppression expires and ends early when severity rises |
| D-11 | Phase 1 rules: CF-002, CF-003, CF-004, CF-007, CF-009, CF-010 (Access part), CF-011 (public part), CF-021, CF-022, CF-024 |
| D-12 | Own thin read-only Cloudflare API client with Zod schemas for the fields used |
| D-13 | Severity modifiers in a TypeScript step after the rule query, recorded in the evidence |
| D-14 | Inventory token: Workers Metadata Read-Only, Pages Metadata Read, product Metadata Read-Only for D1, KV and R2 where tokens offer it. Workload scan adds Workers Content Read-Only and Containers Read |
| D-15 | Master key in Secrets Store, with a documented fallback to a Worker secret on the broker |

## Consequences

The scaffold, the graph package and the rule compiler follow D-02 to D-05. The other defaults take effect when their part is built. A spike result that contradicts a default leads to a new record.

## Refinements made during implementation

These follow from building the graph package. They do not change any decision:

- Each node and edge carries a `class` column with the resource class of the collector that wrote it. The sweep uses it to tombstone only the rows of classes that are complete in the current scan (D-05).
- Edge IDs are deterministic strings (`<type>:<src>-><dst>#<key>`), not hashes. Content hashes stay SHA-256 over canonical JSON.
- `AFTER INSERT` and `AFTER UPDATE` triggers write `changes`, so every write path records history the same way.
