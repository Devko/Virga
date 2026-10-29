# Analysis of the design spec

Status: review of [design spec](concept/design-spec.md) of 2026-10-29, written the same day. The spec refers to a companion "Prüfbericht" tab that was not exported; this document is a new, independent review.

**Method**

1. Read the spec end to end and checked it for internal consistency.
2. Ran the flagship CF-001 query and a draft schema on SQLite 3.45 against a 10-case fixture (see [data-model.md](architecture/data-model.md#cf-001-revised)).
3. Checked 16 groups of external claims against Cloudflare documentation and changelogs. This environment could not fetch developers.cloudflare.com directly, so the checks rely on search results that quote official pages. Each item marked "confirmed" below was seen in such a quote. The spikes in the [implementation plan](implementation-plan.md#phase-0-decisions-and-spikes) confirm the items the design depends on before code relies on them.

## Summary

The design is sound and can be built from the building blocks it names. Its core idea holds up under review: a per-account graph in a Durable Object, rules as SQL over it, read-only collection through a broker, and everything running on Cloudflare. The platform claims mostly check out, and one recent change helps the design: a metadata-only Workers role now exists, which makes the "inventory" token profile possible.

What needs work before implementation:

1. **Scope.** v1 lists 24 rules, 12 components and 9 service domains. For a small team, the risk is a long build with nothing usable in between. The plan cuts it into four gated phases; phase 1 is configuration only.
2. **Data model.** It has three internal contradictions: findings as nodes vs. tables, where traffic lives, and write-on-change vs. sweep. All three are resolved in [data-model.md](architecture/data-model.md).
3. **Rules that need more than SQL.** CIDR math, code heuristics, time series and events need TypeScript evaluators that write derived tables. The SQL rules then read those tables.
4. **CF-001 query.** It runs and is mostly right, but has one false positive (a 0 % version behind a service binding) and shows route IDs instead of route patterns. Both are fixed in the revised query.

## Strengths

- **One clear center.** Every component either writes the account graph or reads it, which keeps the architecture explainable.
- **Honest uncertainty.** `unknown` is never `public`, a 403 is never a pass, and every finding carries a confidence. Customers can trust that.
- **Consume, don't rebuild.** The spec uses Security Insights, the Access policy tester and unmodified scanners instead of re-implementing them, so it can position itself next to native features rather than against them.
- **Security of the tool itself.** Broker isolation, envelope encryption, masked secrets and untrusted-string marking for MCP are present from the start.
- **Open formats.** OCSF, CycloneDX and rules as code make adoption and contribution easier.

## External claims checked

| Claim in the spec | Result | Consequence |
| --- | --- | --- |
| Workflows: 10,000 steps default, up to 25,000; 5 min CPU per step; 1 MiB step result | Confirmed (raised to 10,000/25,000 on 2026-03-03) | None. Instance retention for new paid Workflows is now 7 days by default, so scan history must live in the graph, which it already does |
| Cron schedule on the Workflow binding | Confirmed (`schedules` on the binding since 2026-06-02) | No `scheduled()` handler needed |
| Deterministic instance ID per hour rejects duplicates | Confirmed, while the earlier instance is retained. IDs are at most 100 characters; `:` and `.` are probably not allowed | Use IDs like `scan-<account>-<yyyymmddhh>` |
| Durable Object SQLite up to 10 GB | Confirmed | Also relevant: 100 bound parameters per statement, 100 KB per statement, 2 MB per row or string, 30 s CPU per request by default (up to 5 min). Only positional `?` parameters are documented |
| 1,200 API requests per 5 minutes, 5-minute block when exceeded | Confirmed ("per user/account token"); `Ratelimit` headers exist for REST | GraphQL has its own limit (300 queries per 5 minutes) and no `Ratelimit` header. The budget object has to track both |
| Audit Logs v2: API, 18 months, ~95 % of products, `view` actions since 2026-10-13 | Confirmed; Logpush dataset `audit_logs_v2` exists; filter `actor_token_id.not` exists | Filter the tool's own events on the server, not in the consumer. Scans fill the customer's audit log with `view` entries, so this has to be in the onboarding docs |
| Worker dependency metadata uploaded by Wrangler 4.110+ | Confirmed: name, declared range and installed version, for dependencies and devDependencies, capped at 200 entries, on by default with opt-out | The field name `package_dependencies` is not confirmed (spike S-04). Declared ranges point to direct dependencies only, so transitive packages likely need source maps. devDependencies are usually not in the bundle and must get low confidence |
| Source maps uploaded by default since Wrangler 4.150 | Confirmed | Good fallback for transitive packages |
| Versions API (beta) with `include=modules` | Endpoint seen in third-party sources only; beta status unclear | Spike S-04 |
| `workersInvocationsAdaptive` per script | Confirmed; up to one month per query, data up to three months back | One 30-day query fits. Read `maxDuration` from the `settings` node per account |
| Containers: no internet, outbound handlers inject credentials | Confirmed (`enableInternet = false`, `outboundByHost`, `allowedHosts`, HTTPS interception with a container CA) | Design works as described. Largest instance: 4 vCPU, 12 GiB, 20 GB disk, which limits the size of images that can be scanned |
| Registry credentials API permission undocumented | Still undocumented | Spike S-07, as the spec already says |
| Worker-level Access covers routes, Custom Domains, `workers.dev`, previews | Confirmed | None |
| Host and path Access apps take precedence over Worker-level Access | Not found in official docs, only in a third-party source | CF-002 depends on it. Test on a real account (S-08) |
| Secrets Store for the master key | Exists, still in open beta | The master key depends on a beta product. Decision D-15 |
| `createMcpHandler` | Confirmed; now imported from `agents/mcp/server`, built on MCP SDK v2 (beta); `McpAgent` is deprecated | Pin versions; expect churn |
| Account tokens: unsupported services | Partly confirmed (Super Bot Fight Mode, others from a third-party list) | Collector reports `no_permission`, as the spec says |
| Onboarding: `tokens/verify` returns the ID, token detail returns permission groups | Confirmed, but reading the token detail needs Account API Tokens Read | Fine: CF-003 needs that permission anyway. It also exposes the metadata of every account token, which belongs in the threat model |
| `cfat_` and `cfut_` token prefixes | Confirmed (plus `cfk_` for the Global API Key, with checksum) | Add `cfk_` to the secret patterns |
| "Inventory" profile with metadata permissions only | Contradicted for Workers Scripts Read, which downloads code. **A new role, Workers Metadata Read-Only (2026-09-15), fixes this.** D1 Read runs queries and KV Read returns values; there is no metadata-only role for them | Decision D-14 |
| Cloudflare Mesh (formerly WARP Connector), hostname routes API | Confirmed; the API still calls Mesh nodes `warp_connector` | Since 2026-10-05 the CIDR-encoded `teamnet` route endpoints are gone; use route ID paths |
| Dependency vulnerability alerting announced; Vulnerability Discovery by invitation | Alerting is mentioned as future only; Vulnerability Discovery (2026-09-03) is confirmed as invitation-only | Positioning holds |
| Access log retention 24 h to 180 days by plan | Confirmed | CF-020 (90 days) needs Logpush or Enterprise, as the spec says |

## Inconsistencies and gaps in the spec

**Data model**

- **A-01: Findings as nodes, or as tables?** The node type list has `Finding` nodes with `AFFECTS` edges, but CF-001 reads from a `vulns` table, and the spec says findings "live in their own table". Recommendation: `vulns`, `insights` and `findings` as tables, plus `finding_nodes` instead of `AFFECTS` (D-04).
- **A-02: Traffic attribute.** Flow C writes `traffic_7d`; CF-001 reads `invocations_30d`; CF-009 needs 30 days. Counters also change on every scan. In `props`, they would rewrite the node each time. Recommendation: a `signals` table for volatile values, with one name per window (`invocations_30d`).
- **A-03: Write on change vs. sweep.** "A row is written only when its hash changes" and "a completeness marker decides tombstones" do not fit together, because the sweep has to know what the current scan saw. Recommendation: write `seen_scan` on every observed row and keep the hash gate for content and history (D-05). The cost is one row write per resource per scan.
- **A-04: CF-001 query.** One false positive and two smaller issues; fixed and tested (see [data-model.md](architecture/data-model.md#cf-001-revised)).
- **A-05: Severity modifiers.** "A matching WAF virtual patch lowers one level" is not in the query, and there is no description of how WAF rules map to CVEs. Recommendation: a TypeScript modifier step after the query that records each applied modifier in the evidence (D-13).

**Rules**

- **A-06: Not every rule is one SQL statement.** These rules need inputs that SQL over raw nodes cannot compute well:
  - CIDR containment and route breadth: CF-007, CF-012, CF-014
  - code heuristics such as "recognizable authentication" and the MCP signature: CF-006
  - posture results and logins over time: CF-016, CF-019, CF-020
  - audit events: CF-023

  Recommendation: TypeScript evaluators write derived tables (`exposure`, `zt_access`, `cidr_relations`, code signals in `signals`). Rules stay single SQL statements over those tables, and the rule's `requires` field lists them.
- **A-07: Finding lifecycle on partial coverage.** The spec makes rules `not evaluated` when collectors lack permission, but it does not say what happens to open findings. Recommendation: only an `evaluated` rule run can resolve a finding.
- **A-08: Transitive exposure.** CF-001 covers Workers served by a public entry point and one service-binding hop to data. It misses a vulnerable internal Worker that only a public Worker calls, although that Worker processes public input. Recommendation: a later variant rule (CF-001b) once CF-001 is stable.
- **A-09: "Data store or secret".** `store_types` includes Secrets Store secrets but not plain Worker secrets (`secret_text` bindings). Decide whether those count. Including them would make almost every Worker qualify.

**Collection and limits**

- **A-10: Scan cadence vs. rate limit.** The deterministic instance ID "per hour" suggests hourly scans. The spec itself estimates 45 to 90 minutes for a full scan of 500 zones. Recommendation: daily full scans by default, event-driven updates in between, and hourly scans only for small accounts (D-09).
- **A-11: The dependency metadata is weaker than it reads.** It most likely covers direct dependencies only. It includes devDependencies, is capped at 200 entries, and the customer can switch it off. Confidence levels per source are needed: installed version of a production dependency = medium; transitive package from a source map = medium; devDependency = low.
- **A-12: The rule engine runs inside one Durable Object request.** A request gets 30 s of CPU by default. Recommendation: one RPC call per rule from a Workflow step, and `limits.cpu_ms` raised for the account object. Spike S-03 measures this on a synthetic graph.

**Operations and missing topics**

- **A-13: Missing topics.** These need a design before phase 1 ends:
  - offboarding and data deletion: graph object, R2 prefix, vault entry, index rows
  - schema migrations inside each account object
  - backup and point-in-time recovery
  - observability (scan metrics, errors) with tokens scrubbed from logs
  - a cost model per account size
  - an onboarding guide that walks the customer through creating the token
- **A-14: "Fix proposal as a Wrangler or Terraform diff".** The tool does not see the customer's infrastructure code, so it cannot produce a real diff. Recommendation: generate snippets and patch templates per rule, and call them that.
- **A-15: Roadmap and companion tabs missing.** The four phases in the [implementation plan](implementation-plan.md) are a proposal built around the spec's three anchors.

## Security review: additions

The spec's section on the tool's own security is strong. These additions close gaps:

1. **Read-only by construction in the broker.** The broker allows only an explicit list of methods and paths (GET, plus POST for GraphQL queries). A token with too many permissions that slips past the onboarding check can still do no harm.
2. **Envelope encryption details:**
   - a separate data key per token
   - account ID and token ID as associated data, so a ciphertext cannot be moved to another account
   - a key version on each record
   - a documented procedure for rotating the master key
3. **Separate D1 databases.** A D1 binding cannot be read-only, so the vault gets a database of its own, bound only to the broker.
4. **Token intake.** The web Worker has to accept a token during onboarding. A narrow `TokenIntake` entrypoint on the broker can store and verify a token but cannot use it. Logging of request bodies on that path is off.
5. **The deploy pipeline is the crown jewel.** Anyone who can deploy the broker can read every token. Recommendations:
   - deploy only through a protected CI environment with required reviewers
   - a deploy token that is short-lived and scoped to the tool account
   - signed commits on the release branch
6. **Account API Tokens Read** shows metadata of all account tokens. That is fine for CF-003, but it goes into the threat model and the onboarding text.
7. **Secret patterns:** add `cfk_` (Global API Key) to `cfat_` and `cfut_`.

## Risks

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Scope outgrows capacity; nothing usable for months | High | High | Gated phases, test range, phase 1 without containers |
| Exposure evaluator gets precedence wrong (false "not public") | Medium | High | `unknown` instead of guessing, table-driven tests from the docs, manual review sample at the phase 1 gate |
| Beta or new APIs change (Versions API, dependency metadata, MCP SDK v2, Secrets Store) | High | Medium | Adapters per source, version pinning, fallbacks (source maps, Worker secret) |
| Rate limits make large accounts slow | Medium | Medium | Daily cadence, event-driven updates, rotating zone details |
| Native Cloudflare features overlap (dependency alerting, Vulnerability Discovery) | Medium | Medium | Position as the correlation layer and consume native signals, as the spec says |
| The tool becomes the attack target | Medium | High | Broker isolation, read-only broker allowlist, separate vault database, protected deploy pipeline |
| Privacy objections (works council, GDPR) to Zero Trust usage analysis | Medium | Medium | Pseudonymization by default, usage analysis optional, a data protection impact assessment template in the operator docs |

## Open decisions

Each decision has a recommendation. When a decision is made, record it in `docs/decisions/` (one file per decision, ADR style).

| ID | Decision | Recommendation |
| --- | --- | --- |
| D-01 | Name and affiliation notice | Keep "Virga". Show a non-affiliation notice in the README, the UI footer and the docs; use no Cloudflare logos |
| D-02 | Toolchain | TypeScript strict, pnpm workspaces, Wrangler 4, Vitest with `@cloudflare/vitest-pool-workers`, Biome, Zod |
| D-03 | Rule file layout | One directory per rule: `rule.sql` with front matter, `fixtures/`, `fix/` |
| D-04 | Findings, vulnerabilities, insights | Tables, not nodes; `finding_nodes` instead of `AFFECTS` |
| D-05 | Sweep strategy | `seen_scan` written on every observed row; hash gate for content and history |
| D-06 | Number of Workers | Three: broker, core, web (UI, API and MCP together; same trust level) |
| D-07 | UI stack | Small SPA as static assets: React, Vite, and a graph library such as Cytoscape.js |
| D-08 | Vault database | Separate D1 database for the vault, bound only to the broker |
| D-09 | Default scan cadence | Daily full scan plus event-driven updates; hourly opt-in for small accounts |
| D-10 | Fingerprint granularity and suppression | One finding per subject (CF-001: per Worker) with evidence lists; suppression expires and ends early when severity rises |
| D-11 | Phase 1 rule set | CF-002, CF-003, CF-004, CF-007, CF-009, CF-010 (Access part), CF-011 (public part), CF-021, CF-022, CF-024 |
| D-12 | Cloudflare API client | Own thin read-only client with Zod schemas for the fields actually used, so the broker stays auditable; the official SDK is too broad for that role |
| D-13 | Severity modifiers | TypeScript step after the query; every modifier recorded in the evidence |
| D-14 | Token profiles | Inventory: Workers Metadata Read-Only, no D1 or KV data reads (names come from bindings). Workload scan: adds Workers Content Read-Only and Containers read. D1 and KV read optional and labelled as reaching data |
| D-15 | Master key storage | Secrets Store (beta) as the default, with a documented fallback to a Worker secret on the broker |
