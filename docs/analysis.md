# Analysis of the design spec

Status: review of [design spec](concept/design-spec.md) of 2026-10-29, written the same day. The spec refers to a companion "Prüfbericht" tab that was not exported; this document is a new, independent review.

**Method**

1. Read the spec end to end and checked it for internal consistency.
2. Ran the flagship CF-001 query and a draft schema on SQLite 3.45 against a 10-case fixture (see [data-model.md](architecture/data-model.md#cf-001-revised)).
3. Checked the spec's external claims against the Cloudflare docs, API reference and changelogs on developers.cloudflare.com, read directly on 2026-10-29. "Confirmed" means the official page says so. The spikes in the [implementation plan](implementation-plan.md#phase-0-decisions-and-spikes) still test the items the design depends on in a real account, because documentation and behavior can differ.

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
| Workflows: 10,000 steps default, up to 25,000; 5 min CPU per step; 1 MiB step result | Confirmed | None |
| Workflow retention | Paid plan keeps instances up to 30 days. New paid Workflows since 2026-09-10 default to 7 days | Scan history must live in the graph, which it already does |
| Cron schedule on the Workflow binding | Confirmed (`schedules` on the binding, since 2026-06-02) | No `scheduled()` handler needed |
| Deterministic instance ID per hour rejects duplicates | Confirmed: error 10405 "An instance with this ID already exists" while the earlier instance is retained. IDs are at most 100 characters and must match `^[a-zA-Z0-9_][a-zA-Z0-9-_]*$` | Use IDs like `scan-<account>-<yyyymmddhh>`; no `:` or `.` |
| Durable Object SQLite up to 10 GB | Confirmed | Also relevant: 100 bound parameters per statement, 100 KB per statement, 2 MB per row or string, 30 s CPU per request by default (up to 5 min). Only positional `?` parameters; in a multi-statement `exec`, bindings apply to the last statement only; transactions only through `transaction()`/`transactionSync()` |
| 1,200 API requests per 5 minutes, 5-minute block when exceeded | Confirmed ("per user/account token", cumulative across dashboard, API key and token); `Ratelimit` and `Ratelimit-Policy` headers on REST, `retry-after` on 429 | GraphQL has its own quota (300 queries per 5 minutes by default), and the Rulesets API has its own limits. The budget object has to track them separately |
| Audit Logs v2: API, 18 months, ~95 % of products, `view` actions since 2026-10-13 | Confirmed. `since` and `before` are required parameters. `actor_token_id` and `action_type` accept `not` filters on the account endpoint. Cloudflare warns that `view` actions can be high volume | Filter the tool's own events on the server. Scans fill the customer's audit log with `view` entries, so the onboarding docs must say so. A Resource History API returns earlier changes per resource and can enrich detection findings |
| Version field `package_dependencies` | Confirmed on the Version model of the Workers API (beta): `{name, packageJsonVersion, installedVersion}`, "npm packages that were installed and used when this Worker version was built". Wrangler collects it from `package.json` on `deploy` and `versions upload`; opt-out with `dependencies_instrumentation.enabled = false` | The official docs do not name the Wrangler version (4.110). Wrangler's source (S-04) shows that it merges dependencies and devDependencies, lists direct dependencies only, and stops at 200 entries. No flag separates dev from production dependencies (A-11) |
| Source maps uploaded by default since Wrangler 4.150 | Confirmed (`deploy`, `versions upload`, `preview`; unresolvable maps are skipped). The new `cf deploy` uploads them too | Good fallback for transitive packages; `include=modules` returns "code and sourcemap content". Workers deployed with older Wrangler versions often have none |
| Versions API (beta) with `include=modules` | Confirmed; the endpoint still sits under `workers.beta` and the response "may add several megabytes" | Plan for beta churn and large responses |
| `workersInvocationsAdaptive` per script | Confirmed; up to one month per query, data up to three months back | One 30-day query fits |
| Containers: no internet, outbound handlers inject credentials | Confirmed (`enableInternet = false`, `allowedHosts` deny-by-default, `outbound`/`outboundByHost` handlers, `interceptHttps`; only ports 80 and 443) | Design works as described. Largest instance: 4 vCPU, 12 GiB, 20 GB disk, which limits the size of images that can be scanned |
| Registry credentials API permission undocumented | Still undocumented: the API page lists no accepted permissions. The request takes `permissions: pull, push, list` for managed registries | Spike S-07, as the spec already says |
| Worker-level Access covers routes, Custom Domains, `workers.dev`, previews | Confirmed | Worker-level Access does not support WebSockets (upgrade requests get 403). `ctx.access` gives the Worker the authenticated identity without JWT parsing (spike S-08) |
| Host and path Access apps take precedence over Worker-level Access | Confirmed: hostname or path apps apply first, then Worker-level, then account-level | CF-002 as written is correct |
| Secrets Store for the master key | Exists, still in open beta | The master key depends on a beta product. Decision D-15 |
| `ctx.access` in a Worker with Static Assets | Not available: an internal router Worker sits in front and does not pass it on, and it does not cross service bindings or RPC (found in round 2 by the web work package) | The web Worker verifies the Access JWT itself; S-08 confirms on a real account |
| `createMcpHandler` | Confirmed; imported from `agents/mcp/server`, stateless, built on MCP SDK v2; `McpAgent` is deprecated | Pin versions; expect churn |
| Account tokens: unsupported services | Confirmed: Intel Data Platform, Page Rules, Registrar, Super Bot Fight Mode, Turnstile, Zero Trust Client Platform | Collectors for these report `no_permission`, as the spec says. Zero Trust Client Platform matters for device profiles (CF-018) |
| Onboarding: `tokens/verify` returns the ID, token detail returns permission groups | Confirmed; reading the token detail accepts Account API Tokens Read or Write | Fine: CF-003 needs that permission anyway. It also exposes the metadata of every account token, which belongs in the threat model |
| `cfat_` and `cfut_` token prefixes | Confirmed, plus `cfk_` for the Global API Key | Add `cfk_` to the secret patterns |
| "Inventory" profile with metadata permissions only | Workers Scripts Read is now mapped to Content Read-Only and reads code. **Metadata Read-Only (2026-09-15) reads Workers metadata, settings and observability, but no code and no secret values.** Developer Platform roles define Metadata Read-Only for all products ("cannot view product content such as code, data, or stored objects"). Tokens get product-level roles "where available". The token permission reference still lists only D1 Read, Workers KV Storage Read and Workers R2 Storage Read for those products. Pages has Pages Metadata Read for tokens | Decision D-14. Spike S-05 checks which product-level Metadata Read-Only roles an account token can actually select |
| Cloudflare Mesh (formerly WARP Connector), hostname routes API | Confirmed; the API still calls Mesh nodes `warp_connector` | The routes removed on 2026-10-05 are the CIDR-encoded write endpoints, which Virga never calls. What matters: tunnel and Mesh list/get responses no longer contain `connections`. Connection state needs the dedicated connections endpoint |
| Dependency vulnerability alerting announced; Vulnerability Discovery by invitation | The Wrangler changelog names vulnerability alerting as a future feature. Vulnerability Discovery and Remediation (blog, 2026-09-03) is confirmed: invitation-only, early access through Managed Defense | Positioning holds |
| Access log retention 24 h to 180 days by plan | Confirmed. Device posture logs are kept 30 days on every plan | CF-020 (90 days) needs Logpush or Enterprise, as the spec says. CF-016 sees at most 30 days of posture history without Logpush |

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
- **A-11: The dependency metadata is weaker than it reads.** `package_dependencies` lists name, declared range and installed version from `package.json`. Wrangler's source shows that it merges dependencies and devDependencies without marking which is which, lists direct dependencies only and stops at 200 entries ([S-04](spikes/S-04-worker-dependencies.md)). The customer can also switch it off. Recommendation: a package listed only in `package_dependencies` gets low confidence. It rises to medium or high when the bundle or source maps show it. Otherwise a vulnerable test tool in devDependencies would trigger CF-001.
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
| D-14 | Token profiles | Inventory: Workers Metadata Read-Only, Pages Metadata Read, and Metadata Read-Only for D1, KV and R2 where account tokens offer it (S-05); otherwise no D1 or KV access and names come from bindings. Workload scan: adds Workers Content Read-Only and Containers Read. D1 Read and KV Read stay optional and are labelled as reaching data |
| D-15 | Master key storage | Secrets Store (beta) as the default, with a documented fallback to a Worker secret on the broker |
