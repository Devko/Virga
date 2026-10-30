# Data model

Status: implemented in [`packages/graph`](../../packages/graph). The schema is [`packages/graph/src/schema.ts`](../../packages/graph/src/schema.ts). It runs on Durable Object SQLite in workerd and on Node's SQLite, both in CI; see spike [S-03](../spikes/S-03-durable-object-sqlite.md). It started from the [design spec](../concept/design-spec.md#data-model-the-security-graph) and the review in [analysis.md](../analysis.md).

## Conventions

- **One database per scanned account.** Each Durable Object holds exactly one account, so no table has an account column.
- **Node IDs** are `<type>:<native_id>`. `native_id` is the Cloudflare ID where one exists. Otherwise it is a stable natural key: bucket name, hostname, or a purl for packages. `name` holds the display value (route pattern, hostname) because some native IDs mean nothing to a reader.
- **Edge IDs** are deterministic strings: `<type>:<src>-><dst>#<key>`. `key` tells parallel edges apart, for example two bindings with different names to the same KV namespace.
- **Resource class.** Every node and edge records the class of the collector that wrote it (`workers`, `dns`, `access`, …). The sweep works per class.
- **Times** are Unix epoch milliseconds (integers).
- **`props`** is a JSON object, canonicalized (sorted keys) before hashing with SHA-256. Volatile values go into `signals` instead (see below).
- **Confidence** is an ordinal integer: 0 low, 1 medium, 2 high. Rules compare and aggregate it (`min`, `>=`). Text values would sort `high < low < medium`.
- **Severity rank** for vulnerabilities: 0 none, 1 low, 2 medium, 3 high, 4 critical.
- **Input limits** for strings from scanned accounts: native ID 512 characters, name 1,024, `props` 64 KB per row.

## Tables

| Table | Purpose |
| --- | --- |
| `meta` | Schema version, current scan, settings |
| `scans` | One row per scan (Workflow instance), with kind and status |
| `coverage` | Status per resource class and scan: `complete`, `partial`, `no_permission`, `error`, `skipped`. Decides tombstones and "not evaluated" |
| `nodes`, `edges` | The graph. Resource class, content hash, `first_seen`, `changed_at`, `seen_scan`, tombstone `deleted_at` |
| `signals` | Volatile values per node (traffic, token last use, last login). Updated in place, not hashed, no history |
| `changes` | Attribute history (before/after per changed node or edge), written by triggers. Diff between any two scans |
| `dirty` | Nodes marked by audit events and waiting for a targeted refetch |
| `exposure` | Output of the exposure evaluator per entry point and path prefix |
| `vulns` | Advisory matches per package node |
| `insights` | Native Security Insights as inputs that findings can enrich |
| `findings`, `finding_nodes` | Rule hits with lifecycle, and the nodes each finding is about (replaces the `AFFECTS` edge) |
| `rule_runs` | Per scan and rule: `evaluated`, `not_evaluated` (with missing coverage), `error` |
| `events` | Relevant Audit Logs v2 events, idempotent by audit log ID, for detection rules |

The schema has no foreign key constraints. The write path keeps references consistent, and the sweep tombstones edges whose nodes disappear.

### Deviations from the spec, and why

1. **`vulns`, `insights` and `findings` are tables, not `Finding` nodes.** The spec's CF-001 query already reads from a `vulns` table, while the node type list has `Finding` nodes with `AFFECTS` edges. Tables keep the tombstone sweep simple, because findings are derived and not observed. They also give findings a lifecycle of their own. `finding_nodes` replaces `AFFECTS`. (D-04)
2. **`signals` table.** The spec puts traffic on the Worker node (`traffic_7d` in flow C, `invocations_30d` in CF-001). Counters change on every scan. In `props`, they would change the hash, rewrite the node and add a history row each time, which defeats the hash-gated writes. Token `last_used_on` and login timestamps have the same problem.
3. **`seen_scan` instead of `observed_at`.** The spec writes a row "only when its hash changes", but also needs to know which rows a scan saw so it can sweep deletions. Both cannot hold at once. Every observed row gets `seen_scan`; the hash gate applies to `props`, `changed_at` and history (D-05). S-03 measured 3.7 rows written per graph row for an unchanged rescan. That is affordable at the daily default and expensive at hourly cadence. The spike report proposes recording the IDs seen in one row per batch instead.

## Node types

Type keys used by collectors, rules and fixtures. The registry is `NODE_TYPES` in [`types.ts`](../../packages/graph/src/types.ts); the write path rejects unknown types.

| Group | Type keys |
| --- | --- |
| Context | `account`, `zone`, `dns_record` |
| Entry point | `worker_route`, `worker_custom_domain`, `workers_dev`, `worker_preview_url`, `r2_public_domain`, `tunnel_hostname`, `pages_domain`, `pages_preview`, `spectrum_app` |
| Edge control | `waf_ruleset`, `access_app`, `access_policy`, `access_group`, `gateway_policy` |
| Workload | `worker_script`, `worker_version`, `pages_project`, `container_app`, `container_image` |
| Package | `package` (native ID is a purl, for example `pkg:npm/lodash@4.17.20`) |
| Data store | `r2_bucket`, `d1_database`, `kv_namespace`, `do_namespace`, `queue`, `hyperdrive_config`, `secrets_store_secret`, `vectorize_index` |
| Identity | `member`, `account_token`, `service_token`, `zt_user`, `idp_group`, `identity_provider`, `everyone` |
| Device | `device_profile`, `posture_rule` |
| Private network | `cidr_route`, `hostname_route`, `virtual_network`, `tunnel`, `mesh_node`, `infra_target` |

## Edge types

| Type | From → to | `key` | Notable `props` |
| --- | --- | --- | --- |
| `ROUTES_TO` | entry point → Worker script, Worker version, bucket, tunnel target | | `path` |
| `PROTECTED_BY` | entry point or Worker → Access app or ruleset | | `level` (`host`, `path`, `worker`) |
| `BINDS` | Worker version → data store, container, Worker | binding name | `binding_type` |
| `DEPLOYS` | Worker script → version | | `percentage` |
| `CONTAINS` | Worker version or image → package | | `confidence`, `source` (`package_dependencies`, `sourcemap`, `banner`, `sbom`) |
| `RUNS` | container app → image | | `digest` |
| `EGRESS` | container app → host or `internet` | | |
| `CAN` | identity → resource | permission group | `scope` |
| `SELECTS` | policy → group, IdP, service token, `everyone` | `include`, `require`, `exclude` | |
| `ALLOWS` | policy → app or private network | | `conditions` |
| `REQUIRES` | policy → posture check | | |
| `PRECEDES` | policy → policy | | `order` |
| `ROUTES`, `IN` | tunnel or Mesh node → private network → virtual network | | |
| `INCLUDES`, `EXCLUDES` | device profile → CIDR or domain | | |

Every Worker version carries `script_node_id` in its props, because a preview URL can point to a version that no deployment references.

## Write path

1. A collector step normalizes one chunk into a `Batch` (one scan, one resource class) and calls the account object.
2. `prepareBatch` validates types and sizes and computes IDs and hashes. It is async because Web Crypto is.
3. `applyBatch` writes in one `transactionSync()`. A row is inserted if new. If the hash differs, `props`, `name`, `hash` and `changed_at` are updated. `seen_scan` is always set. A tombstoned row that reappears is restored.
4. Triggers write `changes`: `create` on insert, then `update`, `delete` or `restore` when the hash or the tombstone changes.
5. After all chunks of a class succeed, the class is marked `complete` in `coverage`.
6. `sweep` tombstones rows of that class whose `seen_scan` is not the current scan, plus edges to nodes it tombstones. It does nothing unless coverage is `complete`.
7. Audit events never write state. They insert into `dirty`. A targeted refetch drains it through the same path.

Durable Object SQL limits shape the batch API. A statement takes at most 100 bound parameters, and only positional `?` is documented. A batch is therefore one JSON string parameter (kept below 1.5 MB; the limit is 2 MB), expanded with `json_each`. Larger batches are split into several statements in the same transaction. `BEGIN` and `COMMIT` through `exec` are rejected.

## Exposure

The TypeScript evaluator writes one row per entry point and path prefix with `replaceExposure`.

| Decision | Meaning |
| --- | --- |
| `public` | Reachable from the internet without identity |
| `access` | Access app with identity policies in front |
| `service_auth` | Only service tokens or mTLS |
| `private` | Reachable only through Zero Trust private routing |
| `blocked` | A block decision applies to all traffic (WAF block-all, Access block) |
| `unknown` | The evaluator could not decide (unsupported expression, missing coverage). Never treated as `public` |

`reason_id` points to the deciding node (Access app, policy, ruleset), and `reason` is a short explanation for the UI.

## Findings lifecycle

Implemented in [`packages/rules/src/evaluate.ts`](../../packages/rules/src/evaluate.ts); its doc comment is the detailed reference.

- One row per fingerprint. Rules choose the fingerprint granularity: CF-001 uses one per Worker, so a new CVE updates the finding and does not open a second one (D-10).
- `open` → `resolved` only when the rule ran with status `evaluated` and no longer returns the fingerprint, decided or undecided. A rule that is `not_evaluated` never resolves anything.
- A finding that comes back after `resolved` is reopened with its history intact.
- Suppression always has `suppressed_until`, a reason and the actor. It expires on its own. While it lasts, the accepted severity is kept and a higher severity ends it.
- A rule whose query fails or breaks the output contract is `error` for that run and changes no finding; the rules after it still run.
- Unknown is a result. A row with `decided = 0` says the rule cannot decide that fingerprint, for example because the entry points that decide it have exposure `unknown`. It neither opens nor resolves: an existing finding keeps its status, severity, evidence, node links and `last_seen` (an open, suppressed or resolved finding stays so; an expired suppression waits for the next decided row), and without a finding nothing opens. Before round 2, such a finding was resolved as soon as its exposure turned `unknown`.
- `rule_runs.hits` counts decided rows only; the run summary reports undecided rows apart (`undecided`). `rule_runs` has no column for them yet.
- Changing the rule version keeps the fingerprints unless the rule's meaning changes. In that case the rule gets a new ID.

## Rule files

```
rules/
  CF-001/
    rule.sql           # front matter + one SELECT/WITH statement
    fixtures/
      positive-*.yaml  # graph scenario -> expected fingerprints and severities
      negative-*.yaml  # graph scenario -> no rows at all
      undecided-*.yaml # graph scenario -> at least one undecided row
    fix/
      README.md        # fix proposals; Wrangler and Terraform templates in phase 4
```

Front matter at the top of `rule.sql`, parsed as YAML:

```sql
-- ---
-- id: CF-001
-- version: 2
-- title: Public Worker with an exploitable critical vulnerability and access to data
-- severity: critical
-- kind: toxic                 # posture | toxic | detection
-- requires: [workers, packages, vulns, storage, exposure, access]
-- params:
--   sev_min: 4
--   min_conf: 1
-- enriches: null              # Security Insight type, if any
-- ---
```

Output contract: each row has `rule_id`, `fingerprint` (starting with `<rule_id>:`), `severity` and `subject_id` (the node the finding is about), an optional `decided` (1 by default; 0 for an undecided row), plus evidence columns. An undecided row meets the same contract and its fingerprint is unique in the result too, so a rule that decides a subject on one path and cannot on another returns one decided row. List-valued evidence uses `json_group_array(DISTINCT …)`, not `group_concat`, because hostnames and names can contain commas. Evidence lists are capped at 100 items and strings at 2,048 characters. Every node ID in an evidence list also lands in `finding_nodes`, with the column name as the role. Rules that depend on time read the `now_ms` parameter (the scan start).

Rules that read `exposure` require `exposure` and `access`. Where the entry points that decide such a rule have exposure `unknown`, and the rule would qualify if they were `public` (or, for CF-009, if they were not), the rule returns an undecided row instead of none; one entry point that decides the subject makes the row decided, with only the deciding entry points as evidence. CF-001, CF-002, CF-004, CF-009, CF-021 and CF-022 do this since version 2.

A fixture describes nodes (`type`, native `id`, `name`, `props`), edges (`type`, `src`, `dst`, `key`, `props`, optional `deleted`), `exposure`, `vulns` (severity by name, `kev`), `signals` and the `expect` list. An `expect` entry has a `fingerprint`, an optional `severity`, and `decided: false` for an undecided row, which takes no severity; the fixture fails when a row's decided state differs from its entry. Fixtures load through the regular write path, so every fixture also exercises the batch upsert.

`pnpm rules:build`, implemented in [`packages/rules`](../../packages/rules):

1. parses and validates the front matter (unknown keys fail)
2. replaces `:name` parameters with positional `?` and an ordered binding list, and rejects positional `?`, a second statement, and parameters that are undeclared or unused
3. prepares the statement against the current schema in Node SQLite and checks the required output columns
4. requires at least one positive and one negative fixture, and runs all of them
5. rejects `requires` entries that are neither a resource class nor a derived input (`exposure`, `packages`, `vulns`)
6. writes `rules.gen.ts` and `fixtures.gen.ts`

`pnpm rules:check` does the same and fails if the generated files are stale. The core Worker's tests run every fixture again in Durable Object SQLite, because it allows fewer SQL functions than Node does. The tests in `packages/rules` run every fixture through the findings lifecycle (an undecided row must leave a seeded open finding unchanged), check the fixture name prefixes above, and require a fixture with an undecided row for every rule that requires `exposure`.

## CF-001, revised

The rule is [`rules/CF-001/rule.sql`](../../rules/CF-001/rule.sql). Compared with the spec's query:

1. **False positive through a service binding.** The hop into a bound Worker did not filter on deployment percentage. A 0 % version of the bound Worker with a KV binding made a public Worker qualify. The first hop already filtered on it. The fixture `negative-service-binding-to-idle-version` covers it, and a mutation test in `packages/rules` checks that this fixture catches the original query.
2. **Entry points showed route IDs.** `n.native_id AS host` returns the route ID for routes. The revised query uses `COALESCE(n.name, n.native_id)`.
3. **Ambiguous lists.** `group_concat` changed to `json_group_array(DISTINCT …)`.
4. **Traffic from `signals`**, not from node props (see above).
5. **Alias collision.** `store_types(t)` shared its name with the table alias `t`. It worked, but it was confusing; renamed to `store_type`.
6. **Unknown entry points** (version 2). A Worker that only entry points with exposure `unknown` serve would qualify if one were public, so it returns an undecided row. The fixture `undecided-unknown-entry-point` covers it.

Not in the query: the spec's "a matching WAF virtual patch lowers one level". That needs WAF rule-to-CVE matching. It belongs in a severity modifier step after the query (D-13).
