# Data model (draft v0)

Status: proposal. Built from the [design spec](../concept/design-spec.md#data-model-the-security-graph) and the review in [analysis.md](../analysis.md). The DDL in [schema-draft.sql](schema-draft.sql) and the revised CF-001 query below were run on SQLite 3.45 against a 10-case fixture. They have not yet run on Durable Object SQLite; spike S-03 in the [implementation plan](../implementation-plan.md) covers that.

## Conventions

- **One database per scanned account.** Each Durable Object holds exactly one account, so no table has an account column.
- **Node IDs** are `<type>:<native_id>`. `native_id` is the Cloudflare ID where one exists. Otherwise it is a stable natural key: bucket name, hostname, or a purl for packages. `name` holds the display value (route pattern, hostname) because some native IDs mean nothing to a reader.
- **Edge IDs** are a hash over `(src, type, dst, key)`. `key` disambiguates parallel edges, for example two bindings with different names to the same KV namespace.
- **Times** are Unix epoch milliseconds (integers).
- **`props`** is a JSON object, canonicalized (sorted keys) before hashing. Volatile values go into `signals` instead (see below).
- **Confidence** is an ordinal integer: 0 low, 1 medium, 2 high. Rules compare and aggregate it (`min`, `>=`). Text values would sort `high < low < medium`.
- **Severity rank** for vulnerabilities: 0 none, 1 low, 2 medium, 3 high, 4 critical.

## Tables

| Table | Purpose |
| --- | --- |
| `meta` | Schema version, account ID, settings |
| `scans` | One row per scan (Workflow instance), with kind and status |
| `coverage` | Status per resource class and scan: `complete`, `partial`, `no_permission`, `error`, `skipped`. Decides tombstones and "not evaluated" |
| `nodes`, `edges` | The graph. Content hash, `first_seen`, `changed_at`, `seen_scan`, tombstone `deleted_at` |
| `signals` | Volatile values per node (traffic, token last use, last login). Updated in place, not hashed, no history |
| `changes` | Attribute history (before/after per changed node or edge). Diff between any two scans |
| `dirty` | Nodes marked by audit events and waiting for a targeted refetch |
| `exposure` | Output of the exposure evaluator per entry point and path prefix |
| `vulns` | Advisory matches per package node |
| `insights` | Native Security Insights as inputs that findings can enrich |
| `findings`, `finding_nodes` | Rule hits with lifecycle, and the nodes each finding is about (replaces the `AFFECTS` edge) |
| `rule_runs` | Per scan and rule: `evaluated`, `not_evaluated` (with missing coverage), `error` |
| `events` | Relevant Audit Logs v2 events, idempotent by audit log ID, for detection rules |

The full DDL is in [schema-draft.sql](schema-draft.sql).

### Deviations from the spec, and why

1. **`vulns`, `insights` and `findings` are tables, not `Finding` nodes.** The spec's CF-001 query already reads from a `vulns` table, while the node type list has `Finding` nodes with `AFFECTS` edges. Tables keep the tombstone sweep simple, because findings are derived and not observed. They also give findings a lifecycle of their own. `finding_nodes` replaces `AFFECTS`. (Decision D-04)
2. **`signals` table.** The spec puts traffic on the Worker node (`traffic_7d` in flow C, `invocations_30d` in CF-001). Counters change on every scan. In `props`, they would change the hash, rewrite the node and add a history row each time, which defeats the hash-gated writes. Token `last_used_on` and login timestamps have the same problem.
3. **`seen_scan` instead of `observed_at`.** The spec writes a row "only when its hash changes", but also needs to know which rows a scan saw so it can sweep deletions. Both cannot hold at once. The draft writes `seen_scan` for every observed row (one row write per resource and scan) and keeps the hash gate for `props`, `changed_at` and `changes`. At 20,000 resources and 24 scans a day this is about 15 M row writes per month. (Decision D-05; check pricing in spike S-03)

## Node types

Type keys used by collectors, rules and fixtures. The list is the spec's table, made concrete. It grows with the collectors.

| Group | Type keys |
| --- | --- |
| Context | `account`, `zone`, `dns_record` |
| Entry point | `worker_route`, `worker_custom_domain`, `workers_dev`, `worker_preview_url`, `r2_public_domain`, `tunnel_hostname`, `pages_domain`, `pages_preview`, `spectrum_app` |
| Edge control | `waf_ruleset`, `access_app`, `access_policy`, `access_group`, `gateway_policy` |
| Workload | `worker_script`, `worker_version`, `pages_project`, `container_app`, `container_image` |
| Package | `package` (native ID is a purl, for example `pkg:npm/lodash@4.17.20`) |
| Data store | `r2_bucket`, `d1_database`, `kv_namespace`, `do_namespace`, `queue`, `hyperdrive_config`, `secrets_store_secret`, `vectorize_index` |
| Identity | `member`, `account_token`, `service_token`, `zt_user`, `idp_group`, `identity_provider` |
| Device | `device_profile`, `posture_rule` |
| Private network | `cidr_route`, `hostname_route`, `virtual_network`, `tunnel`, `mesh_node`, `infra_target` |

## Edge types

| Type | From → to | `key` | Notable `props` |
| --- | --- | --- | --- |
| `ROUTES_TO` | entry point → Worker script, Worker version, bucket, tunnel target | | `path` |
| `PROTECTED_BY` | entry point or Worker → Access app or ruleset | | `level` (`host`, `path`, `worker`) |
| `BINDS` | Worker version → data store, container, Worker | binding name | `binding_type` |
| `DEPLOYS` | Worker script → version | | `percentage` |
| `CONTAINS` | Worker version or image → package | | `confidence`, `source` (`wrangler_metadata`, `sourcemap`, `banner`, `sbom`) |
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

1. A collector step normalizes one chunk and calls the account object with a batch of nodes and edges.
2. Upsert per row: insert if new. If the hash differs, update `props`, `name`, `hash` and `changed_at` and write a `changes` row. Always set `seen_scan`. A tombstoned row that reappears is restored and logged as `restore`.
3. After all chunks of a resource class succeed, the class is marked `complete` in `coverage`.
4. The sweep tombstones rows of complete classes whose `seen_scan` is not the current scan. Classes that are not complete are not swept.
5. Audit events never write state. They insert into `dirty`. A targeted refetch drains it through the same upsert path.

Durable Object SQL limits shape the batch API. A statement takes at most 100 bound parameters, and only positional `?` is documented. A batch is therefore one JSON string parameter (at most 2 MB), expanded with `json_each`, and the whole batch runs in `transactionSync()`. `BEGIN` and `COMMIT` through `exec` are rejected. This pattern was tested on SQLite 3.45:

```sql
INSERT INTO nodes (id, type, native_id, name, props, hash, first_seen, changed_at, seen_scan)
SELECT j.value ->> '$.id', j.value ->> '$.type', j.value ->> '$.native_id', j.value ->> '$.name',
       json(j.value -> '$.props'), j.value ->> '$.hash', ?, ?, ?
FROM json_each(?) AS j WHERE true
ON CONFLICT (id) DO UPDATE SET
  seen_scan  = excluded.seen_scan,
  name       = CASE WHEN nodes.hash <> excluded.hash THEN excluded.name  ELSE nodes.name END,
  props      = CASE WHEN nodes.hash <> excluded.hash THEN excluded.props ELSE nodes.props END,
  changed_at = CASE WHEN nodes.hash <> excluded.hash OR nodes.deleted_at IS NOT NULL
                    THEN excluded.changed_at ELSE nodes.changed_at END,
  hash       = excluded.hash,
  deleted_at = NULL;
```

The `changes` rows come from an `AFTER UPDATE` trigger (`WHEN old.hash <> new.hash OR old.deleted_at IS NOT new.deleted_at`) or from an explicit statement before the upsert; spike S-03 decides.

## Exposure

The TypeScript evaluator writes one row per entry point and path prefix.

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

- One row per fingerprint. Rules choose the fingerprint granularity: CF-001 uses one per Worker, so a new CVE updates the finding and does not open a second one (Decision D-10).
- `open` → `resolved` only when the rule ran with status `evaluated` and no longer returns the fingerprint. A rule that is `not_evaluated` never resolves anything.
- A finding that comes back after `resolved` is reopened with its history intact.
- Suppression always has `suppressed_until`, a reason and the actor. It expires on its own.
- Changing the rule version keeps the fingerprints unless the rule's meaning changes. In that case the rule gets a new ID.

## Rule files (proposal)

```
rules/
  CF-001/
    rule.sql          # front matter + one SELECT/WITH statement
    fixtures/
      positive-*.yaml # nodes, edges, exposure, vulns, signals -> expected fingerprints
      negative-*.yaml
    fix/
      wrangler.md     # fix template(s)
      terraform.tf.tmpl
```

Front matter at the top of `rule.sql`:

```sql
-- ---
-- id: CF-001
-- version: 1
-- title: Public Worker with exploitable critical vulnerability and data access
-- severity: critical
-- kind: toxic                 # posture | toxic | detection
-- requires: [workers, exposure, packages, vulns, storage]
-- params: { sev_min: 4, min_conf: 1 }
-- enriches: null              # Security Insight type, if any
-- ---
```

Output contract: each row has `rule_id`, `fingerprint` and `severity`, plus evidence columns. List-valued evidence uses `json_group_array(DISTINCT …)`, not `group_concat`, because hostnames and names can contain commas.

The build step:

1. parses the front matter against a schema
2. checks that `requires` names known resource classes
3. replaces `:name` parameters with positional `?` and an ordered binding list, because `sql.exec` documents only positional parameters
4. prepares the statement against `schema-draft.sql` so syntax and column errors fail the build
5. runs all fixtures

## CF-001, revised

Run against the fixture, the spec's query returned the expected Workers with one exception. Changes:

1. **False positive through a service binding.** The hop into a bound Worker did not filter on deployment percentage. A 0 % version of the bound Worker with a KV binding made a public Worker qualify. The first hop already filtered on it.
2. **Entry points showed route IDs.** `n.native_id AS host` returns the route ID for routes. The revised query uses `COALESCE(n.name, n.native_id)`.
3. **Ambiguous lists.** `group_concat` changed to `json_group_array(DISTINCT …)`.
4. **Traffic from `signals`**, not from node props (see above).
5. **Alias collision.** `store_types(t)` shared its name with the table alias `t`. It worked, but it was confusing; renamed to `store_type`.

Not in the query: the spec's "a matching WAF virtual patch lowers one level". That needs WAF rule-to-CVE matching. It belongs in a severity modifier step after the query (Decision D-13).

<details>
<summary>Revised query</summary>

```sql
-- CF-001: public Worker, exploitable critical vulnerability, access to persistent data
-- Parameters: :sev_min (default 4 = critical), :min_conf (default 1 = medium)
WITH
public_entry AS (
  SELECT x.entry_id, COALESCE(n.name, n.native_id) AS host, x.confidence
  FROM exposure x
  JOIN nodes n ON n.id = x.entry_id AND n.deleted_at IS NULL
  WHERE x.decision = 'public'
),
served AS (
  -- route, Custom Domain, workers.dev -> active versions per deployment
  SELECT r.src AS entry_id, s.id AS script_id, d.dst AS version_id
  FROM edges r
  JOIN nodes s ON s.id = r.dst AND s.type = 'worker_script' AND s.deleted_at IS NULL
  JOIN edges d ON d.src = s.id AND d.type = 'DEPLOYS' AND d.deleted_at IS NULL
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
    AND COALESCE(json_extract(d.props, '$.percentage'), 100) > 0
  UNION
  -- version and preview URLs point straight at a (possibly old) version
  SELECT r.src, json_extract(v.props, '$.script_node_id'), v.id
  FROM edges r
  JOIN nodes v ON v.id = r.dst AND v.type = 'worker_version' AND v.deleted_at IS NULL
  WHERE r.type = 'ROUTES_TO' AND r.deleted_at IS NULL
),
vuln AS (
  SELECT c.src AS version_id, vu.vuln_id, vu.kev
  FROM edges c
  JOIN nodes p ON p.id = c.dst AND p.type = 'package' AND p.deleted_at IS NULL
  JOIN vulns vu ON vu.package_id = p.id
  WHERE c.type = 'CONTAINS' AND c.deleted_at IS NULL
    AND COALESCE(json_extract(c.props, '$.confidence'), 0) >= :min_conf
    AND vu.status = 'open'
    AND (vu.severity_rank >= :sev_min OR vu.kev = 1)
),
store_types(store_type) AS (
  VALUES ('r2_bucket'), ('d1_database'), ('kv_namespace'), ('do_namespace'),
         ('hyperdrive_config'), ('secrets_store_secret')
),
data_access AS (
  -- direct binding of the version
  SELECT b.src AS version_id, b.dst AS store_id, b.key AS binding
  FROM edges b
  JOIN nodes t ON t.id = b.dst AND t.deleted_at IS NULL
  WHERE b.type = 'BINDS' AND b.deleted_at IS NULL
    AND t.type IN (SELECT store_type FROM store_types)
  UNION
  -- one hop through a service binding to the target's active version
  SELECT b1.src, b2.dst, b1.key || '>' || b2.key
  FROM edges b1
  JOIN nodes s2 ON s2.id = b1.dst AND s2.type = 'worker_script' AND s2.deleted_at IS NULL
  JOIN edges d2 ON d2.src = s2.id AND d2.type = 'DEPLOYS' AND d2.deleted_at IS NULL
                AND COALESCE(json_extract(d2.props, '$.percentage'), 100) > 0
  JOIN edges b2 ON b2.src = d2.dst AND b2.type = 'BINDS' AND b2.deleted_at IS NULL
  JOIN nodes t2 ON t2.id = b2.dst AND t2.deleted_at IS NULL
  WHERE b1.type = 'BINDS' AND b1.deleted_at IS NULL
    AND t2.type IN (SELECT store_type FROM store_types)
)
SELECT
  'CF-001'                                 AS rule_id,
  'CF-001:' || sv.script_id                AS fingerprint,
  sv.script_id                             AS worker,
  json_group_array(DISTINCT sv.version_id) AS versions,
  json_group_array(DISTINCT pe.host)       AS entry_points,
  json_group_array(DISTINCT vu.vuln_id)    AS vulnerabilities,
  json_group_array(DISTINCT da.store_id)   AS data_stores,
  min(pe.confidence)                       AS exposure_confidence,
  CASE
    WHEN max(vu.kev) = 1 THEN 'critical'
    WHEN COALESCE(max(sg.value), 0) > 0 THEN 'critical'
    ELSE 'high'
  END                                      AS severity
FROM public_entry pe
JOIN served sv      ON sv.entry_id = pe.entry_id
JOIN vuln vu        ON vu.version_id = sv.version_id
JOIN data_access da ON da.version_id = sv.version_id
LEFT JOIN signals sg ON sg.node_id = sv.script_id AND sg.name = 'invocations_30d'
GROUP BY sv.script_id;
```

</details>

Fixture used for the check:

- **Expected hits.** A route to a Worker with a D1 binding. A Custom Domain to a Worker whose KEV package sits behind a service binding to a KV namespace. A preview URL to an undeployed old version with an R2 binding.
- **Expected misses.** No data store. Exposure `access`. Package confidence low. Vulnerable version at 0 %. Tombstoned binding. A 0 % version behind a service binding (the original query wrongly reported this one).

The query plan uses the partial indexes on `edges (src, type)` and `edges (dst, type)` throughout.
