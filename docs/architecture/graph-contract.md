# Graph contract (phase 1)

This is the agreement between collectors (which write the graph), the exposure evaluator and the rules (which read it). If a collector emits something different from what is written here, the rules break silently. **Change this document first**, in the same commit as the code.

General conventions are in [data-model.md](data-model.md). In short:

- Node ID is `<type>:<native_id>`. Edge ID is derived from `(type, src, dst, key)`.
- `name` is the display value.
- `props` hold stable configuration only. Volatile values (last used, traffic) go to `signals`.
- Props use `snake_case`. Timestamps in props are ISO 8601 strings as the API returns them. Signal values are epoch milliseconds or numbers.
- Booleans are real booleans, and a missing optional value is `null`, never omitted. That way rules can tell "false" from "unknown".

## Secrets never enter the graph

Values of plain-text variables, secret bindings, tokens, keys and certificates are never stored. Collectors store names and derived facts only, for example `looks_secret: true` and `secret_pattern: "cfat_"`.

## Resource classes

| Class | Collector package | Nodes | Edges |
| --- | --- | --- | --- |
| `zones` | platform | `zone` | |
| `dns` | platform | `dns_record` | |
| `workers` | platform | `worker_script`, `worker_version`, `worker_route`, `worker_custom_domain`, `workers_dev`, `worker_preview_url` | `ROUTES_TO`, `DEPLOYS`, `BINDS` |
| `pages` | platform | `pages_project`, `pages_domain`, `pages_preview` | `ROUTES_TO`, `BINDS` |
| `storage` | platform | `r2_bucket`, `r2_public_domain`, `d1_database`, `kv_namespace`, `queue`, `hyperdrive_config`, `do_namespace`, `secrets_store_secret` | `ROUTES_TO` |
| `access` | identity | `access_app`, `access_policy`, `access_group`, `service_token`, `identity_provider`, `everyone` | `ALLOWS`, `SELECTS` |
| `tunnels` | identity | `tunnel`, `tunnel_hostname` | `ROUTES_TO` |
| `tokens` | identity | `account_token` | |
| `members` | identity | `member` | |
| `insights` | identity | none; writes the `insights` table | |
| `traffic` | identity | none; writes `signals` | |

Edges belong to the class of the collector that emits them, even when they point to nodes of another class. For example, the `workers` collector emits `BINDS` edges to `d1_database` nodes. If the target class has no coverage, the edge points to a missing node, and rules that need it are `not evaluated` because they list that class in `requires`.

Derived inputs: `exposure` (exposure evaluator), and from phase 2 `packages` and `vulns`. The scan records them in `coverage` like resource classes once they are complete.

## Nodes

### zones

`zone` — native ID: zone ID; name: zone name.

| Prop | Type | Meaning |
| --- | --- | --- |
| `status` | string | `active`, `pending`, ... |
| `paused` | boolean | Proxy paused for the zone |
| `type` | string | `full`, `partial`, `secondary` |
| `plan` | string \| null | Plan name |

### dns

`dns_record` — native ID: record ID; name: record name (FQDN).

| Prop | Type | Meaning |
| --- | --- | --- |
| `zone_id` | string | |
| `type` | string | `A`, `AAAA`, `CNAME`, ... |
| `content` | string | Record content (IP or target) |
| `proxied` | boolean | Orange cloud |
| `ttl` | number | |

### workers

`worker_script` — native ID: script name (unique per account); name: script name.

| Prop | Type | Meaning |
| --- | --- | --- |
| `worker_id` | string \| null | ID in the Workers API (beta), if known |
| `workers_dev` | boolean | `workers.dev` route enabled |
| `preview_urls` | boolean | Preview URLs enabled |
| `has_assets` | boolean | Static assets attached |
| `compatibility_date` | string \| null | |
| `created_on`, `modified_on` | string \| null | |

`worker_version` — native ID: version ID; name: version number as text.

| Prop | Type | Meaning |
| --- | --- | --- |
| `script_node_id` | string | `worker_script:<name>`; always set |
| `number` | number \| null | Version number |
| `created_on` | string \| null | |
| `source` | string \| null | `wrangler`, `dashboard`, `api`, ... |
| `plain_text_vars` | `{ name, kind, looks_secret, secret_pattern }[]` | Bindings that keep their value in plain text, without the values: `plain_text` (field `text`) and `json` (field `json`, every string and object key tested). `kind` is the binding type. `secret_pattern` is the strongest match in the order `cfat_`, `cfut_`, `cfk_`, `aws_access_key`, `private_key`, `high_entropy`, or `null`. `looks_secret` is `null` when there was no value to inspect |
| `secret_names` | string[] | Names of `secret_text` bindings |

Which versions: every version with traffic in the current deployment, and every version a preview URL points to. Phase 1 does not list the full version history.

`worker_route` — native ID: route ID; name: route pattern. Props: `zone_id` (string), `pattern` (string), `script` (string \| null). A route without a script emits no `ROUTES_TO`.

`worker_custom_domain` — native ID: hostname; name: hostname. Props: `zone_id`, `hostname`, `service` (script name), `environment` (string \| null).

`workers_dev` — native ID and name: `<script>.<subdomain>.workers.dev`. Props: `script`. Emitted only when the script has `workers_dev: true`.

`worker_preview_url` — native ID and name: the preview hostname. Props:

| Prop | Type | Meaning |
| --- | --- | --- |
| `script` | string | |
| `kind` | string | `version` or `alias` |
| `version_id` | string \| null | |
| `alias` | string \| null | |

Emitted only when the script has `preview_urls: true`.

### pages

`pages_project` — native ID: project name; name: project name.

| Prop | Type | Meaning |
| --- | --- | --- |
| `production_branch` | string \| null | |
| `subdomain` | string | `<project>.pages.dev` |
| `preview_deployments` | string | `all`, `none` or `custom`, from the preview branch settings |
| `plain_text_vars` | `{ name, environment, kind, looks_secret, secret_pattern }[]` | Plain-text env vars of the preview and production configs, sorted by environment, then name. Secret env vars are never read and values are never stored; `looks_secret` is `null` when the API returns no value |

`pages_domain` — native ID: custom domain or `<project>.pages.dev`; name: same. Props: `project`, `status`.

`pages_preview` — native ID: `*.<project>.pages.dev`; name: same. Props: `project`. Emitted when `preview_deployments` is not `none`.

### storage

`r2_bucket` — native ID: bucket name. Props: `location` (string \| null), `jurisdiction` (string \| null), `storage_class` (string \| null), `creation_date` (string \| null).

`r2_public_domain` — native ID: domain; name: domain.

| Prop | Type | Meaning |
| --- | --- | --- |
| `bucket` | string | |
| `kind` | string | `r2_dev` or `custom` |
| `enabled` | boolean \| null | `null` when the API omits the field or sends another type (custom domains) |
| `zone_id` | string \| null | |

Custom domains are emitted whatever their state. The managed `r2.dev` domain is emitted only when the API says `enabled: true`, so an unreadable flag drops the entry point; review R4-02 proposes emitting it with `enabled: null` instead.

`d1_database` — native ID: database UUID; name: database name. Props: `created_at` (string \| null).

`kv_namespace` — native ID: namespace ID; name: title.

`queue` — native ID: queue ID; name: queue name.

`hyperdrive_config` — native ID: config ID; name: config name. Props: `origin_host` (string \| null), `origin_scheme` (string \| null).

`do_namespace` — native ID: namespace ID; name: `<script>:<class>`. Props: `script`, `class`, `use_sqlite` (boolean \| null).

`secrets_store_secret` — native ID: `<store_id>/<secret_name>`; name: secret name. Props: `store_id`.

### access

`access_app` — native ID: app ID; name: app name.

| Prop | Type | Meaning |
| --- | --- | --- |
| `app_type` | string | API `type`: `self_hosted`, `saas`, `ssh`, `vnc`, `rdp`, `warp`, `app_launcher`, `infrastructure`, `mcp`, ... |
| `targets` | `Target[]` | Normalized destinations (below) |
| `session_duration` | string \| null | |
| `allowed_idps` | string[] | IdP IDs; empty means all |

`Target` is one of:

- `{ kind: "hostname", host, path, overrides }`.
  - `host` is lowercase and may start with `*.`.
  - `path` is the Access path as configured, wildcards and a trailing slash included (`/admin`, `/admin/`, `/alpha/*`, `/foo*`, `/foo*/bar`), or `""` when absent. Evaluators apply Access path semantics: a path without a wildcard covers its subpaths, `/alpha/*` does not cover `/alpha` itself, and `/*` covers the whole host. A port, a query, a fragment, or a host wildcard other than a leading `*.` makes the destination `other`.
  - `overrides` lists the destination's overrides as `{ behavior, path_pattern }[]`, sorted and deduplicated, empty when there are none.
    - Both are strings as the API returns them; `path_pattern` is verbatim, at most 512 characters.
    - `behavior: "public"` makes those paths reachable without Access; the API documents no other behavior.
    - Unlike `path`, an override path without a wildcard matches that exact path only.
    - A destination whose overrides cannot be read becomes `other`, so no public path is lost. That covers overrides that are not a list, more than 100 of them, or an item without a string `behavior` or `path_pattern`.
- `{ kind: "worker", script, scope, overrides }`. Worker-level Access.
  - `script` is the script name, resolved from the API's `worker_id` through the Workers list. If it cannot be resolved, the collector emits `other` instead.
  - `scope` is `all` or `previews`.
  - `overrides` as for `hostname`.
- `{ kind: "all_workers", scope, overrides }`. Account-level Worker Access: the API destination `all_workers` has scope `all`, `all_preview_workers` has scope `previews`. Overrides are read as for `worker`. It ranks below Worker-level targets.
- `{ kind: "private", cidr, hostname, port_range }`. Private destinations; used from phase 3.
- `{ kind: "other", raw }`. Anything the collector cannot normalize. A collector never drops a destination: a dropped destination would turn `unknown` into `public` or `access`.

`access_policy` — native ID: policy ID; name: policy name.

| Prop | Type | Meaning |
| --- | --- | --- |
| `decision` | string | `allow`, `deny`, `bypass`, `non_identity` (Service Auth) |
| `include`, `require`, `exclude` | `Selector[]` | Normalized rules |
| `session_duration` | string \| null | |

`Selector` is `{ kind, value }` where `kind` is one of:

- `everyone`
- `email`, `email_domain`, `email_list`
- `group` (Access group ID), `idp_group` (`{ idp, name }`)
- `service_token` (token ID), `any_valid_service_token`
- `login_method` (IdP ID)
- `ip`, `geo`, `device_posture`, `certificate`, `common_name`
- `other`

`value` is `null` for `everyone`, `any_valid_service_token` and `certificate`. For `idp_group`, `name` depends on the IdP:

| IdP | `name` |
| --- | --- |
| SAML | `attribute=value` |
| OIDC | `claim=value` |
| GitHub | `org` or `org/team` |
| Azure AD | group ID |
| Google Workspace | group email |
| Okta | group name |

The rule types `ip_list`, `auth_method`, `auth_context`, `external_evaluation`, `linked_app_token`, `user_risk_score` and `cloudflare_account_member` become `other`, with the raw rule capped in size.

`access_group` — native ID: group ID. Props: `include`, `require`, `exclude` (`Selector[]`).

`service_token` — native ID: token ID; name: token name. Props: `expires_at` (string \| null), `duration` (string \| null), `enabled` (boolean \| null; `false` means the token cannot authenticate, for example after a leak report; `null` when the API omits the field). Signal: `last_seen_at` (epoch ms, `null` when never seen). Client IDs and secrets are never stored.

`identity_provider` — native ID: IdP ID; name: IdP name. Props: `idp_type` (`onetimepin`, `azureAD`, `okta`, `github`, ...).

`everyone` — native ID: `everyone`. A single node that `SELECTS` edges point to for `everyone` selectors.

### tunnels

`tunnel` — native ID: tunnel ID; name: tunnel name.

| Prop | Type | Meaning |
| --- | --- | --- |
| `tunnel_type` | string | `cfd_tunnel` or `warp_connector` (Mesh) |
| `status` | string \| null | `healthy`, `down`, `inactive`, ... |
| `config_src` | string \| null | `cloudflare` (remotely managed) or `local` |
| `ingress_truncated` | boolean | `true` when the ingress yields more than 1,000 entry points and the rest were not emitted |

`tunnel_hostname` — native ID: `<tunnel_id>:<hostname>:<path>`; name: hostname.

- The tunnel ID keeps two tunnels that serve the same hostname apart.
- The `:` between hostname and path keeps a hostname and a path from combining into another hostname's ID (review R5-04).
- When the ID would exceed 512 characters, the path part becomes `sha256:<hex of the path>` (R5-05). The full path stays in `path`, and no rule is dropped for its length.
- Fall-through expansion yields at most 1,000 `tunnel_hostname` nodes per tunnel (R5-06). Beyond that, the tunnel gets `ingress_truncated: true`, and the evaluator returns `unknown` for every entry point of that tunnel.
- `via_fallthrough` nodes use the same form, with the hostname from the ingress and the path of the rule without a hostname.
- For one hostname and path only the first matching rule applies, so a hostname rule and a rule without a hostname never share an ID; the ID does not depend on the rule's position.

| Prop | Type | Meaning |
| --- | --- | --- |
| `hostname` | string | |
| `path` | string | The cloudflared path regex as configured (it may lack a leading `/`); `""` when absent |
| `service` | string | Origin as configured, for example `http://localhost:8080` or `ssh://localhost:22` |
| `origin_scheme` | string | `http`, `https`, `ssh`, `rdp`, `tcp`, `smb`, `unix`, `http_status`, `other` |
| `tunnel_id` | string | |
| `access_required` | boolean | cloudflared validates an Access JWT before it proxies a request. Read only from the rule's own `originRequest.access.required`: cloudflared builds the validator from the rule's own block, and the top-level `config.originRequest` does not enforce it (review R3-01). Anything but `true` is `false` |
| `via_fallthrough` | boolean | `true` for nodes derived from an ingress rule without a hostname (see below) |

Emitted from the remotely managed ingress configuration:

- **Hostname rules.** Every rule with a hostname yields one node, unless an earlier rule shadows it (below).
- **Rules without a hostname** match every hostname that reaches the tunnel (review R3-02). This covers the final catch-all and path-only rules. A rule whose hostname is `*` counts as one without a hostname, as in cloudflared.
  - Each such rule whose service is an origin (anything but `http_status:*`) yields one node per hostname that appears in the tunnel's ingress, with the rule's own path, service and `access_required`, and `via_fallthrough: true`.
  - Requests that no hostname rule takes, such as other paths of a path-restricted hostname, are therefore evaluated as their own entry points.
- **Shadowing.** cloudflared takes the first rule that matches. For one hostname, a rule is skipped when an earlier rule for that hostname, or one without a hostname, has the same path or no path. Rules without a hostname that answer with `http_status` take their path for every hostname but yield no node.
- **Rules without a service** are ignored; cloudflared refuses them.
- **Credentials.** For a `scheme://` value, everything from `//` through the last `@` of the authority is removed. The authority runs from `//` to the first `/`, `?` or `#`, as in Go's `url.Parse`, which cloudflared uses. A service with an `@` anywhere else, or an `@` without `scheme://`, is stored as `""`. The stored service never contains `@`.
- **Locally managed tunnels** yield `tunnel` nodes but no `tunnel_hostname`.

Known limits of the per-rule model, and which way each errs:

- Hostnames that reach the tunnel only through DNS are not known to the collector, so rules without a hostname yield no node for them. This can hide an entry point.
- A wildcard hostname rule (`*.example.com`) that comes before an exact hostname is not treated as shadowing it. The exact host's node may then show the later rule's `access_required`, which errs toward `access`; the wildcard rule's own node still reports its exposure.
- A fall-through node's path also covers paths that an earlier hostname rule with a path takes. This errs toward exposure.
- `<hostname><path>` has no separator, so pairs such as (`a.example.co`, `m`) and (`a.example.com`, `""`) share an ID. The first rule keeps it and the other yields no node, which can hide an entry point. This was already true before round 4.

### tokens

`account_token` — native ID: token ID; name: token name.

| Prop | Type | Meaning |
| --- | --- | --- |
| `status` | string | `active`, `disabled`, `expired` |
| `issued_on`, `modified_on` | string \| null | |
| `expires_on` | string \| null | `null` means no expiry |
| `not_before` | string \| null | |
| `policies` | `Policy[]` | `{ effect, permission_groups: { id, name }[], resources: Record<string, string> }`. Nested resource maps from the API (`account -> resource -> value`) are flattened to their inner entries |
| `ip_condition` | `{ in, not_in }` \| null | Arrays of CIDRs |

Signal: `last_used_on` (epoch ms, `null` when never used).

### members

`member` — native ID: member ID; name: email.

| Prop | Type | Meaning |
| --- | --- | --- |
| `status` | string | `accepted`, `pending` |
| `roles` | string[] | Role names |
| `super_admin` | boolean | Has the Super Administrator role |
| `two_factor_enabled` | boolean \| null | `user.two_factor_authentication_enabled`: two-factor authentication for dashboard login (the API says it does not apply to API authentication); `null` when the member has no user object or the field is absent |

`roles` holds the legacy role names plus the permission groups of allow policies.

### insights

Rows in the `insights` table: `id`, `type` (API `issue_type`), `severity`, `subject_id`, and the payload with the documented fields. `issue_type` has only a few category values, so rules match on `payload.issue_class` and `payload.subject`. `subject_id` is `null` in phase 1: the API documents no subject format that maps to a node.

### traffic

Signals on `worker_script` nodes:

- `invocations_30d`: requests in the last 30 days, all triggers
- `errors_30d`

Every script in the Workers list gets both signals, `0` without traffic, because signals are never swept. The traffic collector therefore needs the Workers list (Workers Metadata Read-Only) as well as Account Analytics Read. An account the analytics API does not show is `no_permission`, never zero traffic.

## Edges

| Edge | From → to | `key` | Props |
| --- | --- | --- | --- |
| `ROUTES_TO` | `worker_route`, `worker_custom_domain`, `workers_dev` → `worker_script` | | |
| `ROUTES_TO` | `worker_preview_url` → `worker_version` (kind `version`) or `worker_script` (kind `alias`) | | |
| `ROUTES_TO` | `pages_domain`, `pages_preview` → `pages_project` | | `environment`: `production` or `preview` |
| `ROUTES_TO` | `r2_public_domain` → `r2_bucket` | | |
| `ROUTES_TO` | `tunnel_hostname` → `tunnel` | | |
| `DEPLOYS` | `worker_script` → `worker_version` | | `percentage` (0–100) |
| `BINDS` | `worker_version` → store node, or `worker_script` for service bindings | binding name | `binding_type`: API binding type (`d1`, `kv_namespace`, `r2_bucket`, `durable_object_namespace`, `service`, `queue`, `hyperdrive`, `secrets_store_secret`, `vectorize`, ...) |
| `BINDS` | `pages_project` → store node or `worker_script` | `<environment>:<binding name>` | `binding_type`, `environment` |
| `ALLOWS` | `access_policy` → `access_app` | | `precedence` (number, lower runs first) |
| `SELECTS` | `access_policy` or `access_group` → `everyone`, `access_group`, `service_token`, `identity_provider` | `include`, `require` or `exclude` | |

Binding targets map to node IDs as follows:

| Binding | Target node ID |
| --- | --- |
| KV | `kv_namespace:<namespace_id>` |
| D1 | `d1_database:<database_id>` |
| R2 | `r2_bucket:<bucket_name>` |
| Durable Object | `do_namespace:<namespace_id>` |
| Service | `worker_script:<service>` |
| Queue | `queue:<queue_id>` |
| Hyperdrive | `hyperdrive_config:<id>` |
| Secrets Store | `secrets_store_secret:<store_id>/<secret_name>` |

Binding types without a node type (AI, analytics engine, browser, and so on) emit no edge.

## Exposure semantics (evaluator contract)

Input: live entry point nodes, Access apps and policies, Worker-level Access targets, and `workers_dev` / `preview_urls` flags. Output: one `exposure` row per entry point and path prefix.

1. **Entry points** are:
   - `worker_route`, `worker_custom_domain`, `workers_dev`, `worker_preview_url`
   - `pages_domain`, `pages_preview`
   - `r2_public_domain` unless `enabled` is `false`; with `enabled` `null` the entry point is `unknown`
   - `tunnel_hostname`
2. **Matching.**
   - Every Access app with a `hostname` target that matches the entry point's host decides the path prefixes it covers: an exact host beats a wildcard, and a longer path beats a shorter one.
   - An Access hostname wildcard covers one label. It never covers a route or tunnel host that matches any depth: those deeper hosts are decided as if no hostname app matched them (Worker-level Access if it applies, otherwise `public` with confidence 1).
   - When host specificity and path length point to different apps, the result is `unknown`.
   - A `worker` target covers every entry point of that Worker; `scope: previews` covers only `worker_preview_url`.
   - `all_workers` covers every Worker below Worker-level targets. Targets of one tier that disagree are `unknown`. The order:
     - on preview URLs: `worker` with scope `previews`, `worker` with scope `all`, `all_workers` with scope `previews`, `all_workers` with scope `all`
     - elsewhere: `worker` with scope `all`, then `all_workers` with scope `all`
   - Hostname and path apps take precedence over Worker-level Access.
   - Override paths with `behavior: "public"` are `public`. Overrides with any other behavior are `unknown` on their paths, unless the app is `public` there anyway. An override path without a wildcard is read with its subpaths, which errs toward `public`. An override path wildcard the evaluator cannot place is `unknown`.
   - Access paths:
     - `/admin` covers itself and everything below `/admin/`
     - `/api*` covers every path that starts with `/api`
     - `/alpha/*` covers everything below `/alpha/`, but not `/alpha`
     - `/*` covers the whole host
     - A wildcard elsewhere in the path, or a trailing slash (the docs do not say whether `/admin/` covers `/admin`), cannot be placed: the evaluator returns `unknown` below its literal start.
3. **Decision per covered prefix**, from the app's policies:
   - **Bypass** never asks for an identity ([decision 0003](../decisions/0003-bypass-and-service-auth-exposure.md)):
     - A Bypass whose include holds `everyone` or any non-identity selector (`ip`, `geo`, `certificate`, `common_name`, `device_posture`, `service_token`, `any_valid_service_token`), directly or through an Access group, → `public` with the reason. That holds even when require rules narrow it, for example to an office IP range. It can be a false positive, but never a false "protected".
     - → `unknown`: a Bypass that can match only through `other` or identity selectors, through an Access group missing from the graph, or that has no readable include rule.
   - **Service Auth** (`non_identity`):
     - Includes of `service_token`, `any_valid_service_token`, `certificate` or `common_name`, directly or through an Access group, → `service_auth`.
     - Any IP include with prefix length 0 (`0.0.0.0/0`, `::/0`) makes the policy `public`, even next to credential includes.
     - Every other include → `unknown`: `everyone`, `ip`, `geo`, `other`, identity selectors, `device_posture`, a missing group, or an empty or unreadable include.
   - Otherwise → `access`, including an app without any allow, bypass or Service Auth policy (deny by default). CF-010 judges how broad the allowed audience is, not the evaluator.
4. **Origin-enforced Access.** A `tunnel_hostname` with `access_required: true` is never `public` just because Access lets a request through without a token. cloudflared rejects requests without a valid Access application token. Access issues one only after an Allow or Service Auth policy admits the request; Bypass and public overrides enforce nothing.
   - Where the Access evaluation alone yields `public` (no app, a Bypass, a public override), the deciding app's policies that may give a token without a login decide, whichever policy the Access evaluation names (review R4-01):
     - If any Service Auth policy of that app includes `0.0.0.0/0` or `::/0`, the row stays `public`, with that policy as `reason_id`. This also holds on a path that a public override exempts from Access, because a token of the app is valid there too.
     - Otherwise, a Service Auth policy that is `unknown`, an `ALLOWS` edge to a missing policy, or a policy with an unsupported action makes the row `unknown`.
     - Otherwise the row is `access` with confidence at most 1, and `reason_id` is the tunnel hostname, because the audience tags that cloudflared checks are not collected.
   - Where apps tie on a destination, or host and path precedence select different apps that agree, the app whose token exposes most decides: one with a Service Auth policy for every address first, then one with an undecided policy.
   - `access`, `service_auth` and `unknown` rows stay as they are, and missing `access` coverage still makes the entry point `unknown`.
   - The evaluator does not model require and exclude rules or the exact order of Bypass and Service Auth policies, so it errs toward `public` ([decision 0003](../decisions/0003-bypass-and-service-auth-exposure.md)).
5. **No matching app** → `public`. This also holds for a wildcard entry point (for example `*.<project>.pages.dev` or a `*.zone` route), with confidence 2: the decision does not depend on which hosts exist under the wildcard.
6. **Unsupported input** → `unknown`.
   - That covers a target of kind `other`, a target without the shape above (for example without `overrides`), a hostname target whose host has a port or a wildcard other than a leading `*.`, a wildcard the evaluator cannot place, and missing coverage for `access` while the entry point exists.
   - An `other` target naming a `worker_id` that no `worker_script` carries may apply to every entry point whose Worker has `worker_id` `null`.
   - An `other` target only makes the entry points it might cover `unknown`: API type `all_workers` only Worker entry points, `all_preview_workers` only preview URLs, `worker` or `preview_worker` only that Worker's.
7. **Confidence:**
   - 2 when the decision follows from complete data with exact matching
   - 1 with wildcard matching
   - 0 when a coverage gap is involved
8. **`path_prefix`** in exposure rows:

   | Value | Covers |
   | --- | --- |
   | `/` | The whole host |
   | `/admin` | That path and everything below `/admin/` |
   | `/api*` | Every path that starts with `/api` |
   | `/api/*` | Everything below `/api/` |

   A route's base row uses the route's own path (for example `/api/*`), so not every entry point has a `/` row.

Known limits of v1, all of which err toward reporting exposure:

- Route shadowing is not modeled (a more specific route to another Worker, a route without a script, a Custom Domain on the same host).
- Zone-level Access apps are not collected.
- Tunnel path regexes are read approximately.
- `access_required` holds per ingress rule. Before cloudflared 2026.10.0, or with URL normalization off, a request with dot segments or repeated slashes can match another rule of the same hostname. That rule is its own entry point and is evaluated on its own.

## Scan semantics

What the scan records, and what rules and the evaluator may rely on:

- **Coverage per class and scan:**
  - `complete`: all chunks were written
  - `partial`: some chunks were written before one failed; collection of a class stops at the first failed chunk
  - `no_permission`: the API answered 401 or 403
  - `error`: anything else
- **Sweep** runs only for `complete` classes. A sweep never moves the current scan. The write path refuses the sweep of a scan that is not current.
- **Only the current scan writes.** Writes from a scan marked failed as stale, from one that ended, or from one a newer scan took over are refused (`StaleScanError`). That scan stops and ends `failed`, with the reason in `summary.detail`.
- **Exposure:** the exposure step records coverage `exposure` as `complete` or `error`. A rule that reads `exposure` must also list `access` in `requires`, because exposure without Access data is not a decision.
- **Rules** run after the exposure step, each in its own call. A rule whose `requires` are not all `complete` is `not_evaluated` and changes no finding.
- **Undecided.** Where the exposure that decides a rule is `unknown`, or a value it needs could not be read (for example `plain_text_vars` entries with `looks_secret` `null` in CF-024), the rule returns an undecided row (`decided = 0`). An undecided row is not a hit and changes no finding, except that a suppression past its end returns to open (R3-07).
- **`rule_runs`** records hits (decided rows), undecided rows, and for a failed run its error message (at most 500 characters).
